"""The personal edition's side of accounts: sign in, keep the licence fresh, decide what is allowed.

Argus Personal runs on the investigator's own computer, but it is unlocked by their **Argus
account**: it signs in to the account service, receives a licence for this computer, checks it
offline with the service's public key, and renews it in the background.

Only these ever go to the account service: the email and password at sign-in, this computer's
random device id and name, and the licence when renewing. Nothing about cases, evidence or
searches, unless the investigator uses Argus Connect: then the lookup itself (a company number,
an officer's name), or for the AI analyst the case material they chose to send, passes through
the service on its way to the source. The service keeps none of it; its ledger records only the
kind of request. Investigators who set their own keys bypass the service entirely.
"""

from __future__ import annotations

import asyncio
import logging
import platform
import secrets
from datetime import datetime, timezone
from typing import Any

import aiohttp

from argus.accounts.licence import LicenceError, access, load_public_key, verify
from argus.core.settings import Settings

logger = logging.getLogger("argus.personal")
DEVICE_KEY = "device"
CURRENT: PersonalLicence | None = None  # this installation's licence, for modules that use Argus Connect
LICENCE_KEY = "licence"


class AccountServiceError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


class AccountClient:
    """Talks to the Argus account service over HTTPS."""

    def __init__(self, settings: Settings):
        self.base = settings.account_server_url.rstrip("/")

    async def call(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        if not self.base:
            raise AccountServiceError(503, "No Argus account service is configured for this installation")
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as http, http.post(
                self.base + (path if path.startswith("/") else f"/api/accounts/{path}"), json=body, allow_redirects=False
            ) as resp:  # fmt: skip
                data = await resp.json(content_type=None) if resp.content_length != 0 else {}
                if resp.status >= 400:
                    detail = data.get("detail") if isinstance(data, dict) else None
                    raise AccountServiceError(resp.status, str(detail or f"The account service answered {resp.status}"))
                return data if isinstance(data, dict) else {}
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
            raise AccountServiceError(
                0, "The Argus account service could not be reached: check your connection"
            ) from exc


class PersonalLicence:
    """This installation's licence: loaded at start, renewed in the background, checked on every request."""

    def __init__(self, settings: Settings, state: Any, client: AccountClient | None = None):
        self.settings = settings
        self.state = state  # AppStateRepository
        self.client = client or AccountClient(settings)
        self.device_id = ""
        self.token: str | None = None
        self.payload: dict[str, Any] | None = None
        self.revoked: str | None = None  # why the service refused to renew (cancelled, signed out elsewhere...)
        self.last_refresh_error: str | None = None
        self._public = load_public_key(settings.licence_public_key) if settings.licence_public_key else None
        self.issuer = settings.account_server_url.rstrip("/") or None
        self.last_credits: dict[str, Any] | None = None  # balance after the latest Argus Connect lookup

    async def load(self) -> None:
        global CURRENT
        CURRENT = self
        device = await self.state.get(DEVICE_KEY)
        if not device:
            device = {"id": secrets.token_urlsafe(24), "name": platform.node()[:100] or "My computer"}
            await self.state.set(DEVICE_KEY, device)
        self.device_id = device["id"]
        saved = await self.state.get(LICENCE_KEY)
        if saved:
            try:
                self.payload = self._check(saved["token"])
                self.token, self.revoked = saved["token"], saved.get("revoked")
            except LicenceError as exc:
                logger.warning("Stored licence rejected (%s); sign in again", exc)
                await self.state.delete(LICENCE_KEY)

    def _check(self, token: str) -> dict[str, Any]:
        if self._public is None:
            raise LicenceError("no licence public key is configured (ARGUS_LICENCE_PUBLIC_KEY)")
        payload = verify(token, self._public, issuer=self.issuer)
        if payload.get("device") != self.device_id:
            raise LicenceError("the licence belongs to another computer")
        return payload

    def access(self, now: datetime | None = None) -> tuple[str, str]:
        level, reason = access(self.payload, now)
        if level == "full" and self.revoked:
            return "read_only", self.revoked
        return level, reason

    def status(self) -> dict[str, Any]:
        level, reason = self.access()
        p = self.payload or {}
        return {
            "edition": "personal", "signed_in": self.payload is not None, "access": level, "reason": reason,
            "account": {"email": p.get("email"), "name": p.get("name")} if p else None,
            "plan": p.get("plan"), "plan_label": p.get("plan_label"), "status": p.get("status"),
            "valid_until": p.get("valid_until"), "offline_until": p.get("offline_until"),
            "renewed_at": p.get("issued_at"), "renewal_problem": self.last_refresh_error,
            "account_service": self.settings.account_server_url or None,
            "configured": bool(self.settings.account_server_url and self._public),
        }  # fmt: skip

    async def _store(self, token: str) -> dict[str, Any]:
        payload = self._check(token)
        self.token, self.payload, self.revoked, self.last_refresh_error = token, payload, None, None
        await self.state.set(LICENCE_KEY, {"token": token})
        return payload

    async def sign_in(self, email: str, password: str, device_name: str = "") -> dict[str, Any]:
        result = await self.client.call("token", {"email": email, "password": password, "device_id": self.device_id,
                                                  "device_name": device_name or platform.node()[:100]})  # fmt: skip
        try:
            return await self._store(str(result.get("licence") or ""))
        except LicenceError as exc:
            raise AccountServiceError(502, f"The account service sent a licence Argus cannot trust: {exc}") from exc

    async def credits(self) -> dict[str, Any]:
        """The account's Argus credits and what each lookup costs."""
        if not self.token:
            raise AccountServiceError(401, "Sign in to see your credits")
        return await self.client.call("/api/connect/balance", {"licence": self.token})

    async def billing(self, action: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        """Payments, through the account service: the catalogue, a checkout page, or the billing page."""
        if action == "catalogue":
            return await self.client.call("/api/billing/catalogue", {"licence": self.token} if self.token else {})
        if not self.token:
            raise AccountServiceError(401, "Sign in first")
        return await self.client.call(f"/api/billing/{action}", {"licence": self.token, **(body or {})})

    async def team(self, action: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        """Team plans, through the account service: status, invite, cancel-invite, remove, leave."""
        if not self.token:
            raise AccountServiceError(401, "Sign in first")
        return await self.client.call(f"/api/teams/{action}", {"licence": self.token, **(body or {})})

    async def sign_up(self, email: str, password: str, name: str) -> dict[str, Any]:
        return await self.client.call("signup", {"email": email, "password": password, "name": name})

    async def refresh(self) -> bool:
        """Renew the licence. Never raises: offline is normal, and the licence covers it for a while."""
        if not self.token:
            return False
        try:
            result = await self.client.call("refresh", {"licence": self.token})
            await self._store(str(result.get("licence") or ""))
            return True
        except AccountServiceError as exc:
            if exc.status in (401, 403):  # the account refuses this computer: stop new work, keep the data
                self.revoked = f"{exc.detail}. Your cases stay readable and exportable."
                await self.state.set(LICENCE_KEY, {"token": self.token, "revoked": self.revoked})
            self.last_refresh_error = exc.detail
            logger.info("Licence renewal failed: %s", exc.detail)
        except LicenceError as exc:
            self.last_refresh_error = str(exc)
        return False

    async def sign_out(self) -> None:
        if self.token:
            try:
                await self.client.call("sign-out", {"licence": self.token})
            except AccountServiceError as exc:  # offline: the place is freed when an admin revokes it
                logger.info("Could not tell the account service about the sign-out: %s", exc.detail)
        self.token, self.payload, self.revoked = None, None, None
        await self.state.delete(LICENCE_KEY)

    def due(self, now: datetime | None = None) -> bool:
        if not self.payload:
            return False
        try:
            return (now or datetime.now(timezone.utc)) >= datetime.fromisoformat(self.payload["refresh_after"])
        except (KeyError, ValueError):
            return True

    async def run_forever(self) -> None:
        while True:
            try:
                if self.due():
                    await self.refresh()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Licence renewal loop failed")
            await asyncio.sleep(min(self.settings.licence_refresh_seconds, 3600))
