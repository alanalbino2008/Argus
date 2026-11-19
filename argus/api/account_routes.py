"""The Argus account service: subscription accounts, and the signed licences that unlock Argus Personal.

Run centrally by the operator (``ARGUS_ACCOUNT_SERVICE_ENABLED=true`` with a signing key). Each
person's own Argus (the personal edition) signs in here, gets a licence for that one computer,
and renews it in the background.

What this service learns: that an account signed in from a device, and when it renewed. It never
receives anything about cases, evidence or searches; those stay on the person's computer.

**Payments.** An account has a plan, a status (trialing, active, past_due, cancelled, suspended)
and ``valid_until`` (the end of the paid period). Stripe's webhook keeps them in step
(``billing_routes``); an admin can also change them with ``PATCH /api/accounts/{id}``. Licences
pick a change up at their next renewal, or straight away after a payment.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from argus.accounts.licence import PLANS, LicenceError, issue, load_private_key, public_key_of, verify
from argus.accounts.passwords import DUMMY_HASH, hash_password, verify_password, weakness
from argus.api.deps import audit, client_ip, require_platform_admin
from argus.security.auth import Principal, Role
from argus.security.ratelimit import SlidingWindowLimiter

router = APIRouter(prefix="/api/accounts", tags=["accounts"])
_per_ip = SlidingWindowLimiter(limit=20, window=60)
_signups = SlidingWindowLimiter(limit=5, window=3600)
EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[A-Za-z]{2,}$")
SERVICE = Principal(key_id="account-service", name="account-service", role=Role.ANALYST)


class SignupRequest(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(max_length=256)
    name: str = Field(default="", max_length=255)


class TokenRequest(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(max_length=256)
    device_id: str = Field(min_length=16, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    device_name: str = Field(default="", max_length=128)


class LicenceRequest(BaseModel):
    licence: str = Field(max_length=8192)


class AccountUpdate(BaseModel):
    plan: Literal["trial", "personal", "professional"] | None = None
    status: Literal["trialing", "active", "past_due", "cancelled", "suspended"] | None = None
    valid_until: datetime | None = None
    max_devices: int | None = Field(default=None, ge=1, le=20)
    name: str | None = Field(default=None, max_length=255)
    billing_reference: str | None = Field(default=None, max_length=255)


def _service(request: Request) -> tuple[Any, Any]:
    settings = request.app.state.settings
    if not settings.account_service_enabled:
        raise HTTPException(status_code=404, detail="Not found")
    key = settings.licence_signing_key.get_secret_value() if settings.licence_signing_key else ""
    if not key:
        raise HTTPException(status_code=503, detail="The account service has no signing key configured")
    return request.app.state.subscribers, load_private_key(key)


def _issuer(request: Request) -> str:
    return (request.app.state.settings.public_url or str(request.base_url)).rstrip("/")


def _limit(request: Request) -> None:
    if not _per_ip.hit(client_ip(request) or "unknown"):
        raise HTTPException(status_code=429, detail="Too many attempts; wait a minute")


@router.get("/public-key")
async def account_public_key(request: Request):
    """The key Argus Personal uses to check licences offline (safe to publish)."""
    _repo, private = _service(request)
    return {"public_key": public_key_of(private), "issuer": _issuer(request), "plans": PLANS}


@router.post("/signup", status_code=201)
async def signup(body: SignupRequest, request: Request):
    """Create an account with a free trial (when sign-up is open)."""
    repo, _private = _service(request)
    settings = request.app.state.settings
    if not settings.account_signup_enabled:
        raise HTTPException(status_code=403, detail="Sign-up is closed: ask for an account")
    _limit(request)
    if not _signups.hit(client_ip(request) or "unknown"):
        raise HTTPException(status_code=429, detail="Too many new accounts from this address; try later")
    email = body.email.strip().lower()
    if not EMAIL.match(email):
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    problem = weakness(body.password, email)
    if problem:
        raise HTTPException(status_code=422, detail=problem)
    hashed = await asyncio.to_thread(hash_password, body.password)
    account = await repo.create(email=email, name=body.name.strip(), password_hash=hashed, plan="trial",
                                status="trialing",
                                valid_until=datetime.now(timezone.utc) + timedelta(days=settings.trial_days))  # fmt: skip
    if account is None:
        raise HTTPException(status_code=409, detail="An account with this email already exists: sign in instead")
    await audit(request, SERVICE, "account.signup", account["id"], details={"plan": "trial"})
    return account


@router.post("/token")
async def sign_in(body: TokenRequest, request: Request):
    """Sign in from a computer: returns a signed licence for that computer."""
    repo, private = _service(request)
    _limit(request)
    found = await repo.by_email(body.email.strip())
    stored = found[1] if found else DUMMY_HASH  # same work whether or not the account exists
    ok = await asyncio.to_thread(verify_password, body.password, stored)
    if found is None or not ok:
        if found is not None:
            await repo.login_failed(found[0]["id"])
        raise HTTPException(status_code=401, detail="Wrong email or password")
    account, _hash, locked_until = found
    if locked_until and locked_until > datetime.now(timezone.utc):
        raise HTTPException(status_code=423, detail="Too many failed sign-ins: try again in 15 minutes")
    if account["status"] == "suspended":
        raise HTTPException(status_code=403, detail="This account is suspended: contact support")
    attached, active = await repo.attach_device(account["id"], body.device_id, body.device_name.strip())
    if not attached:
        names = ", ".join(d["name"] or d["device_id"][:8] for d in active)
        raise HTTPException(status_code=409, detail=f"Your plan allows {account['max_devices']} computer(s), already "
                                                    f"used by: {names}. Sign out on one of them first.")  # fmt: skip
    await repo.login_succeeded(account["id"])
    settings = request.app.state.settings
    licence = issue(account, device_id=body.device_id, issuer=_issuer(request), private=private,
                    offline_days=settings.licence_offline_days)  # fmt: skip
    await audit(request, SERVICE, "account.sign_in", account["id"], details={"device": body.device_id[:12]})
    return {"licence": licence, "account": account}


async def _licence_account(request: Request, token: str) -> tuple[dict[str, Any], dict[str, Any], Any]:
    repo, private = _service(request)
    _limit(request)
    try:
        payload = verify(token, private.public_key(), issuer=_issuer(request))
    except LicenceError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    account = await repo.get(payload["sub"])
    if account is None:
        raise HTTPException(status_code=401, detail="This account no longer exists")
    return payload, account, private


@router.post("/refresh")
async def refresh(body: LicenceRequest, request: Request):
    """Renew a licence (Argus Personal does this quietly): picks up plan and payment changes."""
    payload, account, private = await _licence_account(request, body.licence)
    if not await request.app.state.subscribers.device_active(account["id"], payload["device"]):
        raise HTTPException(status_code=401, detail="This computer was signed out of the account: sign in again")
    if account["status"] == "suspended":
        raise HTTPException(status_code=403, detail="This account is suspended: contact support")
    licence = issue(account, device_id=payload["device"], issuer=_issuer(request), private=private,
                    offline_days=request.app.state.settings.licence_offline_days)  # fmt: skip
    return {"licence": licence, "account": account}


@router.post("/sign-out", status_code=204)
async def sign_out(body: LicenceRequest, request: Request):
    """Free this computer's place on the account."""
    payload, account, _private = await _licence_account(request, body.licence)
    await request.app.state.subscribers.revoke_device(account["id"], payload["device"])
    await audit(request, SERVICE, "account.sign_out", account["id"], details={"device": payload["device"][:12]})
    return Response(status_code=204)


# ---------------------------------------------------------------------------- administration
@router.get("")
async def list_accounts(request: Request, _: Principal = Depends(require_platform_admin)):
    repo, _private = _service(request)
    return await repo.list_accounts()


@router.get("/{account_id}")
async def get_account(account_id: str, request: Request, _: Principal = Depends(require_platform_admin)):
    repo, _private = _service(request)
    account = await repo.get(account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="Account not found")
    return {**account, "device_list": await repo.devices(account_id)}


@router.patch("/{account_id}")
async def update_account(account_id: str, body: AccountUpdate, request: Request,
                         principal: Principal = Depends(require_platform_admin)):  # fmt: skip
    """Change plan, status or paid-until date by hand (payments do this automatically)."""
    repo, _private = _service(request)
    changes = body.model_dump(exclude_none=True)
    if "valid_until" in changes and changes["valid_until"].tzinfo is None:
        changes["valid_until"] = changes["valid_until"].replace(tzinfo=timezone.utc)
    account = await repo.update(account_id, **changes)
    if account is None:
        raise HTTPException(status_code=404, detail="Account not found")
    await audit(request, principal, "account.update", account_id, details={k: str(v) for k, v in changes.items()})
    return account


@router.delete("/{account_id}/devices/{device_id}", status_code=204)
async def revoke_account_device(account_id: str, device_id: str, request: Request,
                                principal: Principal = Depends(require_platform_admin)):  # fmt: skip
    repo, _private = _service(request)
    if not await repo.revoke_device(account_id, device_id):
        raise HTTPException(status_code=404, detail="Device not found")
    await audit(request, principal, "account.device_revoked", account_id, details={"device": device_id[:12]})
    return Response(status_code=204)
