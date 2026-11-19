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
from html import escape
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from argus.accounts import emails
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


class ResetRequest(BaseModel):
    email: str = Field(max_length=320)


class ResetConfirm(BaseModel):
    token: str = Field(min_length=20, max_length=128)
    password: str = Field(max_length=256)


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
    await request.app.state.mailer.notify(account, "welcome", "1")
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


# ---------------------------------------------------------------------------- forgotten passwords
RESET_TTL = timedelta(hours=1)
_resets_per_ip = SlidingWindowLimiter(limit=10, window=3600)


@router.post("/password-reset", status_code=202)
async def request_password_reset(body: ResetRequest, request: Request):
    """Email a reset link. The answer is the same whether or not the account exists."""
    repo, _private = _service(request)
    _limit(request)
    if not _resets_per_ip.hit(client_ip(request) or "unknown"):
        raise HTTPException(status_code=429, detail="Too many reset requests from this address; try later")
    mailer = request.app.state.mailer
    if not mailer.enabled:
        raise HTTPException(status_code=503, detail="Password resets need email, which isn't set up: contact support")
    found = await repo.by_email(body.email.strip())
    mail = request.app.state.account_mail
    if found is not None and found[0]["status"] != "suspended":
        account = found[0]
        if await mail.recent_resets(account["id"], timedelta(hours=1)) < 3:  # no flooding someone's inbox
            token = await mail.new_reset(account["id"], RESET_TTL)
            link = f"{_issuer(request)}/reset-password#token={token}"
            await mailer.notify(account, "password_reset", token[:16], link=link,
                                minutes=int(RESET_TTL.total_seconds() // 60))  # fmt: skip
            await audit(request, SERVICE, "account.password_reset_requested", account["id"],
                        details={"ip": client_ip(request)})  # fmt: skip
    return {"detail": "If an account uses that email, a reset link is on its way. It works for one hour."}


@router.post("/password-reset/confirm")
async def confirm_password_reset(body: ResetConfirm, request: Request):
    """Set a new password with a reset link; every computer is signed out."""
    repo, _private = _service(request)
    _limit(request)
    mail = request.app.state.account_mail
    expired = "This reset link has expired or was already used: ask for a new one"
    account_id = await mail.use_reset(body.token, consume=False)
    account = await repo.get(account_id) if account_id else None
    if account is None:
        raise HTTPException(status_code=400, detail=expired)
    problem = weakness(body.password, account["email"])
    if problem:  # the link still works: they can try a better password
        raise HTTPException(status_code=422, detail=problem)
    if await mail.use_reset(body.token) != account["id"]:  # used up in the meantime
        raise HTTPException(status_code=400, detail=expired)
    hashed = await asyncio.to_thread(hash_password, body.password)
    await repo.update(account["id"], password_hash=hashed, failed_logins=0, locked_until=None)
    signed_out = await repo.revoke_all_devices(account["id"])
    await audit(request, SERVICE, "account.password_reset", account["id"],
                details={"computers_signed_out": signed_out, "ip": client_ip(request)})  # fmt: skip
    await request.app.state.mailer.notify(account, "password_changed", body.token[:16])
    return {"detail": "Your password has been changed. Sign in again on each computer with the new password."}


# ---------------------------------------------------------------------------- reminder emails
@router.get("/emails/unsubscribe", response_class=HTMLResponse)
async def unsubscribe_reminders(request: Request, a: str = Query("", max_length=40), t: str = Query("", max_length=64)):
    """One-click unsubscribe from reminder emails (the link in each reminder)."""
    _service(request)
    secret = request.app.state.mailer._secret()
    ok = (
        bool(a) and emails.unsubscribe_ok(secret, a, t) and await request.app.state.account_mail.set_reminders(a, False)
    )
    if ok:
        await audit(request, SERVICE, "account.reminders_off", a)
    message = ("You won't get reminder emails any more. Emails about your account itself (payments, password "
               "changes) still arrive." if ok else "This unsubscribe link isn't valid.")  # fmt: skip
    return HTMLResponse(_page("Reminder emails", message), status_code=200 if ok else 400)


@router.post("/emails/unsubscribe")
async def unsubscribe_one_click(request: Request, a: str = Query("", max_length=40), t: str = Query("", max_length=64)):
    """RFC 8058 one-click unsubscribe, as mail apps send it."""
    _service(request)
    secret = request.app.state.mailer._secret()
    if not (a and emails.unsubscribe_ok(secret, a, t) and await request.app.state.account_mail.set_reminders(a, False)):
        raise HTTPException(status_code=400, detail="Invalid unsubscribe link")
    await audit(request, SERVICE, "account.reminders_off", a)
    return {"detail": "Unsubscribed from reminders"}


def _page(title: str, message: str) -> str:
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" '
            f'content="width=device-width,initial-scale=1"><title>{escape(title)} \u2014 Argus</title>'
            f'<link rel="stylesheet" href="/static/styles.css"></head><body><main class="signin-root"><div class="card signin '
            f'card-pad"><h1>{escape(title)}</h1><p>{escape(message)}</p></div></main></body></html>')  # fmt: skip


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
    return {**account, "device_list": await repo.devices(account_id),
            "emails": await request.app.state.account_mail.for_account(account_id)}  # fmt: skip


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
