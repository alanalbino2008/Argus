"""The owner console's sign-in: set-up, password + authenticator code, sessions, and the owner's security.

Only a full owner session (password and code) reaches the console's other endpoints
(``require_owner``). API keys, workspace users and single sign-on are never accepted here.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from argus.accounts import owner as owner_mod
from argus.accounts.passwords import DUMMY_HASH, hash_password, verify_password, weakness
from argus.api.deps import _same_origin, audit, client_ip, public_base_url
from argus.security import totp
from argus.security.auth import Principal, Role
from argus.security.ratelimit import SlidingWindowLimiter

router = APIRouter(prefix="/api/owner", tags=["owner"])
COOKIE = "argus_owner"
CODE_STAGE_TTL = timedelta(minutes=5)  # between the password and the code
SETUP_TTL = timedelta(minutes=15)
LOCK_AFTER, LOCK_FOR = 5, timedelta(minutes=15)
CONFIRM_FOR = timedelta(minutes=10)  # a code is fresh enough for sensitive changes this long
PENDING_KEY = "owner_setup_pending"
_attempts = SlidingWindowLimiter(limit=30, window=600, name="owner_sign_in")  # per address, for every sign-in step
OWNER = Principal(key_id="owner", name="owner", role=Role.ADMIN)


class SetupStart(BaseModel):
    email: str = Field(max_length=320)
    setup_key: str = Field(max_length=256)


class SetupFinish(SetupStart):
    password: str = Field(max_length=256)
    code: str = Field(max_length=16)


class Login(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(max_length=256)


class Code(BaseModel):
    code: str = Field(max_length=32)


class PasswordChange(BaseModel):
    current: str = Field(max_length=256)
    new: str = Field(max_length=256)


class EndSession(BaseModel):
    id: str = Field(min_length=12, max_length=12)


# ---------------------------------------------------------------------------- helpers
def _enabled(request: Request) -> Any:
    settings = request.app.state.settings
    if settings.edition == "personal":
        raise HTTPException(status_code=404, detail="Not found")
    return settings


async def _guard(request: Request) -> None:
    if request.method != "GET" and not _same_origin(request):
        raise HTTPException(status_code=403, detail="Cross-site request refused")
    if not await _attempts.allow(client_ip(request) or "unknown"):
        raise HTTPException(status_code=429, detail="Too many attempts from this address; wait a few minutes")


def _set_cookie(request: Request, response: Response, token: str, ttl: timedelta) -> None:
    response.set_cookie(COOKIE, token, max_age=int(ttl.total_seconds()), httponly=True, samesite="strict", path="/",
                        secure=public_base_url(request).startswith("https://"))  # fmt: skip


def _ttl(settings: Any) -> timedelta:
    return timedelta(hours=settings.owner_session_hours)


def _who(request: Request) -> tuple[str, str]:
    return client_ip(request) or "unknown", (request.headers.get("user-agent") or "")[:255]


async def owner_session(request: Request, *, stage: str = "full") -> dict[str, Any] | None:
    """The caller's live owner session at ``stage``, if any (never raises)."""
    token = request.cookies.get(COOKIE)
    if not token or request.app.state.settings.edition == "personal":
        return None
    settings = request.app.state.settings
    idle = timedelta(minutes=settings.owner_idle_minutes) if stage == "full" else None
    session = await request.app.state.owner.session(token, idle)
    return session if session and session["stage"] == stage else None


async def require_owner(request: Request, *, fresh: bool = False) -> dict[str, Any]:
    """The owner's full session; with ``fresh``, a code given within the last 10 minutes."""
    _enabled(request)
    if request.method != "GET" and not _same_origin(request):
        raise HTTPException(status_code=403, detail="Cross-site request refused")
    session = await owner_session(request)
    if session is None:
        raise HTTPException(status_code=401, detail="Sign in to the owner console")
    if fresh:
        confirmed = session["confirmed_at"]
        if confirmed is None or confirmed + CONFIRM_FOR < datetime.now(timezone.utc):
            raise HTTPException(status_code=401, detail="Enter a code from your authenticator app to confirm",
                                headers={"X-Argus-Confirm": "code"})  # fmt: skip
    return session


async def _locked(request: Request) -> dict[str, Any] | None:
    owner = await request.app.state.owner.get()
    if owner and owner["locked_until"] and owner["locked_until"] > datetime.now(timezone.utc):
        minutes = max(1, int((owner["locked_until"] - datetime.now(timezone.utc)).total_seconds() // 60) + 1)
        raise HTTPException(status_code=423, detail=f"Too many wrong attempts: the console is locked for {minutes} "
                                                    "more minute(s)")  # fmt: skip
    return owner


async def _wrong(request: Request, owner: dict[str, Any] | None, what: str) -> HTTPException:
    if owner is not None:
        ip, agent = _who(request)
        if await request.app.state.owner.failed(LOCK_AFTER, LOCK_FOR):
            await owner_mod.alert(request.app, owner["email"], "Owner console locked after wrong attempts",
                                  [f"Five wrong {what}s in a row, the last from {ip} ({agent}).",
                                   "The console is locked for 15 minutes."])  # fmt: skip
        await audit(request, OWNER, "owner.sign_in_failed", "owner", "denied", {"step": what, "ip": ip})
    return HTTPException(status_code=401, detail="Wrong email or password" if what == "password" else "Wrong code")


async def _check_code(request: Request, owner: dict[str, Any], code: str) -> str | None:
    """ "code" or "recovery" if the code is right (and not used before)."""
    repo = request.app.state.owner
    if "-" in code or len(code.strip()) > 8:  # a recovery code
        return "recovery" if await repo.use_recovery(owner_mod.recovery_hash(code)) else None
    secret = owner_mod.box(request.app.state.settings).open(owner["totp_sealed"], owner_mod.TOTP_CONTEXT)["secret"]
    counter = totp.verify(secret, code, last_counter=owner["totp_last_counter"])
    return "code" if counter is not None and await repo.use_counter(counter) else None


# ---------------------------------------------------------------------------- state and set-up
@router.get("/state")
async def owner_state(request: Request):
    """What the console page should show: set-up, sign-in, the code step, or the console."""
    settings = _enabled(request)
    owner = await request.app.state.owner.get()
    stage = "full" if await owner_session(request) else "code" if await owner_session(request, stage="code") else None
    return {"configured": bool(settings.owner_email), "owner_exists": owner is not None, "stage": stage,
            "encryption": owner_mod.box(settings).available,
            "email": owner["email"] if owner and stage == "full" else None}  # fmt: skip


async def _setup_checks(request: Request, body: SetupStart) -> str:
    settings = _enabled(request)
    await _guard(request)
    if await request.app.state.owner.get() is not None:
        raise HTTPException(status_code=409, detail="The owner is already set up")
    if not settings.owner_email:
        raise HTTPException(status_code=403, detail="Set ARGUS_OWNER_EMAIL to your email address first")
    if not owner_mod.box(settings).available:
        raise HTTPException(status_code=503, detail="This server needs an encryption key (ARGUS_ENCRYPTION_KEY) "
                                                    "or a licence signing key to protect the owner's secrets")  # fmt: skip
    email = body.email.strip().lower()
    principal = await request.app.state.keys.authenticate(body.setup_key.strip()) if body.setup_key.strip() else None
    if email != settings.owner_email.strip().lower() or principal is None or not principal.platform_admin:
        ip, _agent = _who(request)
        await audit(request, OWNER, "owner.setup_refused", "owner", "denied", {"ip": ip})
        raise HTTPException(status_code=403, detail="That email or set-up key isn't right")
    return email


@router.post("/setup/start")
async def owner_setup_start(body: SetupStart, request: Request):
    """Step 1: prove you control the server; get the authenticator QR code."""
    email = await _setup_checks(request, body)
    secret = totp.new_secret()
    box = owner_mod.box(request.app.state.settings)
    expires = (datetime.now(timezone.utc) + SETUP_TTL).isoformat()
    await request.app.state.app_state.set(PENDING_KEY, {"sealed": box.seal({"secret": secret, "expires": expires},
                                                                           "owner-setup")})  # fmt: skip
    uri = totp.provisioning_uri(secret, email, issuer=f"Argus ({request.url.hostname})")
    return {"secret": secret, "uri": uri, "qr_svg": totp.qr_svg(uri)}


@router.post("/setup/finish")
async def owner_setup_finish(body: SetupFinish, request: Request, response: Response):
    """Step 2: choose the password and confirm the first code; you're signed in with your recovery codes."""
    email = await _setup_checks(request, body)
    settings = request.app.state.settings
    box = owner_mod.box(settings)
    pending = await request.app.state.app_state.get(PENDING_KEY)
    try:
        data = box.open(pending["sealed"], "owner-setup") if pending else None
    except Exception:  # noqa: BLE001 - an unreadable pending set-up is the same as none
        data = None
    if not data or datetime.fromisoformat(data["expires"]) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Set-up took too long: start again")
    problem = weakness(body.password, email)
    if problem:
        raise HTTPException(status_code=422, detail=problem)
    if totp.verify(data["secret"], body.code) is None:
        raise HTTPException(
            status_code=422, detail="That code doesn't match: check the time on your phone and try again"
        )
    codes = owner_mod.new_recovery_codes()
    hashed = await asyncio.to_thread(hash_password, body.password)
    created = await request.app.state.owner.create(
        email=email, password_hash=hashed, totp_sealed=box.seal({"secret": data["secret"]}, owner_mod.TOTP_CONTEXT),
        recovery_hashes=[owner_mod.recovery_hash(c) for c in codes])  # fmt: skip
    if not created:
        raise HTTPException(status_code=409, detail="The owner is already set up")
    await request.app.state.app_state.delete(PENDING_KEY)
    ip, agent = _who(request)
    token = await request.app.state.owner.new_session("full", _ttl(settings), ip, agent)
    _set_cookie(request, response, token, _ttl(settings))
    await request.app.state.owner.update(last_login_at=datetime.now(timezone.utc))
    await audit(request, OWNER, "owner.setup", "owner", details={"email": email, "ip": ip})
    await owner_mod.alert(request.app, email, "Owner console set up", [f"You set up the owner console from {ip}."])
    return {"recovery_codes": codes}


# ---------------------------------------------------------------------------- signing in
@router.post("/login")
async def owner_login(body: Login, request: Request, response: Response):
    """Step 1 of signing in: email and password."""
    settings = _enabled(request)
    await _guard(request)
    owner = await _locked(request)
    stored = owner["password_hash"] if owner else DUMMY_HASH
    ok = await asyncio.to_thread(verify_password, body.password, stored)  # same work whether or not it matches
    if owner is None or not ok or body.email.strip().lower() != owner["email"]:
        raise await _wrong(request, owner, "password")
    ip, agent = _who(request)
    token = await request.app.state.owner.new_session("code", CODE_STAGE_TTL, ip, agent)
    _set_cookie(request, response, token, CODE_STAGE_TTL)
    return {"stage": "code", "session_hours": settings.owner_session_hours}


@router.post("/verify")
async def owner_verify(body: Code, request: Request, response: Response):
    """Step 2: the authenticator code (or a recovery code)."""
    settings = _enabled(request)
    await _guard(request)
    owner = await _locked(request)
    token = request.cookies.get(COOKIE)
    if owner is None or not token or await owner_session(request, stage="code") is None:
        raise HTTPException(status_code=401, detail="Start again with your email and password")
    kind = await _check_code(request, owner, body.code)
    if kind is None:
        raise await _wrong(request, owner, "code")
    full = await request.app.state.owner.promote(token, _ttl(settings))
    if full is None:
        raise HTTPException(status_code=401, detail="Start again with your email and password")
    _set_cookie(request, response, full, _ttl(settings))
    await request.app.state.owner.update(failed=0, last_login_at=datetime.now(timezone.utc))
    ip, agent = _who(request)
    await audit(request, OWNER, "owner.sign_in", "owner", details={"ip": ip, "with": kind})
    lines = [f"Signed in from {ip} ({agent})."]
    if kind == "recovery":
        left = (await request.app.state.owner.get() or {}).get("recovery_left", 0)
        lines.append(f"A recovery code was used: {left} left. If you've lost your phone, set up the authenticator "
                     "again under Security.")  # fmt: skip
    await owner_mod.alert(request.app, owner["email"], "New sign-in to the owner console", lines)
    return {"stage": "full", "used_recovery_code": kind == "recovery"}


@router.post("/confirm")
async def owner_confirm(body: Code, request: Request):
    """A fresh code before a sensitive change (keys, passwords, payments)."""
    await require_owner(request)
    await _guard(request)
    owner = await _locked(request)
    if owner is None or await _check_code(request, owner, body.code) is None:
        raise await _wrong(request, owner, "code")
    await request.app.state.owner.confirm(request.cookies.get(COOKIE, ""))
    await request.app.state.owner.update(failed=0)
    return {"confirmed": True, "for_minutes": int(CONFIRM_FOR.total_seconds() // 60)}


@router.post("/logout")
async def owner_logout(request: Request, response: Response):
    _enabled(request)
    token = request.cookies.get(COOKIE)
    if token:
        await request.app.state.owner.end(token)
    response.delete_cookie(COOKIE, path="/")
    return {"signed_out": True}


# ---------------------------------------------------------------------------- the owner's own security
@router.get("/security")
async def owner_security(request: Request):
    await require_owner(request)
    owner = await request.app.state.owner.get() or {}
    current = request.cookies.get(COOKIE, "")
    from argus.storage.owner_repo import token_hash

    sessions = [
        {**s, "current": token_hash(current).startswith(s["id"])} for s in await request.app.state.owner.sessions()
    ]
    return {"email": owner.get("email"), "recovery_left": owner.get("recovery_left"), "sessions": sessions,
            "created_at": owner.get("created_at"), "last_login_at": owner.get("last_login_at")}  # fmt: skip


@router.post("/sessions/end")
async def owner_end_session(body: EndSession, request: Request):
    await require_owner(request)
    if not await request.app.state.owner.end_one(body.id):
        raise HTTPException(status_code=404, detail="No such session")
    await audit(request, OWNER, "owner.session_ended", body.id)
    return {"ended": True}


@router.post("/sessions/end-others")
async def owner_end_others(request: Request):
    await require_owner(request)
    count = await request.app.state.owner.end_all(except_token=request.cookies.get(COOKIE))
    await audit(request, OWNER, "owner.sessions_ended", "owner", details={"count": count})
    return {"ended": count}


@router.post("/password")
async def owner_password(body: PasswordChange, request: Request):
    """Change the password (a fresh code needed); every other session is signed out."""
    await require_owner(request, fresh=True)
    owner = await request.app.state.owner.get()
    if owner is None or not await asyncio.to_thread(verify_password, body.current, owner["password_hash"]):
        raise HTTPException(status_code=401, detail="Your current password isn't right")
    problem = weakness(body.new, owner["email"])
    if problem:
        raise HTTPException(status_code=422, detail=problem)
    await request.app.state.owner.update(password_hash=await asyncio.to_thread(hash_password, body.new))
    ended = await request.app.state.owner.end_all(except_token=request.cookies.get(COOKIE))
    await audit(request, OWNER, "owner.password_changed", "owner", details={"other_sessions_ended": ended})
    await owner_mod.alert(request.app, owner["email"], "Owner password changed",
                          ["Your owner console password was changed, and every other session signed out."])  # fmt: skip
    return {"changed": True, "other_sessions_ended": ended}


@router.post("/recovery-codes")
async def owner_recovery_codes(request: Request):
    """Ten new recovery codes (a fresh code needed); the old ones stop working."""
    await require_owner(request, fresh=True)
    codes = owner_mod.new_recovery_codes()
    await request.app.state.owner.update(recovery_hashes=[owner_mod.recovery_hash(c) for c in codes])
    await audit(request, OWNER, "owner.recovery_codes", "owner")
    return {"recovery_codes": codes}


@router.post("/authenticator/start")
async def owner_authenticator_start(request: Request):
    """Move to a new phone: a new secret to scan (a fresh code from the old one, or a recovery code, needed)."""
    await require_owner(request, fresh=True)
    owner = await request.app.state.owner.get() or {}
    secret = totp.new_secret()
    box = owner_mod.box(request.app.state.settings)
    expires = (datetime.now(timezone.utc) + SETUP_TTL).isoformat()
    await request.app.state.app_state.set(PENDING_KEY, {"sealed": box.seal({"secret": secret, "expires": expires},
                                                                           "owner-setup")})  # fmt: skip
    uri = totp.provisioning_uri(secret, owner.get("email", "owner"), issuer=f"Argus ({request.url.hostname})")
    return {"secret": secret, "uri": uri, "qr_svg": totp.qr_svg(uri)}


@router.post("/authenticator/finish")
async def owner_authenticator_finish(body: Code, request: Request):
    await require_owner(request, fresh=True)
    box = owner_mod.box(request.app.state.settings)
    pending = await request.app.state.app_state.get(PENDING_KEY)
    try:
        data = box.open(pending["sealed"], "owner-setup") if pending else None
    except Exception:  # noqa: BLE001
        data = None
    if not data or datetime.fromisoformat(data["expires"]) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="That took too long: start again")
    if totp.verify(data["secret"], body.code) is None:
        raise HTTPException(status_code=422, detail="That code doesn't match the new authenticator")
    await request.app.state.owner.update(totp_sealed=box.seal({"secret": data["secret"]}, owner_mod.TOTP_CONTEXT),
                                         totp_last_counter=-1)  # fmt: skip
    await request.app.state.app_state.delete(PENDING_KEY)
    owner = await request.app.state.owner.get() or {}
    await audit(request, OWNER, "owner.authenticator_changed", "owner")
    await owner_mod.alert(request.app, owner.get("email", ""), "Owner authenticator changed",
                          ["The authenticator app for the owner console was replaced."])  # fmt: skip
    return {"changed": True}
