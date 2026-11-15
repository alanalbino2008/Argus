"""Argus Personal: signing in with an Argus account, and the licence gate on every request.

**The gate** (personal edition only), applied before any endpoint runs:

* not signed in: only sign-in, sign-up and status answer; everything else asks to sign in;
* subscription lapsed, cancelled, or offline too long: **read-only**. Everything can still be
  opened, verified and exported, but nothing new can be started (scans, captures, uploads,
  watches...): ``402 Payment Required`` with the reason;
* otherwise: full access.

The gate covers every way in, API keys included, so a key cannot be used to get around a lapsed
subscription.
"""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from argus.accounts.personal import AccountServiceError
from argus.api.deps import (
    SESSION_COOKIE,
    UNSAFE_METHODS,
    _same_origin,
    audit,
    client_ip,
    get_principal,
    public_base_url,
)
from argus.security.auth import Principal, Role

router = APIRouter(prefix="/api/personal", tags=["personal"])
OPEN_PATHS = ("/api/personal/", "/api/live", "/api/health", "/api/auth/config", "/api/auth/logout")
# Writes that only read or verify, so they stay available when the subscription has lapsed.
READ_ONLY_WRITES = (re.compile(r"^/api/evidence/[^/]+/verify$"), re.compile(r"^/api/auth/logout$"))


class SignInRequest(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(max_length=256)


class SignUpRequest(SignInRequest):
    name: str = Field(default="", max_length=255)


def _personal(request: Request) -> Any:
    if request.app.state.settings.edition != "personal":
        raise HTTPException(status_code=404, detail="Not found")
    return request.app.state.personal


def _service_error(exc: AccountServiceError) -> HTTPException:
    status = exc.status if exc.status in (401, 403, 409, 422, 423, 429) else 503 if exc.status in (0, 503) else 502
    return HTTPException(status_code=status, detail=exc.detail)


def _csrf(request: Request) -> None:
    if not _same_origin(request):  # a page on another site must not sign this browser in or out
        raise HTTPException(status_code=403, detail="Cross-site request refused")


async def _start_session(request: Request, response: Response, payload: dict[str, Any]) -> dict[str, Any]:
    settings = request.app.state.settings
    users = request.app.state.users
    user = await users.upsert_from_login(
        issuer=f"argus-account:{settings.account_server_url.rstrip('/')}", subject=str(payload["sub"]),
        email=payload.get("email"), name=payload.get("name") or None, role=Role.ADMIN.value, role_from_idp=True,
    )  # fmt: skip
    ttl = timedelta(hours=max(settings.session_ttl_hours, 24 * 14))  # one person's own computer
    token = await users.create_session(user["id"], ttl, client_ip(request), request.headers.get("user-agent"))
    response.set_cookie(SESSION_COOKIE, token, max_age=int(ttl.total_seconds()), httponly=True,
                        secure=public_base_url(request).startswith("https://"), samesite="strict", path="/")  # fmt: skip
    who = Principal(key_id=f"user:{user['id']}", name=user["email"] or user["id"], role=Role.ADMIN)
    await audit(
        request, who, "auth.login", user["id"], details={"method": "argus account", "plan": payload.get("plan")}
    )
    return request.app.state.personal.status()


@router.get("/status")
async def personal_status(request: Request):
    """Whether this computer is signed in, and what the subscription allows (no sign-in needed)."""
    return _personal(request).status()


@router.post("/sign-in")
async def personal_sign_in(body: SignInRequest, request: Request, response: Response):
    """Sign in with an Argus account: unlocks this computer and starts a session."""
    personal = _personal(request)
    _csrf(request)
    try:
        payload = await personal.sign_in(body.email.strip(), body.password)
    except AccountServiceError as exc:
        raise _service_error(exc) from exc
    return await _start_session(request, response, payload)


@router.post("/sign-up")
async def personal_sign_up(body: SignUpRequest, request: Request, response: Response):
    """Create an Argus account (free trial, when the service allows it), then sign in."""
    personal = _personal(request)
    _csrf(request)
    try:
        await personal.sign_up(body.email.strip(), body.password, body.name.strip())
        payload = await personal.sign_in(body.email.strip(), body.password)
    except AccountServiceError as exc:
        raise _service_error(exc) from exc
    return await _start_session(request, response, payload)


@router.post("/refresh")
async def personal_refresh(request: Request):
    """Check the subscription now (after renewing it, for example)."""
    personal = _personal(request)
    await get_principal(request)
    await personal.refresh()
    return personal.status()


@router.post("/sign-out")
async def personal_sign_out(request: Request, response: Response):
    """Sign this computer out of the account (frees its place). Cases stay on this computer."""
    personal = _personal(request)
    principal = await get_principal(request)
    await personal.sign_out()
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        await request.app.state.users.delete_session(token)
    response.delete_cookie(SESSION_COOKIE, path="/")
    await audit(request, principal, "auth.logout", principal.key_id, details={"method": "argus account sign-out"})
    return personal.status()


async def licence_gate(request: Request, call_next: Any) -> Any:
    """Middleware for the personal edition: enforce the licence on every API request."""
    path = request.url.path
    if (request.app.state.settings.edition != "personal" or not path.startswith("/api/")
            or path.startswith(OPEN_PATHS)):  # fmt: skip
        return await call_next(request)
    level, reason = request.app.state.personal.access()
    if level == "none":
        return JSONResponse({"detail": reason, "sign_in": True}, status_code=401)
    if level == "read_only" and request.method in UNSAFE_METHODS and not any(p.match(path) for p in READ_ONLY_WRITES):
        return JSONResponse({"detail": reason, "read_only": True}, status_code=402)
    return await call_next(request)
