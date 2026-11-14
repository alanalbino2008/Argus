"""Single sign-on (OIDC) endpoints, browser sessions and user management.

Flow: ``GET /auth/oidc/login`` -> provider -> ``GET /auth/oidc/callback`` -> session
cookie -> the web app. Failures redirect to ``/?sso_error=<code>`` with a code the UI
explains; details go to the audit log, never to the browser.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

from argus.api.deps import SESSION_COOKIE, audit, client_ip, public_base_url, require_platform_admin
from argus.observability import metrics
from argus.security.auth import Principal, Role
from argus.security.oidc import (
    OidcError,
    OidcProvider,
    check_identity,
    groups_configured,
    new_login_secrets,
    resolve_role,
    safe_return_path,
)
from argus.security.ratelimit import SlidingWindowLimiter
from argus.storage.user_repo import UserRepository

logger = logging.getLogger("argus.api.sso")
router = APIRouter(tags=["single sign-on"])
LOGIN_TTL = timedelta(minutes=10)
_login_limiter = SlidingWindowLimiter(limit=30, window=60)  # per client IP


def _provider(request: Request) -> OidcProvider:
    provider: OidcProvider | None = getattr(request.app.state, "oidc", None)
    if provider is None:
        raise HTTPException(status_code=404, detail="Single sign-on is not configured")
    return provider


def _redirect_uri(request: Request) -> str:
    return f"{public_base_url(request)}/auth/oidc/callback"


def _fail(code: str) -> RedirectResponse:
    metrics.SSO_LOGINS.labels(code).inc()
    return RedirectResponse(f"/?sso_error={code}", status_code=303)


@router.get("/api/auth/config")
async def auth_config(request: Request):
    """Public: which sign-in methods the web app should offer."""
    provider = getattr(request.app.state, "oidc", None)
    return {
        "sso": {"enabled": provider is not None, "name": request.app.state.settings.oidc_display_name},
        "api_keys": True,
    }


@router.get("/auth/oidc/login")
async def oidc_login(request: Request, return_to: str | None = Query(None, max_length=512)):
    provider = _provider(request)
    if not _login_limiter.hit(client_ip(request) or "unknown"):
        metrics.RATE_LIMITED.labels("sso_login").inc()
        raise HTTPException(status_code=429, detail="Too many sign-in attempts")
    state, nonce, verifier = new_login_secrets()
    users: UserRepository = request.app.state.users
    await users.start_login(state, nonce, verifier, safe_return_path(return_to), LOGIN_TTL)
    try:
        url = await provider.authorization_url(state, nonce, verifier, _redirect_uri(request))
    except OidcError as exc:
        logger.error("Cannot start SSO login: %s", exc)
        return _fail(exc.code)
    return RedirectResponse(url, status_code=303)


@router.get("/auth/oidc/callback")
async def oidc_callback(
    request: Request,
    code: str | None = Query(None, max_length=4096),
    state: str | None = Query(None, max_length=256),
    error: str | None = Query(None, max_length=128),
):
    provider = _provider(request)
    settings = request.app.state.settings
    users: UserRepository = request.app.state.users
    anon = Principal(key_id="unauthenticated", name="unauthenticated", role=Role.VIEWER)
    login = await users.finish_login(state) if state else None  # consume the state whatever happens next
    if error:
        await audit(request, anon, "auth.sso_failed", None, "denied", {"reason": "provider_error", "error": error})
        return _fail("provider_denied")
    if login is None or not code:
        await audit(request, anon, "auth.sso_failed", None, "denied", {"reason": "invalid_or_expired_state"})
        return _fail("expired")
    try:
        tokens = await provider.exchange_code(code, login["code_verifier"], _redirect_uri(request))
        claims = await provider.verify_id_token(tokens["id_token"], login["nonce"])
        email = check_identity(claims, settings)
        role = resolve_role(claims, email, settings)
        if role is None:
            raise OidcError("no_role", "no Argus role is granted to this account")
    except OidcError as exc:
        await audit(request, anon, "auth.sso_failed", None, "denied", {"reason": exc.code, "detail": str(exc)[:300]})
        return _fail(exc.code)
    except Exception:
        logger.exception("SSO callback failed")
        await audit(request, anon, "auth.sso_failed", None, "denied", {"reason": "provider_unreachable"})
        return _fail("provider_unreachable")

    is_bootstrap_admin = bool(email) and email in {e.lower() for e in settings.oidc_admin_emails}
    user = await users.upsert_from_login(
        issuer=provider.issuer,
        subject=str(claims["sub"]),
        email=email,
        name=str(claims.get("name") or "")[:255] or None,
        role=role,
        role_from_idp=groups_configured(settings) or is_bootstrap_admin,
    )
    who = Principal(
        key_id=f"user:{user['id']}", name=user["email"] or user["name"] or user["id"], role=Role(user["role"])
    )
    if not user["disabled"]:
        await _sync_memberships(request, user, claims, role)
    if user["disabled"]:
        await audit(request, who, "auth.sso_failed", user["id"], "denied", {"reason": "disabled"})
        return _fail("disabled")

    ttl = timedelta(hours=settings.session_ttl_hours)
    token = await users.create_session(user["id"], ttl, client_ip(request), request.headers.get("user-agent"))
    await audit(request, who, "auth.login", user["id"], details={"method": "oidc", "role": user["role"]})
    metrics.SSO_LOGINS.labels("success").inc()
    response = RedirectResponse(login["return_to"], status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=int(ttl.total_seconds()),
        httponly=True,  # unreadable by JavaScript: XSS cannot steal it
        secure=public_base_url(request).startswith("https://"),
        samesite="lax",  # not sent on cross-site POSTs (CSRF); Origin is checked as well
        path="/",
    )
    return response


async def _sync_memberships(request: Request, user: dict[str, Any], claims: dict[str, Any], role: str) -> None:
    """Join the default workspace, and mirror IdP groups that are mapped to workspaces."""
    settings = request.app.state.settings
    workspaces = request.app.state.workspaces
    by = "single sign-on"
    if settings.oidc_default_workspace:
        default = await workspaces.get(settings.oidc_default_workspace)
        if default and (groups_configured(settings) or await workspaces.role_of(default["id"], user["id"]) is None):
            await workspaces.set_member(default["id"], user["id"], role, by)
    if settings.oidc_workspace_groups:
        raw = claims.get(settings.oidc_role_claim)
        groups = {raw} if isinstance(raw, str) else {str(g) for g in raw} if isinstance(raw, list) else set()
        for group, slug in settings.oidc_workspace_groups.items():
            ws = await workspaces.get(slug)
            if ws is None:
                logger.warning("SSO group %s maps to unknown workspace %s", group, slug)
                continue
            if group in groups:
                await workspaces.set_member(ws["id"], user["id"], role, by)
            elif await workspaces.role_of(ws["id"], user["id"]) is not None:
                await workspaces.remove_member(ws["id"], user["id"])  # left the team in the IdP


@router.post("/api/auth/logout")
async def logout(request: Request):
    """End this browser session; returns the provider's sign-out URL (single logout) when it has one."""
    token = request.cookies.get(SESSION_COOKIE)
    users: UserRepository = request.app.state.users
    ended = bool(token) and await users.delete_session(token or "")
    end_session_url = None
    provider: OidcProvider | None = getattr(request.app.state, "oidc", None)
    if ended and provider is not None:
        try:
            end_session_url = await provider.end_session_url(f"{public_base_url(request)}/")
        except Exception:
            logger.warning("Could not build the provider sign-out URL", exc_info=True)
    response = JSONResponse({"signed_out": ended, "end_session_url": end_session_url})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


# ---------------------------------------------------------------------------- user management
class UpdateUserRequest(BaseModel):
    role: Role | None = None
    disabled: bool | None = None


@router.get("/api/users")
async def list_users(request: Request, _: Principal = Depends(require_platform_admin)) -> list[dict[str, Any]]:
    return await request.app.state.users.list_users()


@router.patch("/api/users/{user_id}")
async def update_user(
    user_id: str, body: UpdateUserRequest, request: Request, principal: Principal = Depends(require_platform_admin)
):
    """Change a user's role or disable them (which also ends all their sessions immediately)."""
    if principal.key_id == f"user:{user_id}" and (body.disabled or (body.role and body.role != Role.ADMIN)):
        raise HTTPException(status_code=409, detail="You cannot disable or demote yourself")
    updated = await request.app.state.users.update(
        user_id, role=body.role.value if body.role else None, disabled=body.disabled
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="User not found")
    await audit(request, principal, "user.update", user_id, details=body.model_dump(exclude_none=True, mode="json"))
    return updated
