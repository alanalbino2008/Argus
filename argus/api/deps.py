"""FastAPI dependencies: authentication, authorisation (RBAC) and audit helpers."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlsplit

from fastapi import Depends, HTTPException, Request, status

from argus.observability import metrics
from argus.security.auth import ANONYMOUS_ADMIN, Principal, Role
from argus.security.ratelimit import SlidingWindowLimiter
from argus.storage.security_repo import ApiKeyRepository, AuditLog

logger = logging.getLogger("argus.api.auth")

# Throttle how many failed-auth events per IP are written to the audit log (anti log-flooding).
_auth_failure_audit = SlidingWindowLimiter(limit=10, window=60)


def client_ip(request: Request) -> str | None:
    # Behind a reverse proxy, run uvicorn with --proxy-headers so this is the real client.
    return request.client.host if request.client else None


SESSION_COOKIE = "argus_session"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def public_base_url(request: Request) -> str:
    """The URL users reach Argus at (ARGUS_PUBLIC_URL, else derived from the request)."""
    configured = request.app.state.settings.public_url
    return (configured or str(request.base_url)).rstrip("/")


def _same_origin(request: Request) -> bool:
    """CSRF defence for cookie-authenticated writes: the request must come from our own pages.

    Browsers always send Origin on cross-origin POSTs (and on same-origin ones in modern
    browsers); a missing Origin falls back to Referer. API-key callers are not affected.
    """
    source = request.headers.get("origin") or request.headers.get("referer")
    if not source:
        return False
    expected = urlsplit(public_base_url(request))
    got = urlsplit(source)
    return (got.scheme, got.netloc) == (expected.scheme, expected.netloc)


def _extract_key(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.headers.get("x-api-key")


async def audit(
    request: Request,
    principal: Principal,
    action: str,
    resource: str | None = None,
    outcome: str = "success",
    details: dict[str, Any] | None = None,
) -> None:
    """Write an audit event; never let an audit failure break the request itself."""
    try:
        log: AuditLog = request.app.state.audit
        await log.record(principal, action, resource, outcome, client_ip(request), details)
    except Exception:
        logger.exception("Failed to write audit event %s", action)


async def get_principal(request: Request) -> Principal:
    if not request.app.state.settings.auth_enabled:
        return ANONYMOUS_ADMIN
    key = _extract_key(request)
    cookie = request.cookies.get(SESSION_COOKIE)
    if not key and cookie:
        return await _session_principal(request, cookie)
    keys: ApiKeyRepository = request.app.state.keys
    principal = await keys.authenticate(key) if key else None
    if principal is None:
        metrics.AUTH_FAILURES.labels("invalid_key" if key else "missing_key").inc()
        ip = client_ip(request) or "unknown"
        # Only a *presented but invalid* key is a security signal (guessing, leaked or
        # revoked credentials). A visitor who has not signed in yet is just noise.
        if key and _auth_failure_audit.hit(ip):
            anon = Principal(key_id="unauthenticated", name="unauthenticated", role=Role.VIEWER)
            await audit(
                request,
                anon,
                "auth.failed",
                request.url.path,
                "denied",
                {"reason": "invalid or revoked key", "key_prefix": key[:10]},
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Valid API key required (Authorization: Bearer <key> or X-API-Key header)",
            headers={"WWW-Authenticate": "Bearer"},
        )
    request.state.auth_method = "api_key"
    return principal


async def _session_principal(request: Request, token: str) -> Principal:
    user = await request.app.state.users.resolve_session(token)
    if user is None:
        metrics.AUTH_FAILURES.labels("invalid_session").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Your session has ended - please sign in again",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if request.method in UNSAFE_METHODS and not _same_origin(request):
        metrics.AUTH_FAILURES.labels("csrf").inc()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-site request refused")
    request.state.auth_method = "session"
    request.state.user = user
    return Principal(
        key_id=f"user:{user['id']}", name=user["email"] or user["name"] or user["id"], role=Role(user["role"])
    )


def require(role: Role):
    """Dependency factory: ``Depends(require(Role.ANALYST))``."""

    async def checker(request: Request, principal: Principal = Depends(get_principal)) -> Principal:
        if not principal.has(role):
            metrics.AUTH_FAILURES.labels("insufficient_role").inc()
            await audit(
                request,
                principal,
                "auth.forbidden",
                request.url.path,
                "denied",
                {"required_role": role.value, "actual_role": principal.role.value},
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Requires {role.value} role")
        return principal

    return checker
