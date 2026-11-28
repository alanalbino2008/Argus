"""FastAPI dependencies: authentication, authorisation (RBAC) and audit helpers."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit

from fastapi import Depends, HTTPException, Request, status

from argus.core.models import DEFAULT_WORKSPACE_ID
from argus.observability import metrics
from argus.security.auth import ANONYMOUS_ADMIN, Principal, Role
from argus.security.ratelimit import SlidingWindowLimiter
from argus.storage.security_repo import ApiKeyRepository, AuditLog
from argus.storage.workspace_repo import WorkspaceRepository

logger = logging.getLogger("argus.api.auth")

# Throttle how many failed-auth events per IP are written to the audit log (anti log-flooding).
_auth_failure_audit = SlidingWindowLimiter(limit=10, window=60)
# Brute-force lockout: after this many wrong API keys from one address in the window, every key presented
# from that address is refused with 429 - before it is checked - until the window passes. A right key
# guessed during a lockout gets the same 429, so the lock cannot be used as an oracle. Per replica.
KEY_FAILURES_PER_IP = 30
KEY_FAILURE_WINDOW = 300.0
_key_failures = SlidingWindowLimiter(limit=KEY_FAILURES_PER_IP, window=KEY_FAILURE_WINDOW, name="api_key_guess",
                                     shared=False)  # fmt: skip


def _key_lockout(ip: str) -> HTTPException:
    metrics.RATE_LIMITED.labels("api_key_guess").inc()
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many invalid API keys from this address; try again later",
        headers={"Retry-After": str(_key_failures.retry_after(ip))},
    )


def client_ip(request: Request) -> str | None:
    # Behind a reverse proxy, run uvicorn with --proxy-headers so this is the real client.
    return request.client.host if request.client else None


SESSION_COOKIE = "argus_session"
OWNER_COOKIE = "argus_owner"
OWNER_PRINCIPAL = Principal(key_id="owner", name="owner", role=Role.ADMIN)
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
    if auth.lower().startswith("basic "):
        # For clients that only speak HTTP Basic (TAXII clients such as OpenCTI and MISP): the password
        # is an Argus API key, the user name is ignored. Account passwords are never accepted here.
        try:
            _user, _, password = base64.b64decode(auth[6:].strip(), validate=True).decode().partition(":")
        except (binascii.Error, UnicodeDecodeError):
            return None
        return password.strip() or None
    return request.headers.get("x-api-key")


async def audit(
    request: Request,
    principal: Principal,
    action: str,
    resource: str | None = None,
    outcome: str = "success",
    details: dict[str, Any] | None = None,
) -> None:
    """Write an audit event (tagged with the request's workspace); never let it break the request."""
    try:
        log: AuditLog = request.app.state.audit
        workspace_id = getattr(request.state, "workspace_id", None)
        await log.record(principal, action, resource, outcome, client_ip(request), details, workspace_id)
    except Exception:
        logger.exception("Failed to write audit event %s", action)


def public_address(ip: str | None) -> bool:
    try:
        addr = ipaddress.ip_address(ip or "")
    except ValueError:
        return False  # not a network peer (a Unix socket, an in-process test client)
    return not (addr.is_loopback or addr.is_private or addr.is_link_local)


async def get_principal(request: Request) -> Principal:
    if not request.app.state.settings.auth_enabled:
        # Development mode grants everyone admin - so it serves only this machine and private networks.
        # An instance accidentally exposed with authentication off does not hand the internet its data.
        if public_address(client_ip(request)):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="Authentication is disabled on this server; it only serves local networks")  # fmt: skip
        return ANONYMOUS_ADMIN
    key = _extract_key(request)
    owner = request.cookies.get(OWNER_COOKIE)
    if not key and owner:  # the owner, signed in to the owner console, may also use the app as its administrator
        principal = await _owner_principal(request, owner)
        if principal is not None:
            return principal
    cookie = request.cookies.get(SESSION_COOKIE)
    if not key and cookie:
        return await _session_principal(request, cookie)
    keys: ApiKeyRepository = request.app.state.keys
    ip = client_ip(request)
    if key and _key_failures.remaining(ip or "unknown") <= 0:
        raise _key_lockout(ip or "unknown")
    principal, why = await keys.check(key, ip) if key else (None, None)
    if principal is None:
        # An expired key, or a key used from outside its networks, is refused like a wrong one:
        # the caller learns nothing; the audit log and the metric say why.
        reason = {"expired": "expired_key", "network": "key_network"}.get(why or "", "invalid_key")
        metrics.AUTH_FAILURES.labels(reason if key else "missing_key").inc()
        # Only a *presented but invalid* key is a security signal (guessing, leaked or
        # revoked credentials). A visitor who has not signed in yet is just noise.
        if key and _auth_failure_audit.hit(ip or "unknown"):
            anon = Principal(key_id="unauthenticated", name="unauthenticated", role=Role.VIEWER)
            detail = {"expired": "expired key", "network": f"key used from outside its networks ({ip})"}.get(
                why or "", "invalid or revoked key"
            )
            await audit(request, anon, "auth.failed", request.url.path, "denied",
                        {"reason": detail, "key_prefix": key[:10]})  # fmt: skip
        if key and (not _key_failures.hit(ip or "unknown") or _key_failures.remaining(ip or "unknown") <= 0):
            raise _key_lockout(ip or "unknown")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Valid API key required (Authorization: Bearer <key> or X-API-Key header)",
            headers={"WWW-Authenticate": "Bearer"},
        )
    request.state.auth_method = "api_key"
    _rate_limit(request, principal.key_id)
    return principal


def _rate_limit(request: Request, key_id: str) -> None:
    """Per-key request budget for API clients (browser sessions are not limited)."""
    limiter: SlidingWindowLimiter | None = getattr(request.app.state, "api_limiter", None)
    if limiter is None:
        return
    allowed = limiter.hit(key_id)
    reset = limiter.retry_after(key_id)
    request.state.rate_limit = (limiter.limit, limiter.remaining(key_id), reset)
    if not allowed:
        metrics.RATE_LIMITED.labels("api").inc()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded: {limiter.limit} requests per minute for this API key",
            headers={"Retry-After": str(reset), **rate_limit_headers(limiter.limit, 0, reset)},
        )


async def throttle(limiter: Any, key: str, message: str) -> None:
    """Refuse with 429 and Retry-After when ``key`` has used up ``limiter``."""
    if not await limiter.allow(key):
        from argus.observability import metrics

        metrics.RATE_LIMITED.labels(getattr(limiter, "name", None) or "endpoint").inc()
        wait = limiter.retry_after(key)
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=message,
                            headers={"Retry-After": str(wait)})  # fmt: skip


def cooldown(last_run_at: str | None, seconds: float, what: str) -> None:
    """Refuse a manual run that comes too soon after the last one (it spends third-party credits)."""
    if not last_run_at or seconds <= 0:
        return
    from datetime import datetime, timezone

    try:
        last = datetime.fromisoformat(last_run_at)
    except ValueError:
        return
    waited = (datetime.now(timezone.utc) - (last if last.tzinfo else last.replace(tzinfo=timezone.utc))).total_seconds()
    if waited < seconds:
        from argus.observability import metrics

        metrics.RATE_LIMITED.labels(f"{what.replace(' ', '_')}_cooldown").inc()
        wait = int(seconds - waited) + 1
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail=f"This {what} ran {int(waited // 60)} minute(s) ago; run it again in {wait // 60 + 1} minute(s)",
                            headers={"Retry-After": str(wait)})  # fmt: skip


def rate_limit_headers(limit: int, remaining: int, reset: int) -> dict[str, str]:
    return {"RateLimit-Limit": str(limit), "RateLimit-Remaining": str(max(0, remaining)), "RateLimit-Reset": str(reset)}


async def _owner_principal(request: Request, token: str) -> Principal | None:
    settings = request.app.state.settings
    repo = getattr(request.app.state, "owner", None)
    if repo is None or settings.edition == "personal":
        return None
    session = await repo.session(token, timedelta(minutes=settings.owner_idle_minutes))
    if session is None or session["stage"] != "full":
        return None
    if request.method in UNSAFE_METHODS and not _same_origin(request):
        metrics.AUTH_FAILURES.labels("csrf").inc()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-site request refused")
    request.state.auth_method = "owner"
    return OWNER_PRINCIPAL


async def _session_principal(request: Request, token: str) -> Principal:
    from datetime import timedelta

    idle_minutes = request.app.state.settings.session_idle_minutes
    user = await request.app.state.users.resolve_session(
        token, idle=timedelta(minutes=idle_minutes) if idle_minutes else None
    )
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


# ------------------------------------------------------------------------------ workspaces
WORKSPACE_HEADER = "x-argus-workspace"


@dataclass(frozen=True)
class WorkspaceContext:
    """Who is calling, in which workspace, with which role there. Every tenant-scoped endpoint gets one."""

    principal: Principal
    workspace: dict[str, Any]
    role: Role

    @property
    def id(self) -> str:
        return str(self.workspace["id"])


def _not_found() -> HTTPException:
    # 404, not 403: never confirm that a workspace (or anything in it) exists to outsiders.
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found")


async def resolve_workspace(request: Request, principal: Principal, ref: str | None = None) -> WorkspaceContext:
    """The workspace this request acts in: an explicit ``ref``, else the ``X-Argus-Workspace`` header,
    else the caller's natural workspace. Membership is checked here, once, for every endpoint."""
    repo: WorkspaceRepository = request.app.state.workspaces
    requested = ref or request.headers.get(WORKSPACE_HEADER) or request.query_params.get("workspace")
    if principal.workspace_id:  # API key bound to one workspace: that one, and only that one
        ws = await repo.get(principal.workspace_id)
        if ws is None or (requested and requested not in (ws["id"], ws["slug"])):
            raise _not_found()
        role = principal.role
    elif principal.platform_admin:
        ws = await repo.get(requested or DEFAULT_WORKSPACE_ID)
        if ws is None:
            raise _not_found()
        role = Role.ADMIN
    elif principal.user_id:
        memberships = await repo.list_for_user(principal.user_id)
        if requested:
            ws = next((m for m in memberships if requested in (m["id"], m["slug"])), None)
            if ws is None:
                raise _not_found()
        elif memberships:
            ws = next((m for m in memberships if m["default"]), memberships[0])
        else:
            raise HTTPException(status_code=403, detail="You are not a member of any workspace yet")
        role = Role(ws["role"])
    else:
        raise _not_found()
    if not principal.platform_admin:  # platform administrators can always reach a workspace to fix its policy
        networks = await request.app.state.access_policies.networks(ws["id"])
        if networks:
            from argus.storage.security_repo import allowed_from

            ip = client_ip(request)
            if not allowed_from(networks, ip):
                metrics.AUTH_FAILURES.labels("workspace_network").inc()
                await audit(request, principal, "auth.forbidden", request.url.path, "denied",
                            {"reason": f"workspace used from outside its networks ({ip})", "workspace": ws["id"]})  # fmt: skip
                raise _not_found()
    request.state.workspace_id = ws["id"]
    return WorkspaceContext(principal=principal, workspace=ws, role=role)


def in_workspace(min_role: Role):
    """Dependency factory: ``ws: WorkspaceContext = Depends(in_workspace(Role.ANALYST))``."""

    async def checker(request: Request, principal: Principal = Depends(get_principal)) -> WorkspaceContext:
        ctx = await resolve_workspace(request, principal)
        if ctx.role.rank < min_role.rank:
            metrics.AUTH_FAILURES.labels("insufficient_role").inc()
            await audit(
                request, principal, "auth.forbidden", request.url.path, "denied",
                {"required_role": min_role.value, "workspace_role": ctx.role.value},
            )  # fmt: skip
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Requires {min_role.value} role")
        return ctx

    checker.workspace_role = min_role  # type: ignore[attr-defined]  # read by the OpenAPI generator
    return checker


async def require_platform_admin(request: Request, principal: Principal = Depends(get_principal)) -> Principal:
    """Platform-wide administration (all workspaces, users, plugins, audit-chain verification)."""
    if not principal.platform_admin:
        metrics.AUTH_FAILURES.labels("insufficient_role").inc()
        await audit(request, principal, "auth.forbidden", request.url.path, "denied", {"required": "platform admin"})
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Requires a platform administrator")
    settings = request.app.state.settings
    if not settings.admin_keys_allowed and principal.key_id != OWNER_PRINCIPAL.key_id and settings.auth_enabled:
        await audit(request, principal, "auth.forbidden", request.url.path, "denied", {"required": "owner"})
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Only the owner can administer this server (owner console)")  # fmt: skip
    return principal


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


async def require_approval(
    request: Request, ws: WorkspaceContext, action: str, resource: str, summary: str
) -> str | None:
    """Let a protected action through only with a second administrator's approval (Phase 90).

    Returns the approval id spent, or None when the workspace does not protect ``action``. Without an
    approval it records a request and raises :class:`ApprovalRequired` (answered as 202)."""
    from argus.security.approvals import HEADER, ApprovalRefused, ApprovalRequired

    repo = request.app.state.approvals
    if not await repo.protects(ws.id, action):
        return None
    presented = (request.headers.get(HEADER) or "").strip()
    if presented:
        try:
            await repo.consume(presented, ws.id, action=action, resource=resource, key_id=ws.principal.key_id)
        except ApprovalRefused as exc:
            await audit(request, ws.principal, "approval.refused", presented, "denied",
                        {"action": action, "resource": resource, "reason": str(exc)})  # fmt: skip
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        await audit(request, ws.principal, "approval.used", presented, details={"action": action, "resource": resource})
        return presented
    reason = (request.headers.get("X-Argus-Reason") or "").strip()
    approval, new = await repo.request(ws.id, action=action, resource=resource, summary=summary, reason=reason,
                                       key_id=ws.principal.key_id, name=ws.principal.name)  # fmt: skip
    if new:
        await audit(request, ws.principal, "approval.request", approval["id"],
                    details={"action": action, "resource": resource, "summary": summary})  # fmt: skip
        try:
            await request.app.state.monitors.create_alert(
                monitor_id=None, investigation_id="", previous_investigation_id="", target=approval["label"],
                severity="medium", headline=f"Approval needed: {ws.principal.name} asks to {approval['label'].lower()}",
                summary={"approval_request": approval}, workspace_id=ws.id,
                public_url=request.app.state.settings.public_url,
            )  # fmt: skip
        except Exception:  # the request stands even if the notification fails
            logger.exception("Notifying the approval request %s failed", approval["id"])
    raise ApprovalRequired(
        approval,
        f"This needs a second administrator's approval: {approval['label']}. "
        f"Once approved, repeat the request with the header {HEADER}: {approval['id']}",
    )
