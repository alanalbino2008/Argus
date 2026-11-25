"""Browser sessions and workspace network policy (Phase 93).

People see where they are signed in and can end any session; platform administrators can sign a
person out everywhere; a workspace can be limited to its organisation's networks.
See :mod:`argus.security.access_policy`.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from argus.api.deps import WorkspaceContext, audit, client_ip, get_principal, in_workspace, require_platform_admin
from argus.security.auth import Principal, Role
from argus.storage.security_repo import allowed_from, clean_networks

router = APIRouter(prefix="/api", tags=["security"])


class NetworkPolicy(BaseModel):
    allowed_networks: list[str] = Field(max_length=20)


def _signed_in(request: Request, principal: Principal) -> tuple[str, str]:
    """The caller's user id and current session id (sessions belong to people, not API keys)."""
    user = getattr(request.state, "user", None)
    if not principal.user_id or not user:
        raise HTTPException(status_code=400, detail="Sessions belong to people who signed in; API keys have none")
    return principal.user_id, user.get("session_id", "")


@router.get("/auth/sessions")
async def my_sessions(request: Request, principal: Principal = Depends(get_principal)):
    """Where you are signed in. ``current`` marks this browser."""
    user_id, current = _signed_in(request, principal)
    return [{**s, "current": s["id"] == current} for s in await request.app.state.users.sessions(user_id)]


@router.delete("/auth/sessions/{session_id}", status_code=204)
async def end_my_session(session_id: str, request: Request, principal: Principal = Depends(get_principal)):
    user_id, _current = _signed_in(request, principal)
    if len(session_id) < 16 or not session_id.isalnum():
        raise HTTPException(status_code=404, detail="Session not found")
    if not await request.app.state.users.end_sessions(user_id, only=session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    await audit(request, principal, "session.end", session_id)
    return Response(status_code=204)


@router.post("/auth/sessions/end-others")
async def end_my_other_sessions(request: Request, principal: Principal = Depends(get_principal)):
    """Sign out everywhere except this browser (after a lost laptop, or just to be sure)."""
    user_id, current = _signed_in(request, principal)
    ended = await request.app.state.users.end_sessions(user_id, keep=current)
    await audit(request, principal, "session.end_others", user_id, details={"ended": ended})
    return {"ended": ended}


@router.post("/users/{user_id}/sign-out")
async def sign_user_out(user_id: str, request: Request, admin: Principal = Depends(require_platform_admin)):
    """End every session of a person at once (they can sign in again unless disabled)."""
    ended = await request.app.state.users.end_sessions(user_id)
    await audit(request, admin, "session.sign_out_user", user_id, details={"ended": ended})
    return {"ended": ended}


@router.get("/access-policy")
async def get_access_policy(request: Request, ws: WorkspaceContext = Depends(in_workspace(Role.ADMIN))):
    """The networks this workspace may be used from (empty: anywhere), and the caller's address."""
    return {**await request.app.state.access_policies.get(ws.id), "your_address": client_ip(request)}


@router.put("/access-policy")
async def set_access_policy(
    body: NetworkPolicy, request: Request, ws: WorkspaceContext = Depends(in_workspace(Role.ADMIN))
):
    """Limit the workspace to these networks (empty: anywhere). A policy that would shut out the
    administrator setting it is refused."""
    try:
        networks = clean_networks(body.allowed_networks)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid network: {exc}") from exc
    ip = client_ip(request)
    if networks and not ws.principal.platform_admin and not allowed_from(networks, ip):
        raise HTTPException(status_code=422,
                            detail=f"This would lock you out: your address ({ip}) is not in these networks")  # fmt: skip
    before = await request.app.state.access_policies.get(ws.id)
    policy = await request.app.state.access_policies.set(ws.id, networks, by=ws.principal.name)
    await audit(request, ws.principal, "access.policy", ws.id,
                details={"before": before["allowed_networks"], "after": networks})  # fmt: skip
    return policy
