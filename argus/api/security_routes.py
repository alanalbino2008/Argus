"""Security endpoints: identity, WebSocket tickets, API-key management and the audit log."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from argus.api.deps import WorkspaceContext, audit, get_principal, in_workspace, require_platform_admin
from argus.security.auth import Principal, Role

router = APIRouter(prefix="/api", tags=["security"])


class CreateKeyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[\w .@-]+$")
    role: Role = Role.ANALYST
    # Platform keys administer every workspace (platform administrators only, admin role only).
    platform: bool = False


async def visible_workspaces(request: Request, principal: Principal) -> list[dict[str, Any]]:
    """Every workspace the caller can open, with their role in it."""
    repo = request.app.state.workspaces
    if principal.workspace_id:
        ws = await repo.get(principal.workspace_id)
        return [{**ws, "role": principal.role.value}] if ws else []
    if principal.platform_admin:
        return [{**ws, "role": Role.ADMIN.value} for ws in await repo.list_all()]
    if principal.user_id:
        return list(await repo.list_for_user(principal.user_id))
    return []


@router.get("/me")
async def whoami(request: Request, principal: Principal = Depends(get_principal)):
    """Identity, how the caller signed in, and the workspaces they can open."""
    return {
        "key_id": principal.key_id,
        "name": principal.name,
        "role": principal.role.value,
        "auth": getattr(request.state, "auth_method", "api_key"),
        "platform_admin": principal.platform_admin,
        "workspaces": await visible_workspaces(request, principal),
    }


@router.post("/ws-ticket")
async def issue_ws_ticket(request: Request, ws: WorkspaceContext = Depends(in_workspace(Role.VIEWER))):
    """Exchange the API key/session for a single-use, short-lived WebSocket ticket bound to this workspace."""
    tickets = request.app.state.ws_tickets
    return {"ticket": await tickets.issue(ws.principal, ws.id), "expires_in": tickets.ttl}


@router.get("/keys")
async def list_keys(
    request: Request,
    scope: str = Query("workspace", pattern="^(workspace|all)$"),
    ws: WorkspaceContext = Depends(in_workspace(Role.ADMIN)),
):
    """This workspace's keys; platform administrators may ask for every key (``scope=all``)."""
    every = scope == "all" and ws.principal.platform_admin
    return await request.app.state.keys.list(workspace_id=None if every else ws.id)


@router.post("/keys", status_code=201)
async def create_key(
    body: CreateKeyRequest, request: Request, ws: WorkspaceContext = Depends(in_workspace(Role.ADMIN))
):
    """Create an API key bound to this workspace. The plaintext key is returned once and never stored."""
    principal = ws.principal
    if body.platform and not (principal.platform_admin and body.role == Role.ADMIN):
        raise HTTPException(status_code=403, detail="Only platform administrators can create platform admin keys")
    workspace_id = None if body.platform else ws.id
    record, key = await request.app.state.keys.create(
        body.name, body.role, created_by=principal.name, workspace_id=workspace_id
    )
    await audit(
        request, principal, "key.create", record["id"],
        details={"name": body.name, "role": body.role.value, "platform": body.platform},
    )  # fmt: skip
    return {**record, "key": key, "warning": "Store this key now - it cannot be shown again."}


@router.delete("/keys/{key_id}", status_code=204)
async def revoke_key(key_id: str, request: Request, ws: WorkspaceContext = Depends(in_workspace(Role.ADMIN))):
    keys = request.app.state.keys
    record = await keys.get(key_id)
    platform = ws.principal.platform_admin
    if record is None or record["revoked"] or (not platform and record["workspace_id"] != ws.id):
        raise HTTPException(status_code=404, detail="Active key not found")
    if record["workspace_id"] is None and record["role"] == Role.ADMIN.value:
        others = [
            k for k in await keys.list() if k["workspace_id"] is None and k["role"] == "admin" and not k["revoked"]
        ]
        if len(others) <= 1 and not await request.app.state.users.has_platform_admin():
            raise HTTPException(status_code=409, detail="Refusing to revoke the last platform administrator")
    await keys.revoke(key_id, workspace_id=None if platform else ws.id)
    await audit(request, ws.principal, "key.revoke", key_id, details={"name": record["name"]})
    return Response(status_code=204)


@router.get("/audit")
async def list_audit_events(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    action: str | None = Query(None, max_length=64),
    actor_id: str | None = Query(None, max_length=64),
    scope: str | None = Query(None, pattern="^(workspace|all)$"),
    ws: WorkspaceContext = Depends(in_workspace(Role.ADMIN)),
):
    """Most recent audit events. Workspace admins see their workspace's; platform administrators see
    everything, including platform events such as sign-ins (``scope=workspace`` narrows it)."""
    every = ws.principal.platform_admin and scope != "workspace"
    return await request.app.state.audit.list(
        limit=limit, action=action, actor_id=actor_id, workspace_id=None if every else ws.id
    )


@router.get("/audit/verify")
async def verify_audit_chain(request: Request, _: Principal = Depends(require_platform_admin)):
    """Recompute the (platform-wide) audit hash chain to detect tampering."""
    return await request.app.state.audit.verify()
