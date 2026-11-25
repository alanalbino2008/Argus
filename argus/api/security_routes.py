"""Security endpoints: identity, WebSocket tickets, API-key management and the audit log."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
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
    expires_in_days: int | None = Field(default=None, ge=1, le=3650, description="None: never (if policy allows)")
    allowed_networks: list[str] = Field(default_factory=list, max_length=20,
                                        description="CIDRs the key may be used from; empty: anywhere")  # fmt: skip


class KeyNetworks(BaseModel):
    allowed_networks: list[str] = Field(max_length=20)


class RotateKey(BaseModel):
    overlap_hours: int = Field(default=24, ge=0, le=168, description="How long the old key keeps working")


def _networks(values: list[str]) -> list[str]:
    from argus.storage.security_repo import clean_networks

    try:
        return clean_networks(values)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid network: {exc}") from exc


def _expiry(request: Request, days: int | None) -> datetime | None:
    """The new key's expiry, enforcing ARGUS_API_KEY_MAX_LIFETIME_DAYS."""
    limit = request.app.state.settings.api_key_max_lifetime_days
    if days is None and limit:
        days = limit
    if days is not None and limit and days > limit:
        raise HTTPException(status_code=422, detail=f"Keys may live at most {limit} days on this server")
    return datetime.now(timezone.utc) + timedelta(days=days) if days else None


async def _own_key(request: Request, ws: WorkspaceContext, key_id: str) -> dict[str, Any]:
    record = await request.app.state.keys.get(key_id)
    if record is None or record["revoked"] or (not ws.principal.platform_admin and record["workspace_id"] != ws.id):
        raise HTTPException(status_code=404, detail="Active key not found")
    return record


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
        body.name, body.role, created_by=principal.name, workspace_id=workspace_id,
        expires_at=_expiry(request, body.expires_in_days), allowed_networks=_networks(body.allowed_networks),
    )  # fmt: skip
    await audit(
        request, principal, "key.create", record["id"],
        details={"name": body.name, "role": body.role.value, "platform": body.platform,
                 "expires_at": record["expires_at"], "allowed_networks": record["allowed_networks"]},
    )  # fmt: skip
    return {**record, "key": key, "warning": "Store this key now - it cannot be shown again."}


@router.get("/keys/report")
async def key_report(request: Request, ws: WorkspaceContext = Depends(in_workspace(Role.ADMIN))):
    """Keys that need attention: expiring soon, unused for 90 days, or usable from anywhere."""
    warn = request.app.state.settings.api_key_expiry_warning_days
    keys = [k for k in await request.app.state.keys.list(workspace_id=ws.id) if not k["revoked"] and not k["expired"]]
    return {
        "expiring": [k for k in keys if k["expires_in_days"] is not None and k["expires_in_days"] <= warn],
        "stale": [k for k in keys if k["stale"]],
        "never_expire": [k for k in keys if k["expires_at"] is None],
        "unrestricted": [k for k in keys if not k["allowed_networks"]],
        "active": len(keys),
    }


@router.patch("/keys/{key_id}")
async def set_key_networks(
    key_id: str, body: KeyNetworks, request: Request, ws: WorkspaceContext = Depends(in_workspace(Role.ADMIN))
):
    """Change where a key may be used from (an empty list: anywhere). Takes effect on its next request."""
    record = await _own_key(request, ws, key_id)
    networks = _networks(body.allowed_networks)
    await request.app.state.keys.set_networks(key_id, networks)
    await audit(request, ws.principal, "key.networks", key_id,
                details={"name": record["name"], "before": record["allowed_networks"], "after": networks})  # fmt: skip
    return await request.app.state.keys.get(key_id)


@router.post("/keys/{key_id}/rotate", status_code=201)
async def rotate_key(
    key_id: str, body: RotateKey, request: Request, ws: WorkspaceContext = Depends(in_workspace(Role.ADMIN))
):
    """Replace a key: a new key with the same name, role, networks and lifetime; the old one keeps
    working for ``overlap_hours`` so integrations can switch without downtime, then expires."""
    record = await _own_key(request, ws, key_id)
    if record["workspace_id"] is None and not ws.principal.platform_admin:
        raise HTTPException(status_code=403, detail="Only platform administrators can rotate platform keys")
    rotated = await request.app.state.keys.rotate(key_id, overlap=timedelta(hours=body.overlap_hours),
                                                  by=ws.principal.name)  # fmt: skip
    if rotated is None:
        raise HTTPException(status_code=409, detail="This key was already rotated or has expired")
    new, key = rotated
    await audit(request, ws.principal, "key.rotate", key_id,
                details={"name": record["name"], "new_key": new["id"], "overlap_hours": body.overlap_hours})  # fmt: skip
    return {**new, "key": key, "old_key_expires_at": (await request.app.state.keys.get(key_id) or {}).get("expires_at"),
            "warning": "Store this key now - it cannot be shown again."}  # fmt: skip


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
