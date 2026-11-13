"""Security endpoints: identity, WebSocket tickets, API-key management and the audit log."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from argus.api.deps import audit, get_principal, require
from argus.security.auth import Principal, Role

router = APIRouter(prefix="/api", tags=["security"])


class CreateKeyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[\w .@-]+$")
    role: Role = Role.ANALYST


@router.get("/me")
async def whoami(principal: Principal = Depends(get_principal)):
    """Identity and role of the current API key."""
    return {"key_id": principal.key_id, "name": principal.name, "role": principal.role.value}


@router.post("/ws-ticket")
async def issue_ws_ticket(request: Request, principal: Principal = Depends(require(Role.VIEWER))):
    """Exchange the API key for a single-use, short-lived WebSocket ticket."""
    tickets = request.app.state.ws_tickets
    return {"ticket": tickets.issue(principal), "expires_in": tickets.ttl}


@router.get("/keys")
async def list_keys(request: Request, _: Principal = Depends(require(Role.ADMIN))):
    return await request.app.state.keys.list()


@router.post("/keys", status_code=201)
async def create_key(body: CreateKeyRequest, request: Request, principal: Principal = Depends(require(Role.ADMIN))):
    """Create an API key. The plaintext key is returned once and never stored."""
    record, key = await request.app.state.keys.create(body.name, body.role, created_by=principal.name)
    await audit(request, principal, "key.create", record["id"], details={"name": body.name, "role": body.role.value})
    return {**record, "key": key, "warning": "Store this key now - it cannot be shown again."}


@router.delete("/keys/{key_id}", status_code=204)
async def revoke_key(key_id: str, request: Request, principal: Principal = Depends(require(Role.ADMIN))):
    keys = request.app.state.keys
    record = await keys.get(key_id)
    if record is None or record["revoked"]:
        raise HTTPException(status_code=404, detail="Active key not found")
    if record["role"] == Role.ADMIN.value and await keys.count_active(Role.ADMIN) <= 1:
        raise HTTPException(status_code=409, detail="Refusing to revoke the last active admin key")
    await keys.revoke(key_id)
    await audit(request, principal, "key.revoke", key_id, details={"name": record["name"]})
    return Response(status_code=204)


@router.get("/audit")
async def list_audit_events(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    action: str | None = Query(None, max_length=64),
    actor_id: str | None = Query(None, max_length=64),
    _: Principal = Depends(require(Role.ADMIN)),
):
    """Most recent audit events first."""
    return await request.app.state.audit.list(limit=limit, action=action, actor_id=actor_id)


@router.get("/audit/verify")
async def verify_audit_chain(request: Request, _: Principal = Depends(require(Role.ADMIN))):
    """Recompute the audit hash chain to detect tampering."""
    return await request.app.state.audit.verify()
