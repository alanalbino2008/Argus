"""Workspace quotas: what is used and allowed, and setting a workspace's limits (Phase 100)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from argus.api.deps import WorkspaceContext, audit, in_workspace
from argus.security.auth import Role

router = APIRouter(prefix="/api", tags=["workspaces"])


class Limits(BaseModel):
    """None: the server's default; 0: no limit."""

    scans_per_day: int | None = Field(default=None, ge=0, le=100_000)
    evidence_mb: int | None = Field(default=None, ge=0, le=10_000_000)
    watches: int | None = Field(default=None, ge=0, le=100_000)
    api_keys: int | None = Field(default=None, ge=0, le=100_000)


@router.get("/quota")
async def workspace_quota(request: Request, ws: WorkspaceContext = Depends(in_workspace(Role.VIEWER))):
    """This workspace's usage and limits (a warning from 80% of a limit)."""
    return await request.app.state.quotas.usage(ws.id)


@router.put("/quota")
async def set_workspace_quota(body: Limits, request: Request, ws: WorkspaceContext = Depends(in_workspace(Role.ADMIN))):
    """Set this workspace's own limits (platform administrators)."""
    if not ws.principal.platform_admin:
        raise HTTPException(status_code=403, detail="Only platform administrators set a workspace's quotas")
    changes = body.model_dump()
    usage = await request.app.state.quotas.set_limits(ws.id, changes, ws.principal.name)
    await audit(request, ws.principal, "quota.set", ws.id, details=changes)
    return usage
