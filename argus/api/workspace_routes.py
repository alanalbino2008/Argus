"""Workspaces (teams): listing, creation and membership.

Platform administrators create and delete workspaces; a workspace's own admins manage
its members. Every lookup goes through ``resolve_workspace`` - outsiders get 404.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from argus.api.deps import WorkspaceContext, audit, get_principal, require_platform_admin, resolve_workspace
from argus.api.security_routes import visible_workspaces
from argus.security.auth import Principal, Role
from argus.storage.workspace_repo import WorkspaceError, WorkspaceRepository

router = APIRouter(prefix="/api/workspaces", tags=["workspaces"])
NAME = Field(min_length=2, max_length=128, pattern=r"^[\w .&'()-]+$")


class WorkspaceBody(BaseModel):
    name: str = NAME


class AddMemberBody(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    role: Role = Role.ANALYST


class MemberRoleBody(BaseModel):
    role: Role


async def _admin_of(request: Request, principal: Principal, ref: str) -> WorkspaceContext:
    ctx = await resolve_workspace(request, principal, ref)
    if ctx.role != Role.ADMIN:
        raise HTTPException(status_code=403, detail="Requires admin role in this workspace")
    return ctx


def _repo(request: Request) -> WorkspaceRepository:
    return request.app.state.workspaces


@router.get("")
async def list_workspaces(request: Request, principal: Principal = Depends(get_principal)):
    """Workspaces the caller can open, with their role in each."""
    return await visible_workspaces(request, principal)


@router.post("", status_code=201)
async def create_workspace(
    body: WorkspaceBody, request: Request, principal: Principal = Depends(require_platform_admin)
):
    ws = await _repo(request).create(body.name, created_by=principal.name)
    if principal.user_id:  # the creator can see what they made
        await _repo(request).set_member(ws["id"], principal.user_id, Role.ADMIN.value, principal.name)
    request.state.workspace_id = ws["id"]
    await audit(request, principal, "workspace.create", ws["id"], details={"name": ws["name"]})
    return ws


@router.patch("/{ref}")
async def rename_workspace(
    ref: str, body: WorkspaceBody, request: Request, principal: Principal = Depends(get_principal)
):
    ctx = await _admin_of(request, principal, ref)
    ws = await _repo(request).rename(ctx.id, body.name)
    await audit(request, principal, "workspace.rename", ctx.id, details={"name": body.name})
    return ws


@router.delete("/{ref}", status_code=204)
async def delete_workspace(ref: str, request: Request, principal: Principal = Depends(require_platform_admin)):
    ctx = await resolve_workspace(request, principal, ref)
    try:
        await _repo(request).delete(ctx.id)
    except WorkspaceError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await audit(request, principal, "workspace.delete", ctx.id, details={"name": ctx.workspace["name"]})
    return Response(status_code=204)


@router.get("/{ref}/members")
async def list_members(ref: str, request: Request, principal: Principal = Depends(get_principal)):
    ctx = await _admin_of(request, principal, ref)
    return await _repo(request).members(ctx.id)


@router.post("/{ref}/members", status_code=201)
async def add_member(ref: str, body: AddMemberBody, request: Request, principal: Principal = Depends(get_principal)):
    """Add someone who has signed in at least once (their account is created by single sign-on)."""
    ctx = await _admin_of(request, principal, ref)
    user = await request.app.state.users.find_by_email(body.email.strip().lower())
    if user is None:
        raise HTTPException(status_code=404, detail="No user with that email has signed in yet")
    await _repo(request).set_member(ctx.id, user["id"], body.role.value, principal.name)
    await audit(request, principal, "workspace.member_add", user["id"], details={"role": body.role.value})
    return {"user_id": user["id"], "email": user["email"], "role": body.role.value}


@router.put("/{ref}/members/{user_id}")
async def set_member_role(
    ref: str, user_id: str, body: MemberRoleBody, request: Request, principal: Principal = Depends(get_principal)
):
    ctx = await _admin_of(request, principal, ref)
    if principal.user_id == user_id and body.role != Role.ADMIN and not principal.platform_admin:
        raise HTTPException(status_code=409, detail="You cannot demote yourself")
    if await _repo(request).role_of(ctx.id, user_id) is None:
        raise HTTPException(status_code=404, detail="Not a member of this workspace")
    await _repo(request).set_member(ctx.id, user_id, body.role.value, principal.name)
    await audit(request, principal, "workspace.member_role", user_id, details={"role": body.role.value})
    return {"user_id": user_id, "role": body.role.value}


@router.delete("/{ref}/members/{user_id}", status_code=204)
async def remove_member(ref: str, user_id: str, request: Request, principal: Principal = Depends(get_principal)):
    ctx = await _admin_of(request, principal, ref)
    if principal.user_id == user_id and not principal.platform_admin:
        raise HTTPException(status_code=409, detail="You cannot remove yourself")
    if not await _repo(request).remove_member(ctx.id, user_id):
        raise HTTPException(status_code=404, detail="Not a member of this workspace")
    await audit(request, principal, "workspace.member_remove", user_id)
    return Response(status_code=204)
