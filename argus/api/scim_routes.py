"""SCIM 2.0 endpoints for identity providers, and group-to-workspace roles for administrators (Phase 94).

See :mod:`argus.security.scim`. The identity provider authenticates with ``Authorization: Bearer
<ARGUS_SCIM_TOKEN>``; without that setting every ``/scim/v2`` path answers 404.
"""

from __future__ import annotations

import hmac
import json
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from argus.api.deps import audit, client_ip, public_base_url, require_platform_admin, throttle
from argus.security.auth import Principal, Role
from argus.security.ratelimit import SlidingWindowLimiter
from argus.security.scim import GROUP_SCHEMA, PATCH_SCHEMA, USER_SCHEMA, Scim, ScimError

router = APIRouter(tags=["scim"])
SCIM_PRINCIPAL = Principal(key_id="scim", name="identity provider (SCIM)", role=Role.ADMIN)
MEDIA = "application/scim+json"
_limiter = SlidingWindowLimiter(limit=600, window=60, name="scim")  # a full sync of a large directory, not a flood


def _reply(body: Any, status: int = 200) -> Response:
    return Response(json.dumps(body), status_code=status, media_type=MEDIA)


async def _scim(request: Request) -> Scim:
    token = request.app.state.settings.scim_token
    if token is None or not token.get_secret_value():
        raise HTTPException(status_code=404, detail="Not found")
    presented = (request.headers.get("authorization") or "").removeprefix("Bearer ").strip()
    if not hmac.compare_digest(presented.encode(), token.get_secret_value().encode()):
        await audit(request, Principal(key_id="unauthenticated", name="unauthenticated", role=Role.VIEWER),
                    "scim.auth_failed", request.url.path, "denied", {"ip": client_ip(request)})  # fmt: skip
        raise HTTPException(status_code=401, detail="Invalid SCIM token", headers={"WWW-Authenticate": "Bearer"})
    await throttle(_limiter, "scim", "Too many SCIM requests; slow down")
    return Scim(request.app.state.db, public_base_url(request))


SCIM = Depends(_scim)


async def _body(request: Request) -> dict[str, Any]:
    try:
        body = json.loads(await request.body() or b"{}")
    except ValueError as exc:
        raise ScimError(400, "The body is not JSON", "invalidSyntax") from exc
    if not isinstance(body, dict):
        raise ScimError(400, "The body must be a JSON object", "invalidSyntax")
    return body


async def _audit_in(request: Request, principal: Principal, action: str, resource: str, workspace_id: str,
                    details: dict[str, Any]) -> None:  # fmt: skip
    """An audit entry in a given workspace (SCIM requests themselves belong to no workspace)."""
    await request.app.state.audit.record(principal, action, resource, "success", client_ip(request), details,
                                         workspace_id)  # fmt: skip


async def _sync(request: Request, scim: Scim, users: set[str]) -> None:
    for change in await scim.sync(users):
        await _audit_in(request, SCIM_PRINCIPAL, "scim.membership", change["user"], change["workspace"], change)


def _error(exc: ScimError) -> Response:
    return _reply(exc.body(), exc.status)


# ---------------------------------------------------------------------------- discovery
@router.get("/scim/v2/ServiceProviderConfig")
async def scim_service_provider_config(_: Scim = SCIM):
    return _reply({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": True}, "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 1000}, "changePassword": {"supported": False},
        "sort": {"supported": False}, "etag": {"supported": False},
        "authenticationSchemes": [{"type": "oauthbearertoken", "name": "Bearer token", "primary": True,
                                   "description": "ARGUS_SCIM_TOKEN"}],
    })  # fmt: skip


@router.get("/scim/v2/ResourceTypes")
async def scim_resource_types(_: Scim = SCIM):
    types = [{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": name, "name": name,
              "endpoint": f"/{name}s", "schema": schema} for name, schema in (("User", USER_SCHEMA), ("Group", GROUP_SCHEMA))]  # fmt: skip
    return _reply(Scim.page(types, 1, len(types)))


@router.get("/scim/v2/Schemas")
async def scim_schemas(_: Scim = SCIM):
    schemas = [{"id": USER_SCHEMA, "name": "User"}, {"id": GROUP_SCHEMA, "name": "Group"}]
    return _reply(Scim.page(schemas, 1, len(schemas)))


# ---------------------------------------------------------------------------- users
@router.get("/scim/v2/Users")
async def scim_list_users(scim: Scim = SCIM, filter: str | None = None, startIndex: int = 1, count: int = 100):
    try:
        return _reply(Scim.page(await scim.list_users(filter), startIndex, min(count, 1000)))
    except ScimError as exc:
        return _error(exc)


@router.get("/scim/v2/Users/{user_id}")
async def scim_get_user(user_id: str, scim: Scim = SCIM):
    try:
        return _reply(await scim.get_user(user_id))
    except ScimError as exc:
        return _error(exc)


@router.post("/scim/v2/Users")
async def scim_create_user(request: Request, scim: Scim = SCIM):
    try:
        user = await scim.create_user(await _body(request))
    except ScimError as exc:
        return _error(exc)
    await audit(request, SCIM_PRINCIPAL, "scim.user_create", user["id"],
                details={"userName": user["userName"], "active": user["active"]})  # fmt: skip
    return _reply(user, 201)


async def _changed_user(request: Request, scim: Scim, user: dict[str, Any], action: str) -> Response:
    ended = user.pop("_sessions_ended", 0)
    await audit(request, SCIM_PRINCIPAL, action, user["id"],
                details={"userName": user["userName"], "active": user["active"], "sessions_ended": ended})  # fmt: skip
    await _sync(request, scim, {user["id"]})
    return _reply(user)


@router.put("/scim/v2/Users/{user_id}")
async def scim_replace_user(user_id: str, request: Request, scim: Scim = SCIM):
    try:
        user = await scim.replace_user(user_id, await _body(request))
    except ScimError as exc:
        return _error(exc)
    return await _changed_user(request, scim, user, "scim.user_update")


@router.patch("/scim/v2/Users/{user_id}")
async def scim_patch_user(user_id: str, request: Request, scim: Scim = SCIM):
    try:
        body = await _body(request)
        if PATCH_SCHEMA not in (body.get("schemas") or [PATCH_SCHEMA]):
            raise ScimError(400, "Expected a PatchOp", "invalidSyntax")
        user = await scim.patch_user(user_id, list(body.get("Operations") or []))
    except ScimError as exc:
        return _error(exc)
    return await _changed_user(request, scim, user, "scim.user_update")


@router.delete("/scim/v2/Users/{user_id}", status_code=204)
async def scim_delete_user(user_id: str, request: Request, scim: Scim = SCIM):
    """Deprovisioning: the user is disabled and signed out everywhere (their history stays for the audit)."""
    try:
        ended = await scim.deactivate_user(user_id)
    except ScimError as exc:
        return _error(exc)
    await audit(request, SCIM_PRINCIPAL, "scim.user_deactivate", user_id, details={"sessions_ended": ended})
    await _sync(request, scim, {user_id})
    return Response(status_code=204)


# ---------------------------------------------------------------------------- groups
@router.get("/scim/v2/Groups")
async def scim_list_groups(scim: Scim = SCIM, filter: str | None = None, startIndex: int = 1, count: int = 100):
    try:
        return _reply(Scim.page(await scim.list_groups(filter), startIndex, min(count, 1000)))
    except ScimError as exc:
        return _error(exc)


@router.get("/scim/v2/Groups/{group_id}")
async def scim_get_group(group_id: str, scim: Scim = SCIM):
    try:
        return _reply(await scim.get_group(group_id))
    except ScimError as exc:
        return _error(exc)


@router.post("/scim/v2/Groups")
async def scim_create_group(request: Request, scim: Scim = SCIM):
    try:
        group, members = await scim.create_group(await _body(request))
    except ScimError as exc:
        return _error(exc)
    await audit(request, SCIM_PRINCIPAL, "scim.group_create", group["id"],
                details={"displayName": group["displayName"], "members": len(members)})  # fmt: skip
    await _sync(request, scim, members)
    return _reply(group, 201)


async def _changed_group(request: Request, scim: Scim, group: dict[str, Any], touched: set[str]) -> Response:
    await audit(request, SCIM_PRINCIPAL, "scim.group_update", group["id"],
                details={"displayName": group["displayName"], "members": len(group["members"])})  # fmt: skip
    await _sync(request, scim, touched)
    return _reply(group)


@router.put("/scim/v2/Groups/{group_id}")
async def scim_replace_group(group_id: str, request: Request, scim: Scim = SCIM):
    try:
        group, touched = await scim.replace_group(group_id, await _body(request))
    except ScimError as exc:
        return _error(exc)
    return await _changed_group(request, scim, group, touched)


@router.patch("/scim/v2/Groups/{group_id}")
async def scim_patch_group(group_id: str, request: Request, scim: Scim = SCIM):
    try:
        body = await _body(request)
        group, touched = await scim.patch_group(group_id, list(body.get("Operations") or []))
    except ScimError as exc:
        return _error(exc)
    return await _changed_group(request, scim, group, touched)


@router.delete("/scim/v2/Groups/{group_id}", status_code=204)
async def scim_delete_group(group_id: str, request: Request, scim: Scim = SCIM):
    try:
        members = await scim.delete_group(group_id)
    except ScimError as exc:
        return _error(exc)
    await audit(request, SCIM_PRINCIPAL, "scim.group_delete", group_id)
    await _sync(request, scim, members)
    return Response(status_code=204)


# ---------------------------------------------------------------------------- administrators
class GroupRole(BaseModel):
    group: str = Field(min_length=1, max_length=255, description="The identity provider's group name")
    workspace_id: str = Field(min_length=1, max_length=32)
    role: Literal["viewer", "analyst", "admin"] | None = Field(description="None removes the mapping")


@router.get("/api/scim/group-roles")
async def list_group_roles(request: Request, _: Principal = Depends(require_platform_admin)):
    """Which identity-provider groups give which workspace roles, and whether SCIM is switched on."""
    token = request.app.state.settings.scim_token
    return {"enabled": bool(token and token.get_secret_value()), "endpoint": f"{public_base_url(request)}/scim/v2",
            "mappings": await Scim(request.app.state.db).group_roles()}  # fmt: skip


@router.put("/api/scim/group-roles")
async def set_group_role(body: GroupRole, request: Request, admin: Principal = Depends(require_platform_admin)):
    """Members of ``group`` get ``role`` in the workspace (or, with role null, lose what it gave them)."""
    if await request.app.state.workspaces.get(body.workspace_id) is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    scim = Scim(request.app.state.db)
    members = await scim.set_group_role(body.group, body.workspace_id, body.role, admin.name)
    await _audit_in(
        request,
        admin,
        "scim.group_role",
        body.group.strip().lower(),
        body.workspace_id,
        {"workspace": body.workspace_id, "role": body.role},
    )
    await _sync(request, scim, members)
    return await list_group_roles(request, admin)


def register_errors(app: Any) -> None:
    """SCIM clients expect SCIM error bodies, also for errors raised outside the handlers."""

    @app.exception_handler(ScimError)
    async def _scim_error(_request: Request, exc: ScimError) -> JSONResponse:
        return JSONResponse(exc.body(), status_code=exc.status, media_type=MEDIA)
