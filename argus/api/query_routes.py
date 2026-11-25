"""Saved queries and hunts: Argus Query Language across a workspace's investigations."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from argus.api.deps import WorkspaceContext, audit, in_workspace
from argus.intel import hunt as hunting
from argus.intel.query import QueryError
from argus.security.auth import Role
from argus.security.ratelimit import SlidingWindowLimiter
from argus.storage.saved_query_repo import MAX_SAVED_QUERIES

router = APIRouter(prefix="/api", tags=["query"])
VIEWER = Depends(in_workspace(Role.VIEWER))
ANALYST = Depends(in_workspace(Role.ANALYST))
_hunt_limiter = SlidingWindowLimiter(limit=20, window=60, name="hunt")  # hunts load many graphs: keep them occasional

Severity = Literal["low", "medium", "high", "critical"]


class SavedQueryRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120, examples=["Exploited CVEs"])
    query: str = Field(min_length=1, max_length=2000, examples=["type:vulnerability intel.kev:*"])
    description: str = Field(default="", max_length=1000)
    alert: bool = Field(default=False, description="Check after every scan and alert on new matches")
    severity: Severity = "medium"


class SavedQueryUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    query: str | None = Field(default=None, min_length=1, max_length=2000)
    description: str | None = Field(default=None, max_length=1000)
    alert: bool | None = None
    severity: Severity | None = None


class HuntRequest(BaseModel):
    query: str = Field(min_length=1, max_length=2000, examples=["category:favicon"])
    investigations: int = Field(default=hunting.DEFAULT_HUNT_INVESTIGATIONS, ge=1, le=hunting.MAX_HUNT_INVESTIGATIONS)
    include_running: bool = Field(default=False, description="Also search scans that have not finished")


def _repo(request: Request) -> Any:
    return request.app.state.saved_queries


def _check(text: str) -> None:
    try:
        hunting.validate(text)
    except QueryError as exc:
        raise HTTPException(status_code=400, detail={"message": str(exc), "position": exc.position}) from exc


@router.get("/saved-queries")
async def list_saved_queries(request: Request, ws: WorkspaceContext = VIEWER):
    """The workspace's saved queries (shared by the team)."""
    return await _repo(request).list(ws.id)


@router.post("/saved-queries", status_code=201)
async def create_saved_query(body: SavedQueryRequest, request: Request, ws: WorkspaceContext = ANALYST):
    """Save a query. With ``alert``, it runs after every completed scan and alerts on new matches."""
    _check(body.query)
    if await _repo(request).count(ws.id) >= MAX_SAVED_QUERIES:
        raise HTTPException(status_code=422, detail=f"A workspace can save up to {MAX_SAVED_QUERIES} queries")
    saved = await _repo(request).create(
        workspace_id=ws.id, name=body.name.strip(), query=body.query.strip(), description=body.description.strip(),
        alert=body.alert, severity=body.severity, by=ws.principal.name,
    )  # fmt: skip
    await audit(request, ws.principal, "saved_query.create", saved["id"], details={"alert": body.alert})
    return saved


@router.patch("/saved-queries/{query_id}")
async def update_saved_query(query_id: str, body: SavedQueryUpdate, request: Request, ws: WorkspaceContext = ANALYST):
    if body.query is not None:
        _check(body.query)
    changes = body.model_dump(exclude_none=True)
    for key in ("name", "query", "description"):
        if key in changes:
            changes[key] = changes[key].strip()
    saved = await _repo(request).update(query_id, ws.id, **changes)
    if saved is None:
        raise HTTPException(status_code=404, detail="Saved query not found")
    await audit(request, ws.principal, "saved_query.update", query_id, details={"fields": sorted(changes)})
    return saved


@router.delete("/saved-queries/{query_id}", status_code=204)
async def delete_saved_query(query_id: str, request: Request, ws: WorkspaceContext = ANALYST):
    if not await _repo(request).delete(query_id, ws.id):
        raise HTTPException(status_code=404, detail="Saved query not found")
    await audit(request, ws.principal, "saved_query.delete", query_id)
    return Response(status_code=204)


@router.post("/hunt")
async def hunt(body: HuntRequest, request: Request, ws: WorkspaceContext = VIEWER):
    """Run one query across the workspace's most recent investigations (newest first).

    Bounded by ``investigations`` (at most 200) and a 25-second budget; ``partial`` says when the
    budget ran out first.
    """
    if not await _hunt_limiter.allow(f"{ws.id}:{ws.principal.key_id}"):
        raise HTTPException(status_code=429, detail="Too many hunts: try again in a minute")
    try:
        result = await hunting.hunt(
            request.app.state.repo, ws.id, body.query, investigations=body.investigations,
            include_running=body.include_running, annotations=await request.app.state.annotations.all(ws.id),
        )  # fmt: skip
    except QueryError as exc:
        raise HTTPException(status_code=400, detail={"message": str(exc), "position": exc.position}) from exc
    await audit(
        request, ws.principal, "hunt.run", None,
        details={"investigations": result["investigations_searched"], "matched": result["investigations_matched"]},
    )  # fmt: skip
    return result


@router.post("/saved-queries/{query_id}/hunt")
async def hunt_saved(query_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Hunt with a saved query (over the 25 most recent completed investigations)."""
    saved = await _repo(request).get(query_id, ws.id)
    if saved is None:
        raise HTTPException(status_code=404, detail="Saved query not found")
    return await hunt(HuntRequest(query=saved["query"]), request, ws)
