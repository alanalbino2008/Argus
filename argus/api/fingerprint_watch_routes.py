"""Fingerprint watches: a fingerprint's Shodan or Censys search, re-run on a schedule.

Watch a favicon, JARM, HASSH or certificate from any investigation; Argus re-runs that entity's
own search every day or week and alerts when new servers start sharing it.
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from argus.api.deps import WorkspaceContext, audit, cooldown, in_workspace
from argus.intel.fingerprint_watch import ENGINE_NAMES, engine_keys
from argus.security.auth import Role
from argus.storage.fingerprint_watch_repo import MAX_WATCHES

router = APIRouter(prefix="/api", tags=["monitoring"])
VIEWER = Depends(in_workspace(Role.VIEWER))
ANALYST = Depends(in_workspace(Role.ANALYST))


class WatchRequest(BaseModel):
    investigation_id: str = Field(min_length=1, max_length=64)
    entity_id: str = Field(min_length=1, max_length=64, description="A fingerprint or certificate entity")
    engine: Literal["shodan", "censys"] = "shodan"
    interval_hours: Literal[24, 168] = Field(default=24, description="Every day (24) or every week (168)")
    severity: Literal["low", "medium", "high", "critical"] = "high"


def _repo(request: Request) -> Any:
    return request.app.state.fingerprint_watches


@router.get("/fingerprint-watches")
async def list_fingerprint_watches(request: Request, ws: WorkspaceContext = VIEWER):
    """The workspace's fingerprint watches, newest first."""
    return await _repo(request).list_watches(ws.id)


@router.post("/fingerprint-watches", status_code=201)
async def create_fingerprint_watch(body: WatchRequest, request: Request, ws: WorkspaceContext = ANALYST):
    """Watch an entity's fingerprint. The first run (straight away) records today's servers."""
    repo = request.app.state.repo
    inv = await repo.get_investigation(body.investigation_id)
    if inv is None or inv.workspace_id != ws.id:
        raise HTTPException(status_code=404, detail="Investigation not found")
    graph = await repo.load_graph(body.investigation_id, shared=True)
    entity = graph.get_entity(body.entity_id) if graph else None
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found in this investigation")
    name = ENGINE_NAMES[body.engine]
    query = str((entity.metadata.get("search_queries") or {}).get(body.engine) or "")
    if not query:
        raise HTTPException(status_code=422, detail=f"This entity has no {name} search")
    if not engine_keys(request.app.state.settings)[body.engine]:
        setting = "ARGUS_SHODAN_API_KEY" if body.engine == "shodan" else "ARGUS_CENSYS_API_TOKEN"
        raise HTTPException(status_code=409, detail=f"Watching needs a {name} key ({setting})")
    if await _repo(request).find(ws.id, body.engine, entity.id):
        raise HTTPException(status_code=409, detail=f"This fingerprint is already watched on {name}")
    if await _repo(request).count(ws.id) >= MAX_WATCHES:
        raise HTTPException(status_code=422, detail=f"A workspace can watch up to {MAX_WATCHES} fingerprints")
    await request.app.state.quotas.check(ws.id, "watches")
    kind = str(entity.metadata.get("category") or entity.type.value).replace("_", " ")
    label = (entity.label if kind.lower() in entity.label.lower() else f"{kind} {entity.label}")[:200]
    watch = await _repo(request).create(
        workspace_id=ws.id, engine=body.engine, entity_id=entity.id, investigation_id=body.investigation_id,
        label=label, query=query, interval_hours=body.interval_hours, severity=body.severity, by=ws.principal.name,
    )  # fmt: skip
    await audit(request, ws.principal, "fingerprint_watch.create", watch["id"], details={"engine": body.engine})
    request.app.state.fingerprint_watcher.kick()
    return watch


@router.post("/fingerprint-watches/{watch_id}/run", status_code=202)
async def run_fingerprint_watch(watch_id: str, request: Request, ws: WorkspaceContext = ANALYST):
    """Run a watch now (it spends a search credit) instead of waiting for its schedule; not more often
    than every 10 minutes."""
    current = await _repo(request).get(watch_id, ws.id)
    if current is not None:
        cooldown(current.get("last_run_at"), request.app.state.settings.watch_run_cooldown_seconds, "fingerprint watch")
    if not await _repo(request).make_due(watch_id, ws.id):
        raise HTTPException(status_code=404, detail="Fingerprint watch not found")
    await audit(request, ws.principal, "fingerprint_watch.run", watch_id)
    request.app.state.fingerprint_watcher.kick()
    return {"queued": True}


@router.delete("/fingerprint-watches/{watch_id}", status_code=204)
async def delete_fingerprint_watch(watch_id: str, request: Request, ws: WorkspaceContext = ANALYST):
    if not await _repo(request).delete(watch_id, ws.id):
        raise HTTPException(status_code=404, detail="Fingerprint watch not found")
    await audit(request, ws.principal, "fingerprint_watch.delete", watch_id)
    return Response(status_code=204)
