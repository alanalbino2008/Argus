"""Account watching inside a case: which accounts are watched, their history, and checking now."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from argus.api.case_routes import _case
from argus.api.deps import WorkspaceContext, audit, in_workspace
from argus.intel.account_watch import READERS, profile_url
from argus.modules.identity import catalog
from argus.modules.identity.username_hunter import get_platforms
from argus.security.auth import Role
from argus.security.ratelimit import SlidingWindowLimiter

router = APIRouter(prefix="/api", tags=["cases"])
VIEWER = Depends(in_workspace(Role.VIEWER))
ANALYST = Depends(in_workspace(Role.ANALYST))
_check_limiter = SlidingWindowLimiter(limit=10, window=60, name="account_watch_check")
MAX_WATCHES = 100  # per case


class WatchRequest(BaseModel):
    platform: str = Field(min_length=1, max_length=80, examples=["GitHub"])
    handle: str = Field(min_length=1, max_length=128, examples=["jane-roe"])
    interval_hours: Literal[6, 24, 168] = 24
    capture_on_change: bool = Field(default=True, description="Capture the profile page as evidence when it changes")


class WatchUpdate(BaseModel):
    interval_hours: Literal[6, 24, 168] | None = None
    capture_on_change: bool | None = None
    enabled: bool | None = None


def _platforms() -> list[Any]:
    curated = get_platforms()
    names = {p.name.lower() for p in curated}
    return curated + [p for p in catalog._state.platforms if p.name.lower() not in names]


def _repo(request: Request) -> Any:
    return request.app.state.account_watches


@router.get("/watchable-platforms")
async def watchable_platforms(request: Request, ws: WorkspaceContext = VIEWER):
    """Platforms an account can be watched on: full detail (official APIs) or presence only."""
    detailed = sorted(READERS)
    presence = sorted({p.name for p in _platforms()} - set(detailed), key=str.lower)
    return {"detailed": detailed, "presence": presence}


@router.get("/cases/{case_id}/watches")
async def list_account_watches(case_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    await _case(request, ws, case_id)
    return await _repo(request).list_for_case(case_id)


@router.post("/cases/{case_id}/watches", status_code=201)
async def add_account_watch(case_id: str, body: WatchRequest, request: Request, ws: WorkspaceContext = ANALYST):
    """Watch an account: Argus re-reads it on a schedule and records every change in the case."""
    await _case(request, ws, case_id)
    platforms = _platforms()
    match = next((p for p in platforms if p.name.lower() == body.platform.strip().lower()), None)
    platform = match.name if match else next((r for r in READERS if r.lower() == body.platform.strip().lower()), None)
    if platform is None:
        raise HTTPException(status_code=422, detail=f"Argus cannot watch accounts on {body.platform!r}")
    handle = body.handle.strip().lstrip("@")
    if match is not None and not match.accepts(handle):
        raise HTTPException(status_code=422, detail=f"{handle!r} is not a valid {platform} handle")
    if len(await _repo(request).list_for_case(case_id)) >= MAX_WATCHES:
        raise HTTPException(status_code=422, detail=f"A case can watch up to {MAX_WATCHES} accounts")
    watch = await _repo(request).create(
        workspace_id=ws.id, case_id=case_id, by=ws.principal.name, platform=platform, handle=handle,
        profile_url=profile_url(platform, handle, platforms), interval_hours=body.interval_hours,
        capture_on_change=body.capture_on_change,
    )  # fmt: skip
    if watch is None:
        raise HTTPException(status_code=409, detail="This case already watches that account")
    await audit(request, ws.principal, "account_watch.create", watch["id"],
                details={"case": case_id, "platform": platform, "handle": handle})  # fmt: skip
    return watch


@router.patch("/cases/{case_id}/watches/{watch_id}")
async def update_account_watch(case_id: str, watch_id: str, body: WatchUpdate, request: Request,
                       ws: WorkspaceContext = ANALYST):  # fmt: skip
    await _case(request, ws, case_id)
    changes = body.model_dump(exclude_none=True)
    watch = await _repo(request).update(watch_id, case_id, **changes)
    if watch is None:
        raise HTTPException(status_code=404, detail="Watch not found")
    await audit(
        request, ws.principal, "account_watch.update", watch_id, details={k: str(v) for k, v in changes.items()}
    )
    return watch


@router.delete("/cases/{case_id}/watches/{watch_id}", status_code=204)
async def delete_account_watch(case_id: str, watch_id: str, request: Request, ws: WorkspaceContext = ANALYST):
    await _case(request, ws, case_id)
    if not await _repo(request).delete(watch_id, case_id):
        raise HTTPException(status_code=404, detail="Watch not found")
    await audit(request, ws.principal, "account_watch.delete", watch_id, details={"case": case_id})
    return Response(status_code=204)


@router.get("/cases/{case_id}/watches/{watch_id}/history")
async def account_watch_history(case_id: str, watch_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """The profile when first seen and after each change, newest first."""
    await _case(request, ws, case_id)
    if await _repo(request).get(watch_id, case_id) is None:
        raise HTTPException(status_code=404, detail="Watch not found")
    return await _repo(request).history(watch_id)


@router.post("/cases/{case_id}/watches/{watch_id}/check")
async def check_account_watch(case_id: str, watch_id: str, request: Request, ws: WorkspaceContext = ANALYST):
    """Check the account now (through the case's route), instead of waiting for the schedule."""
    await _case(request, ws, case_id)
    watch = await _repo(request).get(watch_id, case_id)
    if watch is None:
        raise HTTPException(status_code=404, detail="Watch not found")
    if not await _check_limiter.allow(ws.principal.key_id):
        raise HTTPException(status_code=429, detail="Too many checks; wait a minute")
    result = await request.app.state.account_watcher.check(watch)
    await audit(request, ws.principal, "account_watch.check", watch_id, details={"status": result["status"]})
    return result
