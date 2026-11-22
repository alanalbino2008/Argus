"""Brand watches: lookalike domains of the organisation's brand, found in Certificate Transparency.

Watch ``acme.com``: every day Argus asks the Certificate Transparency logs for new certificates
on names that imitate it (``acme-login.com``, ``acrne.com``, ``acme.com.evil.example``…) and
alerts on new ones. Domains the organisation owns can be listed so they are never reported.
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from argus.api.deps import WorkspaceContext, audit, in_workspace
from argus.intel.brand_watch import HOSTNAME
from argus.intel.lookalikes import registrable
from argus.security.auth import Role
from argus.storage.brand_watch_repo import MAX_WATCHES

router = APIRouter(prefix="/api", tags=["monitoring"])
VIEWER = Depends(in_workspace(Role.VIEWER))
ANALYST = Depends(in_workspace(Role.ANALYST))
MAX_ALLOW = 50


class BrandWatchRequest(BaseModel):
    domain: str = Field(min_length=3, max_length=253, examples=["acme.com"])
    allow: list[str] = Field(default_factory=list, max_length=MAX_ALLOW,
                             description="Other domains the organisation owns: never reported")  # fmt: skip
    interval_hours: Literal[24, 168] = Field(default=24, description="Every day (24) or every week (168)")
    web_check: str = Field(default="off", max_length=64,
                           description="Visit lookalikes' websites: 'off', 'direct', or an egress route's name")  # fmt: skip


class BrandWatchUpdate(BaseModel):
    allow: list[str] | None = Field(default=None, max_length=MAX_ALLOW)
    web_check: str | None = Field(default=None, max_length=64)


def _repo(request: Request) -> Any:
    return request.app.state.brand_watches


def _domain(value: str) -> str:
    name = value.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0].rstrip(".")
    if not HOSTNAME.match(name):
        raise HTTPException(status_code=422, detail=f"{value!r} is not a domain name")
    try:
        return registrable(name)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"{value!r} is not a domain name") from exc


def _web_check(request: Request, value: str) -> str:
    """'off', 'direct' or a configured route: visiting a phishing site tells its operator who looked."""
    from argus.api.opsec_routes import find_route

    value = value.strip() or "off"
    if value not in ("off", "direct") and find_route(request.app.state.settings, value) is None:
        raise HTTPException(status_code=422, detail=f"No route called '{value}' (see Settings → Investigator safety)")
    return value


def _allow(values: list[str], own: str) -> list[str]:
    return sorted({d for d in (_domain(v) for v in values if v.strip()) if d != own})


@router.get("/brand-watches")
async def list_brand_watches(request: Request, ws: WorkspaceContext = VIEWER):
    """The workspace's brand watches, with the lookalikes found most recently."""
    return await _repo(request).list_watches(ws.id)


@router.post("/brand-watches", status_code=201)
async def create_brand_watch(body: BrandWatchRequest, request: Request, ws: WorkspaceContext = ANALYST):
    """Watch a brand. The first run (straight away) records the lookalikes that exist today and alerts
    only on certificates issued in the last 14 days."""
    domain = _domain(body.domain)
    allow = _allow(body.allow, domain)
    if await _repo(request).find(ws.id, domain):
        raise HTTPException(status_code=409, detail=f"{domain} is already watched")
    if await _repo(request).count(ws.id) >= MAX_WATCHES:
        raise HTTPException(status_code=422, detail=f"A workspace can watch up to {MAX_WATCHES} brands")
    web_check = _web_check(request, body.web_check)
    watch = await _repo(request).create(workspace_id=ws.id, domain=domain, allow=allow, web_check=web_check,
                                        interval_hours=body.interval_hours, by=ws.principal.name)  # fmt: skip
    await audit(request, ws.principal, "brand_watch.create", watch["id"], details={"domain": domain})
    request.app.state.brand_watcher.kick()
    return watch


@router.patch("/brand-watches/{watch_id}")
async def update_brand_watch(watch_id: str, body: BrandWatchUpdate, request: Request, ws: WorkspaceContext = ANALYST):
    """Change the domains the organisation owns (never reported) or whether lookalikes' sites are visited."""
    current = await _repo(request).get(watch_id, ws.id)
    if current is None:
        raise HTTPException(status_code=404, detail="Brand watch not found")
    changes: dict[str, Any] = {}
    if body.allow is not None:
        changes["allow"] = _allow(body.allow, current["domain"])
    if body.web_check is not None:
        changes["web_check"] = _web_check(request, body.web_check)
    updated = await _repo(request).update(watch_id, ws.id, **changes)
    await audit(request, ws.principal, "brand_watch.update", watch_id,
                details={"allow": len(updated["allow"]), "web_check": updated["web_check"]})  # fmt: skip
    return updated


@router.post("/brand-watches/{watch_id}/run", status_code=202)
async def run_brand_watch(watch_id: str, request: Request, ws: WorkspaceContext = ANALYST):
    if not await _repo(request).make_due(watch_id, ws.id):
        raise HTTPException(status_code=404, detail="Brand watch not found")
    await audit(request, ws.principal, "brand_watch.run", watch_id)
    request.app.state.brand_watcher.kick()
    return {"queued": True}


@router.delete("/brand-watches/{watch_id}", status_code=204)
async def delete_brand_watch(watch_id: str, request: Request, ws: WorkspaceContext = ANALYST):
    if not await _repo(request).delete(watch_id, ws.id):
        raise HTTPException(status_code=404, detail="Brand watch not found")
    await audit(request, ws.principal, "brand_watch.delete", watch_id)
    return Response(status_code=204)
