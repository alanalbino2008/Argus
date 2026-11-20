"""Research tools used from a case: a web page's history, and where else an image appears.

* ``GET  /api/cases/{case_id}/page-history?url=``: every different version of a page in the
  Internet Archive (free). Any version can then be captured as evidence with the usual capture.
* ``GET  /api/image-search``: which reverse image searches are available here.
* ``POST /api/cases/{case_id}/image-search``: TinEye's matches for an image's address: the pages
  and sites where it appears, and when TinEye first saw it there (own key, or Argus credits).

Both go out through the case's network route, and both are recorded in the audit log.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import aiohttp
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from argus.accounts.connect_client import available, lookup
from argus.accounts.connectors import ConnectError
from argus.api.case_routes import _case
from argus.api.deps import WorkspaceContext, audit, in_workspace
from argus.api.opsec_routes import route_for
from argus.intel import page_history
from argus.intel.account_watch import client
from argus.security.auth import Role

router = APIRouter(prefix="/api", tags=["research"])
ANALYST = Depends(in_workspace(Role.ANALYST))


class ImageSearch(BaseModel):
    image_url: str = Field(min_length=8, max_length=2000)


def matches(data: dict[str, Any]) -> list[dict[str, Any]]:
    """TinEye's answer as a short list: each site and page an image appears on."""
    results = data.get("results") or {}
    rows = results.get("matches") if isinstance(results, dict) else results
    out = []
    for m in rows or []:
        backlinks = m.get("backlinks") or []
        first = min((b.get("crawl_date") for b in backlinks if b.get("crawl_date")), default=None)
        out.append({"domain": m.get("domain"), "image_url": m.get("image_url"), "score": m.get("score"),
                    "size": f"{m.get('width')} x {m.get('height')}" if m.get("width") and m.get("height") else None,
                    "first_seen": str(first)[:10] if first else None,
                    "pages": [{"url": b.get("backlink"), "crawled": str(b.get("crawl_date") or "")[:10] or None}
                              for b in backlinks[:5] if b.get("backlink")]})  # fmt: skip
    return out


@router.get("/cases/{case_id}/page-history")
async def page_history_lookup(case_id: str, request: Request, url: str = Query(min_length=4, max_length=2000),
                              ws: WorkspaceContext = ANALYST):  # fmt: skip
    """Every different version of a web page that the Internet Archive holds, oldest first."""
    case = await _case(request, ws, case_id)
    settings = request.app.state.settings
    base = (settings.wayback_url or "").rstrip("/")
    if not base:
        raise HTTPException(status_code=409, detail="Page history is switched off on this server")
    try:
        target = page_history.clean_url(url)
    except page_history.HistoryError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    route = route_for(settings, case, None)  # an anonymous case never asks directly
    endpoint, params = page_history.query(base, target)
    try:
        async with client(settings, route) as http, http.get(endpoint, params=params) as resp:
            if resp.status != 200:
                raise HTTPException(
                    status_code=502, detail=f"The Internet Archive answered {resp.status}: try again later"
                )
            text = await resp.text()
            rows = json.loads(text) if text.strip() else []  # no archived copies: an empty answer
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError) as exc:
        raise HTTPException(
            status_code=502, detail="The Internet Archive could not be reached; try again later"
        ) from exc
    history = page_history.versions(rows if isinstance(rows, list) else [], base, target)
    await audit(request, ws.principal, "case.page_history", case_id,
                details={"url": target, "versions": len(history["versions"]), "route": route.name if route else "direct"})  # fmt: skip
    return history


@router.get("/image-search")
async def image_search_status(request: Request, ws: WorkspaceContext = ANALYST):
    """Which reverse image searches this installation can run itself (the rest open in the browser)."""
    return {"tineye": available("tineye")}


@router.post("/cases/{case_id}/image-search")
async def image_search(case_id: str, body: ImageSearch, request: Request, ws: WorkspaceContext = ANALYST):
    """Where else an image appears on the web, from TinEye (own key, or Argus credits)."""
    case = await _case(request, ws, case_id)
    if not available("tineye"):
        raise HTTPException(status_code=409, detail="Reverse image search needs a TinEye key or an Argus account")
    image = body.image_url.strip()
    if not image.lower().startswith(("http://", "https://")):
        raise HTTPException(status_code=422, detail="Give the image's web address (https://...)")
    route = route_for(request.app.state.settings, case, None)
    try:
        async with client(request.app.state.settings, route) as http:
            data = await lookup(http, "tineye", "search", {"image_url": image})
    except ConnectError as exc:
        raise HTTPException(
            status_code=exc.status if exc.status in (402, 409, 422, 429) else 502, detail=exc.detail
        ) from exc
    found = matches(data)
    stats = data.get("stats") or {}
    await audit(request, ws.principal, "case.image_search", case_id,
                details={"matches": len(found), "route": route.name if route else "direct"})  # fmt: skip
    return {"image_url": image, "matches": found, "total": stats.get("total_results", len(found))}
