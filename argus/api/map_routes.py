"""A case's timeline and map, address look-ups, and map images served through Argus.

**Map images never come from the investigator's browser.** An ordinary web map makes the browser
download map images ("tiles") of the area being looked at, which tells the map provider, from the
investigator's own connection, which street they are studying. Here Argus's server fetches the
tiles and serves them from its own address, so the browser only ever talks to Argus. Tiles are
cached, and requests identify Argus, as the OpenStreetMap tile policy asks.

**Looking up an address** (geocoding) sends that address to the geocoding service. It only happens
when the investigator asks, through the case's route; an anonymous case refuses to do it without
an anonymous route.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from typing import Any

import aiohttp
from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response

from argus.api.case_routes import _case, _repo
from argus.api.deps import WorkspaceContext, audit, in_workspace
from argus.api.opsec_routes import route_for
from argus.core.http import DEFAULT_USER_AGENT
from argus.evidence.inspect import photo_facts
from argus.intel.account_watch import client
from argus.intel.places import build_places, build_timeline, kml, timeline_csv
from argus.security.auth import Role
from argus.security.network import GuardedResolver, configured_proxy_hosts

router = APIRouter(prefix="/api", tags=["cases"])
VIEWER = Depends(in_workspace(Role.VIEWER))
ANALYST = Depends(in_workspace(Role.ANALYST))
MAX_TILE = 512 * 1024
TILE_CACHE = 2000
PHOTO_CACHE = 5000

_tiles: OrderedDict[tuple[int, int, int], bytes] = OrderedDict()
_photos: OrderedDict[tuple[str, str], dict[str, Any]] = OrderedDict()  # evidence never changes: cache freely
_geocode_lock: asyncio.Lock | None = None
_last_geocode = 0.0


def _remember(cache: OrderedDict[Any, Any], key: Any, value: Any, limit: int) -> None:
    cache[key] = value
    cache.move_to_end(key)
    while len(cache) > limit:
        cache.popitem(last=False)


async def _photos_of(request: Request, captures: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Where and when each photo in the evidence was taken, read once from its own metadata."""
    known = [c["id"] for c in captures]
    out: list[dict[str, Any]] = []
    missing = [cid for cid in known if not any(k[0] == cid for k in _photos)]
    for capture_id, name, data in await _repo(request).image_files(missing):
        _remember(_photos, (capture_id, name), await asyncio.to_thread(photo_facts, data), PHOTO_CACHE)
    for cid in missing:  # remember captures without photos too, so they are not re-read every time
        if not any(k[0] == cid for k in _photos):
            _remember(_photos, (cid, ""), {}, PHOTO_CACHE)
    for (capture_id, name), facts in list(_photos.items()):
        if capture_id in known and name and facts:
            out.append({"capture_id": capture_id, "file": name, **facts})
    return out


async def _scans(request: Request, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    scans = []
    for item in items:
        inv_id = (item.get("data") or {}).get("investigation_id") if item["kind"] == "scan" else None
        inv = await request.app.state.repo.get_investigation(inv_id) if inv_id else None
        if inv is not None:
            scans.append({"id": inv.id, "target": inv.config.target, "status": inv.status.value,
                          "started_at": inv.created_at.isoformat(), "created_by": inv.created_by})  # fmt: skip
    return scans


@router.get("/cases/{case_id}/timeline")
async def case_timeline(case_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Everything dated in the case, oldest first: events, account changes, evidence, scans, photo dates."""
    await _case(request, ws, case_id)
    repo = _repo(request)
    items, captures = await repo.items(case_id), await repo.captures(case_id)
    return build_timeline(items, captures, await _scans(request, items), await _photos_of(request, captures))


@router.get("/cases/{case_id}/places")
async def case_places(case_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Everything placed in the case (entities with coordinates, photos with GPS) and addresses not yet placed."""
    await _case(request, ws, case_id)
    repo = _repo(request)
    places = build_places(await repo.items(case_id), await _photos_of(request, await repo.captures(case_id)))
    settings = request.app.state.settings
    return {**places, "tiles": bool(settings.map_tile_url), "attribution": settings.map_attribution,
            "geocoding": bool(settings.geocoder_url)}  # fmt: skip


@router.get("/cases/{case_id}/places.kml")
async def export_places(case_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """The case's places for Google Earth and other mapping tools."""
    case = await _case(request, ws, case_id)
    repo = _repo(request)
    places = build_places(await repo.items(case_id), await _photos_of(request, await repo.captures(case_id)))
    await audit(request, ws.principal, "case.export_places", case_id, details={"places": len(places["places"])})
    return Response(kml(case["title"], places["places"]), media_type="application/vnd.google-earth.kml+xml",
                    headers={"Content-Disposition": f'attachment; filename="argus-{case_id}-places.kml"'})  # fmt: skip


@router.get("/cases/{case_id}/timeline.csv")
async def export_timeline(case_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    await _case(request, ws, case_id)
    repo = _repo(request)
    items, captures = await repo.items(case_id), await repo.captures(case_id)
    entries = build_timeline(items, captures, await _scans(request, items), await _photos_of(request, captures))
    await audit(request, ws.principal, "case.export_timeline", case_id, details={"entries": len(entries)})
    return Response(timeline_csv(entries), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="argus-{case_id}-timeline.csv"'})  # fmt: skip


# ---------------------------------------------------------------------------- geocoding
async def _spaced() -> None:
    """At most one look-up a second (the public Nominatim service's usage policy)."""
    global _geocode_lock, _last_geocode
    if _geocode_lock is None:
        _geocode_lock = asyncio.Lock()
    async with _geocode_lock:
        wait = 1.1 - (time.monotonic() - _last_geocode)
        if wait > 0:
            await asyncio.sleep(wait)
        _last_geocode = time.monotonic()


@router.post("/cases/{case_id}/items/{item_id}/geocode")
async def geocode_item(case_id: str, item_id: str, request: Request, ws: WorkspaceContext = ANALYST):
    """Look up an address's position (sends the address to the geocoder, through the case's route)."""
    case = await _case(request, ws, case_id)
    settings = request.app.state.settings
    if not settings.geocoder_url:
        raise HTTPException(status_code=409, detail="Address look-up is switched off on this server")
    item = await _repo(request).get_item(item_id, case_id)
    if item is None or item["kind"] != "entity":
        raise HTTPException(status_code=404, detail="Entity not found")
    query = str((item["data"] or {}).get("value") or item["title"]).strip()[:300]
    route = route_for(settings, case, None)  # an anonymous case refuses to look up directly
    await _spaced()
    try:
        async with (
            client(settings, route) as http,
            http.get(settings.geocoder_url, params={"q": query, "format": "jsonv2", "limit": "1"},
                     headers={"Accept": "application/json", "Accept-Language": "en"}) as resp,
        ):  # fmt: skip
            if resp.status != 200:
                raise HTTPException(status_code=502, detail=f"The address service answered {resp.status}")
            found = await resp.json(content_type=None)
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
        raise HTTPException(status_code=502, detail="The address service could not be reached") from exc
    if not isinstance(found, list) or not found:
        raise HTTPException(status_code=404, detail="The address could not be found on the map")
    best = found[0]
    try:
        lat, lon = round(float(best["lat"]), 6), round(float(best["lon"]), 6)
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=502, detail="The address service gave an unusable answer") from exc
    data = dict(item["data"] or {})
    data["attributes"] = {**(data.get("attributes") or {}), "lat": str(lat), "lon": str(lon),
                          "geocoded_name": str(best.get("display_name") or "")[:300],
                          "geocoded_by": "address look-up"}  # fmt: skip
    updated = await _repo(request).update_item(item_id, case_id, data=data)
    await audit(request, ws.principal, "case.geocode", case_id,
                details={"item": item_id, "route": route.name if route else "direct"})  # fmt: skip
    return updated


# ---------------------------------------------------------------------------- map images
_session: aiohttp.ClientSession | None = None


async def _tile_session(request: Request) -> aiohttp.ClientSession:
    global _session
    if _session is None or _session.closed:
        settings = request.app.state.settings
        resolver = None if settings.allow_private_targets else GuardedResolver(trusted_hosts=configured_proxy_hosts())
        _session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(resolver=resolver, limit=8), timeout=aiohttp.ClientTimeout(total=20),
            headers={"User-Agent": DEFAULT_USER_AGENT}, trust_env=True)  # fmt: skip
    return _session


@router.get("/map/tiles/{z}/{x}/{y}.png")
async def map_tile(request: Request, z: int = Path(ge=0, le=19), x: int = Path(ge=0), y: int = Path(ge=0),
                   ws: WorkspaceContext = VIEWER):  # fmt: skip
    """A map image, fetched and cached by Argus so the browser never contacts the map provider."""
    if x >= 2**z or y >= 2**z:
        raise HTTPException(status_code=404, detail="No such tile")
    template = request.app.state.settings.map_tile_url
    if not template:
        raise HTTPException(status_code=404, detail="Map images are switched off on this server")
    data = _tiles.get((z, x, y))
    if data is None:
        session = await _tile_session(request)
        try:
            async with session.get(template.format(z=z, x=x, y=y), allow_redirects=False) as resp:
                body = await resp.content.read(MAX_TILE + 1)
                if (
                    resp.status != 200
                    or len(body) > MAX_TILE
                    or not resp.headers.get("Content-Type", "").startswith("image/")
                ):
                    raise HTTPException(status_code=502, detail="The map service did not return an image")
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
            raise HTTPException(status_code=502, detail="The map service could not be reached") from exc
        data = body
        _remember(_tiles, (z, x, y), data, TILE_CACHE)
    return Response(data, media_type="image/png",
                    headers={"Cache-Control": "private, max-age=86400", "X-Content-Type-Options": "nosniff"})  # fmt: skip
