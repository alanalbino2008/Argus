"""Ransomware-ecosystem intelligence hub: recent leak-site posts, group tracking, new-group detection.

Read-only. Argus never visits leak sites; this reads the same public research feed as the exposure
monitor. Only metadata is handled — victim, group, date, sector, country — never leaked files."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from argus.api.deps import WorkspaceContext, audit, in_workspace
from argus.intel import ransomware as R
from argus.intel.breach_sources import SourceError, SourceUnavailable
from argus.security.auth import Role

router = APIRouter(prefix="/api/ransomware", tags=["ransomware"])
VIEWER = Depends(in_workspace(Role.VIEWER))


@router.get("")
async def ransomware_hub(
    request: Request,
    ws: WorkspaceContext = VIEWER,
    group: str = Query("", max_length=80),
    country: str = Query("", max_length=3),
    sector: str = Query("", max_length=80),
    q: str = Query("", max_length=120),
    limit: int = Query(200, ge=1, le=R.MAX_POSTS),
):
    """The ransomware landscape from the research feed: recent posts (filterable), the active groups,
    newly appeared groups, and ecosystem stats."""
    sources = request.app.state.exposure_monitor.sources
    store = request.app.state.app_state
    now = datetime.now(timezone.utc)
    empty = {
        "capabilities": {"ransomware": bool(sources.ransomware_feed)},
        "stats": R.stats([], now), "facets": {"groups": [], "sectors": [], "countries": []},
        "new_groups": [], "roster_count": 0, "posts": [], "total_matched": 0,
        "filters": {"group": group, "country": country, "sector": sector, "q": q},
    }  # fmt: skip
    if not sources.ransomware_feed:
        return empty
    try:
        raw = await sources.recent_victims()
    except SourceUnavailable:
        return empty
    except SourceError as exc:
        raise HTTPException(status_code=502, detail=f"The ransomware feed is unavailable: {exc}") from exc

    posts = R.recent_posts(raw)
    stored = await store.get(R.KNOWN_GROUPS_KEY) or {}
    known = {str(g) for g in (stored.get("groups") or [])}
    new_groups, updated = R.detect_new_groups(posts, known)
    if updated != known:
        await store.set(R.KNOWN_GROUPS_KEY, {"groups": sorted(updated), "updated_at": now.isoformat()})
    roster = await sources.groups()

    matched = R.filter_posts(posts, group=group, country=country, sector=sector, q=q)
    await audit(request, ws.principal, "ransomware.view", None,
                details={"posts": len(posts), "new_groups": len(new_groups)})  # fmt: skip
    return {
        "capabilities": {"ransomware": True},
        "stats": R.stats(posts, now),
        "facets": R.facets(posts),
        "new_groups": new_groups,
        "roster_count": len({str(g.get("name") or g.get("group") or "") for g in roster if isinstance(g, dict)} - {""}),
        "posts": matched[:limit],
        "total_matched": len(matched),
        "filters": {"group": group, "country": country, "sector": sector, "q": q},
    }
