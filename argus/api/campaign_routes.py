"""Campaigns: what the workspace's watches and tags found, grouped by shared infrastructure.

See :mod:`argus.intel.campaigns`. Computed on request from what brand watches, fingerprint watches
and the team's tags have already recorded: nothing is looked up.
"""

from __future__ import annotations

from typing import Any

import anyio
from fastapi import APIRouter, Depends, Request

from argus.api.deps import WorkspaceContext, in_workspace
from argus.intel.campaigns import cluster
from argus.security.auth import Role

router = APIRouter(prefix="/api", tags=["monitoring"])
VIEWER = Depends(in_workspace(Role.VIEWER))


async def gather(
    request: Request, workspace_id: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    state = request.app.state
    lookalikes = []
    for watch, first_seen, details in await state.brand_watches.first_seen(workspace_id):
        triage = watch.get("triage") or {}
        takedowns = watch.get("takedowns") or {}
        for name, when in first_seen.items():
            verdict = triage.get(name) or {}
            if verdict.get("verdict") == "yours":
                continue
            info = details.get(name) or {}
            lookalikes.append({
                "name": name, "display": info.get("display") or name, "brand": watch["domain"],
                "severity": verdict.get("severity") or info.get("severity") or "medium",
                "verdict": verdict.get("verdict") or "", "first_seen": when, "triage": verdict,
                "takedown": (takedowns.get(name) or {}).get("status"),
            })  # fmt: skip
    servers = [
        {"server": server, "watch_id": watch["id"], "label": watch["label"], "first_seen": when}
        for watch, seen in await state.fingerprint_watches.first_seen(workspace_id)
        for server, when in seen.items()
    ]
    tagged = [a for a in (await state.annotations.all(workspace_id)).values() if a.get("tags")]
    return lookalikes, servers, tagged


@router.get("/campaigns")
async def list_campaigns(request: Request, ws: WorkspaceContext = VIEWER):
    """Groups of lookalike domains, watched servers and tagged indicators that share infrastructure
    (addresses, name servers, mail hosts, favicons, page titles, fingerprints), worst first."""
    lookalikes, servers, tagged = await gather(request, ws.id)
    campaigns = await anyio.to_thread.run_sync(cluster, lookalikes, servers, tagged)
    takedown = {item["name"]: item["takedown"] for item in lookalikes if item.get("takedown")}
    for campaign in campaigns:
        for member in campaign["members"]:
            if member["value"] in takedown:
                member["takedown"] = takedown[member["value"]]
    return {"campaigns": campaigns, "indicators": len(lookalikes) + len(servers) + len(tagged)}
