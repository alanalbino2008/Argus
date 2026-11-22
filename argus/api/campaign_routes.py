"""Campaigns: what the workspace's watches and tags found, grouped by shared infrastructure.

See :mod:`argus.intel.campaigns`. Computed on request from what brand watches, fingerprint watches
and the team's tags have already recorded: nothing is looked up.
"""

from __future__ import annotations

from typing import Any

import anyio
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from argus.api.deps import WorkspaceContext, audit, in_workspace
from argus.intel.campaigns import cluster
from argus.security.auth import Role

router = APIRouter(prefix="/api", tags=["monitoring"])
VIEWER = Depends(in_workspace(Role.VIEWER))
ANALYST = Depends(in_workspace(Role.ANALYST))
MAX_CAMPAIGN_TAKEDOWN = 30  # domains looked up in RDAP for one campaign report


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
                "name": name, "display": info.get("display") or name, "brand": watch["domain"], "watch_id": watch["id"],
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


async def campaigns_of(request: Request, workspace_id: str) -> list[dict[str, Any]]:
    lookalikes, servers, tagged = await gather(request, workspace_id)
    return await anyio.to_thread.run_sync(cluster, lookalikes, servers, tagged)


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


class CampaignTakedown(BaseModel):
    organisation: str = Field(default="", max_length=200, description="Who the reports are from (signs them)")


@router.post("/campaigns/{campaign_id}/takedown")
async def campaign_takedown(campaign_id: str, body: CampaignTakedown, request: Request, ws: WorkspaceContext = ANALYST):
    """Draft takedowns for a whole campaign: one abuse report per registrar and host, each listing the
    campaign's domains it is responsible for, with the infrastructure they share. Each domain also gets
    its own takedown record, followed until it goes down. Argus does not send the reports.

    Calling it again re-shows the reports, and drafts only domains that have no open takedown yet."""
    from argus.intel import takedown

    campaign = next((c for c in await campaigns_of(request, ws.id) if c["id"] == campaign_id), None)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found (its membership may have changed)")
    watches = {w["id"]: w for w, _seen, _details in await request.app.state.brand_watches.first_seen(ws.id)}
    lookalikes = [m for m in campaign["members"] if m["kind"] == "lookalike" and m.get("watch_id") in watches]
    if not lookalikes:
        raise HTTPException(status_code=422, detail="This campaign has no lookalike domains to report")
    pending: list[dict[str, Any]] = []
    existing: list[dict[str, Any]] = []
    for member in lookalikes:
        record = (watches[member["watch_id"]].get("takedowns") or {}).get(member["value"]) or {}
        (existing if record.get("status") in ("drafted", "reported", "down") else pending).append(member)
    pending = pending[:MAX_CAMPAIGN_TAKEDOWN]
    contacts = request.app.state.brand_watcher.takedown_contacts
    items = []
    for member in pending:
        watch = watches[member["watch_id"]]
        name = member["value"]
        triage = (watch.get("triage") or {}).get(name) or {}
        finding = next((f for f in watch.get("recent") or [] if f.get("name") == name), None) or {
            "name": name, **((watch.get("details") or {}).get(name) or {})}  # fmt: skip
        found = await contacts(name, (triage.get("dns") or {}).get("ips") or [])
        items.append({"domain": name, "display": member["display"], "brand": watch["domain"], "finding": finding,
                      "triage": triage, "found": found, "watch_id": watch["id"]})  # fmt: skip
    letters = takedown.campaign_letters(campaign=campaign, domains=items, organisation=body.organisation.strip())
    repo = request.app.state.brand_watches
    for item in items:
        own = takedown.draft(domain=item["domain"], display=item["display"], brand=item["brand"], finding=item["finding"],
                             triage=item["triage"], found=item["found"], organisation=body.organisation.strip())  # fmt: skip
        await repo.put_takedown(
            item["watch_id"], ws.id, item["domain"],
            {"status": "drafted", "contacts": item["found"], "draft": own, "created_by": ws.principal.name,
             "verdict_at_report": item["triage"].get("verdict"), "misses": 0, "campaign_id": campaign_id,
             "campaign_letters": [x for x in letters if item["domain"] in x["domains"]]},
            {"event": "drafted", "by": ws.principal.name, "campaign": campaign_id},
        )  # fmt: skip
    if not letters:  # nothing new to draft: show the reports drafted before
        seen: dict[str, dict[str, Any]] = {}
        for member in existing:
            record = (watches[member["watch_id"]].get("takedowns") or {}).get(member["value"]) or {}
            for letter in record.get("campaign_letters") or []:
                seen.setdefault(letter["to"][0], letter)
        letters = list(seen.values())
    await audit(request, ws.principal, "takedown.campaign", campaign_id,
                details={"drafted": len(items), "letters": len(letters), "already_open": len(existing)})  # fmt: skip
    return {
        "campaign_id": campaign_id, "letters": letters,
        "domains": [{"domain": m["value"], "watch_id": m["watch_id"]} for m in lookalikes],
        "drafted": [i["domain"] for i in items], "already_open": [m["value"] for m in existing],
    }  # fmt: skip
