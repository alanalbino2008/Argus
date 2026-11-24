"""Campaigns: what the workspace's watches and tags found, grouped by shared infrastructure.

See :mod:`argus.intel.campaigns`. Computed on request from what brand watches, fingerprint watches
and the team's tags have already recorded: nothing is looked up.
"""

from __future__ import annotations

from typing import Any, Literal

import anyio
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from argus.api.deps import WorkspaceContext, audit, in_workspace, throttle
from argus.intel.campaigns import cluster
from argus.security.auth import Role
from argus.security.ratelimit import SlidingWindowLimiter

router = APIRouter(prefix="/api", tags=["monitoring"])
VIEWER = Depends(in_workspace(Role.VIEWER))
ANALYST = Depends(in_workspace(Role.ANALYST))
MAX_CAMPAIGN_TAKEDOWN = 30  # domains looked up in RDAP for one campaign report
_read_limiter = SlidingWindowLimiter(
    limit=60, window=60, name="campaign_read"
)  # campaigns and metrics read every lookalike
_campaign_takedown_limiter = SlidingWindowLimiter(
    limit=3, window=60, name="campaign_takedown"
)  # up to 30 RDAP look-ups each
_report_limiter = SlidingWindowLimiter(limit=10, window=60, name="brand_report")  # PDF rendering costs CPU


async def gather(
    request: Request, workspace_id: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    state = request.app.state
    lookalikes = []
    for watch, first_seen, details in await state.brand_watches.first_seen(workspace_id, takedowns=False):
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
    throttle(_read_limiter, ws.principal.key_id, "Too many requests; wait a minute")
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

    throttle(_campaign_takedown_limiter, ws.principal.key_id, "Too many campaign takedowns; wait a minute")
    campaign = next((c for c in await campaigns_of(request, ws.id) if c["id"] == campaign_id), None)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found (its membership may have changed)")
    repo = request.app.state.brand_watches
    lookalikes = [m for m in campaign["members"] if m["kind"] == "lookalike" and m.get("watch_id")]
    rows: dict[tuple[str, str], dict[str, Any]] = {}  # (watch, domain) -> finding, triage and takedown
    brands: dict[str, str] = {}
    for watch_id in {m["watch_id"] for m in lookalikes}:
        watch = await repo.get(watch_id, ws.id)
        if watch is None:
            continue
        brands[watch_id] = watch["domain"]
        names = [m["value"] for m in lookalikes if m["watch_id"] == watch_id]
        rows.update({(watch_id, n): row for n, row in (await repo.lookalikes(watch_id, names)).items()})
    lookalikes = [m for m in lookalikes if (m["watch_id"], m["value"]) in rows]
    if not lookalikes:
        raise HTTPException(status_code=422, detail="This campaign has no lookalike domains to report")
    pending: list[dict[str, Any]] = []
    existing: list[dict[str, Any]] = []
    for member in lookalikes:
        record = rows[(member["watch_id"], member["value"])].get("takedown") or {}
        (existing if record.get("status") in ("drafted", "reported", "down") else pending).append(member)
    pending = pending[:MAX_CAMPAIGN_TAKEDOWN]
    contacts = request.app.state.brand_watcher.takedown_contacts
    items = []
    for member in pending:
        name = member["value"]
        row = rows[(member["watch_id"], name)]
        triage = row.get("triage") or {}
        finding = {k: v for k, v in row.items() if k not in ("triage", "takedown")}
        found = await contacts(name, (triage.get("dns") or {}).get("ips") or [])
        items.append({"domain": name, "display": member["display"], "brand": brands[member["watch_id"]],
                      "finding": finding, "triage": triage, "found": found, "watch_id": member["watch_id"]})  # fmt: skip
    letters = takedown.campaign_letters(campaign=campaign, domains=items, organisation=body.organisation.strip())
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
            record = rows[(member["watch_id"], member["value"])].get("takedown") or {}
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


# ----------------------------------------------------------------------------- brand-protection metrics
BRAND_TARGET = "Brand protection"


@router.get("/brand-protection/summary")
async def brand_protection_summary(request: Request, ws: WorkspaceContext = VIEWER, days: int = 90):
    """Lookalikes found, open threats, takedowns (with median time to takedown), campaigns and weekly trend."""
    from argus.intel.brand_metrics import summarise

    throttle(_read_limiter, ws.principal.key_id, "Too many requests; wait a minute")
    days = max(7, min(days, 365))
    watches = await request.app.state.brand_watches.first_seen(ws.id, triage=False)
    return summarise(watches, await campaigns_of(request, ws.id), days=days)


async def issue_brand_report(
    app: Any, workspace: dict[str, Any], *, days: int, tlp: str, prepared_for: str, issued_by: str,
    trigger: str = "manual", keep_file_for: Any = None, after_record: Any = None,
) -> dict[str, Any]:  # fmt: skip
    """Render, fingerprint and register a brand-protection report (one code path for the API and schedules)."""
    import hashlib
    from datetime import datetime, timezone

    from argus import __version__
    from argus.intel.brand_metrics import summarise
    from argus.observability import metrics
    from argus.reports.brand import render_brand_pdf
    from argus.reports.data import new_report_id
    from argus.reports.service import default_issuer

    class _Request:  # campaigns_of only needs the application
        def __init__(self, application: Any) -> None:
            self.app = application

    watches = await app.state.brand_watches.first_seen(workspace["id"], triage=False)
    summary = summarise(watches, await campaigns_of(_Request(app), workspace["id"]), days=days)  # type: ignore[arg-type]
    branding = await app.state.reports.branding(workspace["id"], default_org=default_issuer(workspace))
    base = app.state.settings.public_url
    verify_url = f"{base.rstrip('/')}/api/reports/verify/<sha256>" if base else None
    report_id, generated_at = new_report_id(), datetime.now(timezone.utc)
    pdf = await anyio.to_thread.run_sync(lambda: render_brand_pdf(
        summary, branding=branding, report_id=report_id, workspace=str(workspace.get("name") or workspace["id"]),
        tlp=tlp, prepared_for=prepared_for, generated_at=generated_at, generator=f"Argus {__version__}",
        verify_url=verify_url,
    ))  # fmt: skip
    digest = hashlib.sha256(pdf).hexdigest()
    filename = f"argus-brand-protection-{generated_at:%Y%m%d}-{report_id}.pdf"
    record, after = await app.state.reports.record(
        fields={"id": report_id, "workspace_id": workspace["id"], "investigation_id": "", "target": BRAND_TARGET,
                "sha256": digest, "size": len(pdf), "tlp": tlp, "prepared_for": prepared_for or None,
                "issued_by_org": branding.organisation, "created_by": issued_by[:128]},
        file=(filename, pdf, keep_file_for) if keep_file_for else None,
        after_record=(lambda session, rec: after_record(session, rec, summary)) if after_record else None,
    )  # fmt: skip
    metrics.REPORTS_GENERATED.labels(f"brand_{trigger}").inc()
    return {"record": record, "pdf": pdf, "sha256": digest, "filename": filename, "summary": summary, "after": after}


class BrandReportRequest(BaseModel):
    days: int = Field(default=90, ge=7, le=365)
    tlp: Literal["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"] = "AMBER"
    prepared_for: str = Field(default="", max_length=200)


@router.post("/brand-protection/report")
async def brand_protection_report(body: BrandReportRequest, request: Request, ws: WorkspaceContext = ANALYST):
    """The brand-protection report as a PDF, registered like every Argus report (verifiable by SHA-256)."""
    from fastapi import Response

    throttle(_report_limiter, ws.principal.key_id, "Too many reports; wait a minute")
    issued = await issue_brand_report(request.app, ws.workspace, days=body.days, tlp=body.tlp,
                                      prepared_for=body.prepared_for.strip(), issued_by=ws.principal.name)  # fmt: skip
    await audit(request, ws.principal, "report.brand", issued["record"]["id"], details={"sha256": issued["sha256"]})
    return Response(issued["pdf"], media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="{issued["filename"]}"', "X-Report-SHA256": issued["sha256"],
        "Cache-Control": "no-store"})  # fmt: skip
