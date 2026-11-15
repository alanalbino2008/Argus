"""Breach and dark-web exposure: watched domains, findings, triage and export.

Staff email addresses are **personal data**. Every listing masks them (``a•••e@acme.com``); an
analyst can reveal them (``?reveal=true``) or export them to reset passwords, and both actions
are written to the audit log with the number of addresses disclosed.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from argus.api.deps import WorkspaceContext, audit, in_workspace
from argus.core.models import EntityType
from argus.intel.exposure import KIND_LABEL, SEVERITY_ORDER, summarise
from argus.intel.suppliers import normalise_domain
from argus.security.auth import Role
from argus.security.network import validate_scan_target

router = APIRouter(prefix="/api/exposure", tags=["exposure"])
VIEWER = Depends(in_workspace(Role.VIEWER))
ANALYST = Depends(in_workspace(Role.ANALYST))
ADMIN = Depends(in_workspace(Role.ADMIN))


class WatchRequest(BaseModel):
    domain: str = Field(min_length=3, max_length=253, examples=["acme.com"])
    organisation: str = Field(default="", max_length=200, description="Legal or trading name, to match leak-site posts")
    basis: str = Field(min_length=5, max_length=300, examples=["Our corporate domain; monitored by the SOC"])
    authorized: bool = Field(
        description="Confirms this is your organisation's domain, or one you are engaged to protect"
    )


class WatchUpdate(BaseModel):
    enabled: bool | None = None
    organisation: str | None = Field(default=None, max_length=200)
    interval_hours: int | None = Field(default=None, ge=6, le=24 * 7)


class StatusRequest(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=500)
    status: Literal["open", "resolved", "accepted"]
    note: str = Field(default="", max_length=500, description="e.g. 'Password reset and sessions revoked'")


def _repo(request: Request) -> Any:
    return request.app.state.exposure


def _ordered(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    kinds = list(KIND_LABEL)
    return sorted(
        findings,
        key=lambda f: (-SEVERITY_ORDER.get(f["severity"], 0), kinds.index(f["kind"]), f["subject"],
                       f.get("account_masked") or "", f["first_seen_at"] or ""),
    )  # fmt: skip


@router.get("")
async def overview(
    request: Request,
    ws: WorkspaceContext = VIEWER,
    status: Literal["open", "resolved", "accepted", "all"] = "open",
    reveal: bool = Query(False, description="Include full email addresses (analyst; audited)"),
):
    """Watched domains, what the sources can do here, and the findings (staff addresses masked)."""
    if reveal and ws.role.rank < Role.ANALYST.rank:
        raise HTTPException(status_code=403, detail="Requires analyst role to reveal email addresses")
    repo = _repo(request)
    if await request.app.state.suppliers.domains(workspace_id=ws.id):
        await repo.ensure_supplier_watch(workspace_id=ws.id, by="system")
    everything = await repo.findings(workspace_id=ws.id, reveal=True)
    summary = summarise(everything)  # counts distinct accounts, so it needs the real addresses
    if not reveal:
        everything = [{**f, "account": None} for f in everything]
    shown = everything if status == "all" else [f for f in everything if f["status"] == status]
    if reveal:
        disclosed = len({f["account"] for f in shown if f.get("account")})
        await audit(request, ws.principal, "exposure.reveal", None, details={"addresses": disclosed})
    return {
        "capabilities": request.app.state.exposure_monitor.sources.capabilities(),
        "watches": await repo.list_watches(workspace_id=ws.id),
        "summary": summary,
        "findings": _ordered(shown),
        "revealed": reveal,
    }


@router.post("/watches", status_code=201)
async def create_watch(body: WatchRequest, request: Request, ws: WorkspaceContext = ANALYST):
    if not body.authorized:
        raise HTTPException(status_code=422, detail="Confirm this is your organisation's domain (or one you protect)")
    domain = normalise_domain(body.domain)
    if not domain:
        raise HTTPException(status_code=422, detail="Enter a domain, e.g. acme.com")
    if not request.app.state.settings.allow_private_targets:
        try:
            validate_scan_target(domain, EntityType.DOMAIN)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    watch = await _repo(request).create_watch(
        workspace_id=ws.id, scope="domain", domain=domain, organisation=body.organisation.strip(),
        basis=body.basis.strip(), by=ws.principal.name,
    )  # fmt: skip
    if watch is None:
        raise HTTPException(status_code=409, detail=f"{domain} is already monitored for exposure")
    await audit(request, ws.principal, "exposure.watch_create", watch["id"],
                details={"domain": domain, "organisation": body.organisation, "basis": body.basis})  # fmt: skip
    _kick(request)
    return watch


@router.patch("/watches/{watch_id}")
async def update_watch(watch_id: str, body: WatchUpdate, request: Request, ws: WorkspaceContext = ANALYST):
    changes = body.model_dump(exclude_none=True)
    if "organisation" in changes:
        changes["organisation"] = changes["organisation"].strip()
    watch = await _repo(request).update_watch(watch_id, workspace_id=ws.id, **changes)
    if watch is None:
        raise HTTPException(status_code=404, detail="Watch not found")
    await audit(
        request, ws.principal, "exposure.watch_update", watch_id, details={k: str(v) for k, v in changes.items()}
    )
    return watch


@router.post("/watches/{watch_id}/check", status_code=202)
async def check_now(watch_id: str, request: Request, ws: WorkspaceContext = ANALYST):
    repo = _repo(request)
    watch = await repo.get_watch(watch_id, workspace_id=ws.id)
    if watch is None:
        raise HTTPException(status_code=404, detail="Watch not found")
    if watch["demo"]:
        raise HTTPException(
            status_code=409, detail="This is demonstration data; it is not checked against live sources"
        )
    await repo.update_watch(watch_id, workspace_id=ws.id, next_check_at=datetime.now(timezone.utc), enabled=True)
    await audit(request, ws.principal, "exposure.check", watch_id)
    _kick(request)
    return {"status": "queued", "watch_id": watch_id}


@router.delete("/watches/{watch_id}", status_code=204)
async def delete_watch(watch_id: str, request: Request, ws: WorkspaceContext = ADMIN):
    if not await _repo(request).delete_watch(watch_id, workspace_id=ws.id):
        raise HTTPException(status_code=404, detail="Watch not found")
    await audit(request, ws.principal, "exposure.watch_delete", watch_id)
    return Response(status_code=204)


@router.post("/findings/status")
async def set_status(body: StatusRequest, request: Request, ws: WorkspaceContext = ANALYST):
    """Triage: resolved (e.g. password reset), accepted (risk accepted), or reopened."""
    changed = await _repo(request).set_status(
        list(dict.fromkeys(body.ids)), workspace_id=ws.id, status=body.status, by=ws.principal.name, note=body.note
    )
    await audit(request, ws.principal, "exposure.triage", None,
                details={"status": body.status, "findings": changed, "note": body.note})  # fmt: skip
    return {"updated": changed}


@router.get("/export.csv")
async def export(request: Request, ws: WorkspaceContext = ANALYST, status: Literal["open", "all"] = "open"):
    """Exposed accounts with full addresses, e.g. to force password resets. Audited."""
    findings = await _repo(request).findings(workspace_id=ws.id, reveal=True)
    rows = _ordered([f for f in findings if status == "all" or f["status"] == "open"])
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Severity", "Type", "Subject", "Account", "What", "Breach or group", "Data exposed", "When",
                     "First seen", "Status", "Note"])  # fmt: skip
    for f in rows:
        d = f["details"]
        writer.writerow([
            f["severity"], KIND_LABEL[f["kind"]], f["subject_name"], f["account"] or "", f["title"],
            d.get("breach_title") or d.get("group") or "", ", ".join(d.get("data_classes") or d.get("websites") or []),
            f["occurred_at"] or "", (f["first_seen_at"] or "")[:10], f["status"], f["note"],
        ])  # fmt: skip
    await audit(request, ws.principal, "exposure.export", None,
                details={"findings": len(rows), "addresses": len({f["account"] for f in rows if f["account"]})})  # fmt: skip
    return Response(out.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="exposure.csv"'})  # fmt: skip


def _kick(request: Request) -> None:
    if request.app.state.settings.exposure_monitoring_enabled:
        request.app.state.exposure_monitor.kick()
