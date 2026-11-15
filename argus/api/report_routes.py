"""Report branding, the registry of issued reports, and public verification.

Generating a report lives next to the other investigation endpoints in ``server.py`` (it
shares their tenant checks). Verification is deliberately **public**: the person who must
check a report is usually the client who received it, not an Argus user. It reveals
nothing to anyone who does not already hold the exact file: the SHA-256 of the PDF is the
lookup key, and 2^256 possible values cannot be guessed or enumerated.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from argus.api.deps import WorkspaceContext, audit, client_ip, in_workspace
from argus.api.executive_service import BOARD_TARGET
from argus.notify.channels import TICKETING
from argus.observability import metrics
from argus.reports.branding import BrandingError, check_accent, decode_data_url, sanitise_logo
from argus.reports.schedule import ScheduleError
from argus.reports.schedule import validate as validate_schedule
from argus.reports.service import default_issuer
from argus.security.auth import Role
from argus.security.ratelimit import SlidingWindowLimiter
from argus.storage.report_repo import ReportRepository
from argus.storage.schedule_repo import ScheduleRepository

router = APIRouter(prefix="/api/reports", tags=["reports"])
VIEWER = Depends(in_workspace(Role.VIEWER))
ADMIN = Depends(in_workspace(Role.ADMIN))
SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_verify_limiter = SlidingWindowLimiter(limit=60, window=60)  # per client IP


class BrandingRequest(BaseModel):
    organisation: str = Field(min_length=1, max_length=128)
    accent: str = Field(default="#4f46e5", max_length=7)
    footer_note: str = Field(default="", max_length=200)
    logo: str | None = Field(default=None, description="data:image/png;base64,... ; '' removes the logo; omit to keep")


def _repo(request: Request) -> ReportRepository:
    repo: ReportRepository = request.app.state.reports
    return repo


@router.get("")
async def list_reports(
    request: Request,
    ws: WorkspaceContext = VIEWER,
    investigation_id: str | None = Query(None, max_length=64),
    limit: int = Query(50, ge=1, le=200),
):
    return await _repo(request).list_reports(workspace_id=ws.id, investigation_id=investigation_id, limit=limit)


@router.get("/branding")
async def get_branding(request: Request, ws: WorkspaceContext = VIEWER):
    return await _repo(request).branding_public(ws.id, default_org=default_issuer(ws.workspace))


@router.put("/branding")
async def set_branding(body: BrandingRequest, request: Request, ws: WorkspaceContext = ADMIN):
    repo = _repo(request)
    try:
        accent = check_accent(body.accent)
        logo = repo.KEEP
        if body.logo == "":
            logo = None
        elif body.logo is not None:
            logo = sanitise_logo(decode_data_url(body.logo))
    except BrandingError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    await repo.set_branding(
        ws.id,
        organisation=body.organisation.strip(),
        accent=accent,
        footer_note=body.footer_note.strip(),
        logo_png=logo,
        by=ws.principal.name,
    )
    changes = {"organisation": body.organisation.strip(), "accent": accent}
    if logo is not repo.KEEP:
        changes["logo"] = "removed" if logo is None else "replaced"
    await audit(request, ws.principal, "report.branding_update", ws.id, details=changes)
    return await repo.branding_public(ws.id, default_org=default_issuer(ws.workspace))


@router.get("/branding/logo")
async def get_logo(request: Request, ws: WorkspaceContext = VIEWER):
    logo = await _repo(request).logo(ws.id)
    if not logo:
        raise HTTPException(status_code=404, detail="No logo")
    return Response(logo, media_type="image/png", headers={"Cache-Control": "private, no-cache"})


@router.get("/verify/{sha256}")
async def verify_report(sha256: str, request: Request):
    """Public: is this file a genuine, unmodified report issued by this Argus?"""
    if not _verify_limiter.hit(client_ip(request) or "unknown"):
        metrics.RATE_LIMITED.labels("report_verify").inc()
        raise HTTPException(status_code=429, detail="Too many verification requests")
    if not SHA256.match(sha256):
        raise HTTPException(status_code=422, detail="Expected the 64-character SHA-256 of the PDF")
    report = await _repo(request).find_by_sha256(sha256)
    if report is None:
        raise HTTPException(
            status_code=404,
            detail="No report with this fingerprint was issued here: the file was modified or did not come from this Argus",
        )
    return {
        "genuine": True,
        "report_id": report["id"],
        "issued_by": report["issued_by_org"],
        "issued_at": report["created_at"],
        "target": report["target"],
        "prepared_for": report["prepared_for"],
        "classification": f"TLP:{report['tlp']}",
    }


# ---------------------------------------------------------------------------- scheduled reports
class ScheduleOptions(BaseModel):
    kind: Literal["assessment", "board"] = Field(
        default="assessment", description="assessment: one target's report; board: the workspace's board report"
    )
    period_days: Literal[30, 90, 180] = Field(default=90, description="Board reports: the period covered")
    prepared_for: str = Field(default="", max_length=200)
    tlp: Literal["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"] = "AMBER"
    include_inventory: bool = True
    compare_previous: bool = True


class ScheduleRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    target: str = Field(default="", max_length=253, description="The target (assessment reports only)")
    frequency: Literal["weekly", "monthly"] = "weekly"
    weekday: int | None = Field(default=0, ge=0, le=6)
    day_of_month: int | None = Field(default=None, ge=1, le=28)
    hour: int = Field(default=8, ge=0, le=23)
    minute: int = Field(default=0, ge=0, le=59)
    timezone: str = Field(default="UTC", max_length=64)
    channel_ids: list[str] = Field(min_length=1, max_length=10)
    skip_unchanged: bool = True
    enabled: bool = True
    options: ScheduleOptions = ScheduleOptions()


class ScheduleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    frequency: Literal["weekly", "monthly"] | None = None
    weekday: int | None = Field(default=None, ge=0, le=6)
    day_of_month: int | None = Field(default=None, ge=1, le=28)
    hour: int | None = Field(default=None, ge=0, le=23)
    minute: int | None = Field(default=None, ge=0, le=59)
    timezone: str | None = Field(default=None, max_length=64)
    channel_ids: list[str] | None = Field(default=None, min_length=1, max_length=10)
    skip_unchanged: bool | None = None
    enabled: bool | None = None
    options: ScheduleOptions | None = None


def _schedules(request: Request) -> ScheduleRepository:
    repo: ScheduleRepository = request.app.state.schedules
    return repo


async def _check_channels(request: Request, workspace_id: str, channel_ids: list[str]) -> None:
    """Destinations must exist in *this* workspace (a foreign id is treated as unknown)."""
    for channel_id in dict.fromkeys(channel_ids):
        channel = await request.app.state.notifications.get_channel(channel_id, workspace_id=workspace_id)
        if channel is None:
            raise HTTPException(status_code=422, detail=f"Unknown destination {channel_id}")
        if channel["type"] in TICKETING:
            raise HTTPException(
                status_code=422, detail=f"{channel['name']} creates tickets for alerts; it cannot receive reports"
            )


def _check_timing(values: dict[str, Any]) -> None:
    try:
        validate_schedule(
            values["frequency"], values.get("weekday"), values.get("day_of_month"), values["hour"], values["minute"],
            values["timezone"],
        )  # fmt: skip
    except ScheduleError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/schedules")
async def list_schedules(request: Request, ws: WorkspaceContext = ADMIN):
    return await _schedules(request).list_schedules(workspace_id=ws.id)


@router.post("/schedules", status_code=201)
async def create_schedule(body: ScheduleRequest, request: Request, ws: WorkspaceContext = ADMIN):
    values = body.model_dump()
    if body.frequency == "weekly":
        values["day_of_month"] = None
    else:
        values["weekday"] = None
    _check_timing(values)
    await _check_channels(request, ws.id, body.channel_ids)
    board = body.options.kind == "board"
    if not board and not body.target.strip():
        raise HTTPException(status_code=422, detail="Choose the target this report is about")
    values["target"] = BOARD_TARGET if board else body.target.strip()
    values["name"] = body.name.strip()
    values["channel_ids"] = list(dict.fromkeys(body.channel_ids))
    schedule = await _schedules(request).create(workspace_id=ws.id, by=ws.principal.name, **values)
    latest = None if board else await request.app.state.repo.latest_completed(schedule["target"], workspace_id=ws.id)
    schedule["has_scan"] = board or latest is not None
    await audit(
        request, ws.principal, "report.schedule_create", schedule["id"],
        details={"name": schedule["name"], "target": schedule["target"], "when": schedule["description"],
                 "destinations": schedule["channel_ids"]},
    )  # fmt: skip
    return schedule


@router.patch("/schedules/{schedule_id}")
async def update_schedule(schedule_id: str, body: ScheduleUpdate, request: Request, ws: WorkspaceContext = ADMIN):
    repo = _schedules(request)
    current = await repo.get(schedule_id, workspace_id=ws.id)
    if current is None:
        raise HTTPException(status_code=404, detail="Schedule not found")
    changes = body.model_dump(exclude_unset=True)
    if "options" in changes and changes["options"] is not None:
        changes["options"] = body.options.model_dump() if body.options else None
    merged = {**current, **{k: v for k, v in changes.items() if v is not None}}
    if merged["frequency"] == "weekly":
        merged["day_of_month"] = changes["day_of_month"] = None
    else:
        merged["weekday"] = changes["weekday"] = None
    _check_timing(merged)
    if changes.get("channel_ids"):
        await _check_channels(request, ws.id, changes["channel_ids"])
    changes = {k: v for k, v in changes.items() if v is not None or k in ("weekday", "day_of_month")}
    updated = await repo.update(schedule_id, workspace_id=ws.id, **changes)
    await audit(
        request,
        ws.principal,
        "report.schedule_update",
        schedule_id,
        details={k: str(v)[:200] for k, v in changes.items()},
    )
    return updated


@router.delete("/schedules/{schedule_id}", status_code=204)
async def delete_schedule(schedule_id: str, request: Request, ws: WorkspaceContext = ADMIN):
    if not await _schedules(request).delete(schedule_id, workspace_id=ws.id):
        raise HTTPException(status_code=404, detail="Schedule not found")
    await audit(request, ws.principal, "report.schedule_delete", schedule_id)
    return Response(status_code=204)


@router.post("/schedules/{schedule_id}/run", status_code=202)
async def run_schedule_now(schedule_id: str, request: Request, ws: WorkspaceContext = ADMIN):
    """Run on the next scheduler tick (on any replica), then continue with the normal schedule."""
    schedule = await _schedules(request).run_now(schedule_id, workspace_id=ws.id)
    if schedule is None:
        raise HTTPException(status_code=404, detail="Schedule not found")
    await audit(request, ws.principal, "report.schedule_run", schedule_id)
    return schedule


@router.get("/{report_id}/file")
async def download_report_file(report_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """The stored PDF of a scheduled report (kept 30 days)."""
    stored = await _repo(request).file(report_id, workspace_id=ws.id)
    if stored is None:
        raise HTTPException(status_code=404, detail="No stored file for this report (expired, or generated on demand)")
    filename, pdf = stored
    await audit(request, ws.principal, "report.download", report_id)
    return Response(
        pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"},
    )
