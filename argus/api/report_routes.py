"""Report branding, the registry of issued reports, and public verification.

Generating a report lives next to the other investigation endpoints in ``server.py`` (it
shares their tenant checks). Verification is deliberately **public**: the person who must
check a report is usually the client who received it, not an Argus user. It reveals
nothing to anyone who does not already hold the exact file: the SHA-256 of the PDF is the
lookup key, and 2^256 possible values cannot be guessed or enumerated.
"""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from argus.api.deps import WorkspaceContext, audit, client_ip, in_workspace
from argus.observability import metrics
from argus.reports.branding import BrandingError, check_accent, decode_data_url, sanitise_logo
from argus.security.auth import Role
from argus.security.ratelimit import SlidingWindowLimiter
from argus.storage.report_repo import ReportRepository

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
    return await _repo(request).branding_public(ws.id, default_org=ws.workspace.get("name") or "Argus")


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
    return await repo.branding_public(ws.id, default_org=ws.workspace.get("name") or "Argus")


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
