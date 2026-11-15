"""Compliance mapping: Argus's evidence against Cyber Essentials, ISO 27001, NIST CSF 2.0 and DORA."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from argus import __version__
from argus.api.compliance_service import evidence_context
from argus.api.deps import WorkspaceContext, audit, in_workspace
from argus.intel.compliance import BY_ID, DISCLAIMER, FRAMEWORKS, assess_framework
from argus.security.auth import Role

router = APIRouter(prefix="/api/compliance", tags=["compliance"])
VIEWER = Depends(in_workspace(Role.VIEWER))
STATUS_LABEL = {"met": "Met", "partial": "Partially met", "gap": "Gap", "not_assessed": "Not assessed"}


async def _assess(request: Request, ws: WorkspaceContext) -> tuple[datetime, list[dict[str, Any]]]:
    now = datetime.now(timezone.utc)
    ctx = await evidence_context(request.app, ws.id)
    return now, [assess_framework(f, ctx, now) for f in FRAMEWORKS]


@router.get("")
async def compliance(request: Request, ws: WorkspaceContext = VIEWER):
    """Every framework: counts by status, and each control with its reasons, evidence and gaps."""
    now, frameworks = await _assess(request, ws)
    return {"generated_at": now.isoformat(), "disclaimer": DISCLAIMER, "frameworks": frameworks}


@router.get("/{framework_id}/export.csv")
async def export_framework_csv(framework_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """One framework as a spreadsheet: for audit preparation or a statement of applicability."""
    if framework_id not in BY_ID:
        raise HTTPException(status_code=404, detail="Unknown framework")
    now, frameworks = await _assess(request, ws)
    fw = next(f for f in frameworks if f["id"] == framework_id)
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Control", "Title", "Status", "Coverage", "Why", "Evidence", "Findings", "Untracked findings"])
    for c in fw["controls"]:
        writer.writerow([
            c["ref"], c["title"], STATUS_LABEL[c["status"]], c["coverage"], " · ".join(c["reasons"]),
            " · ".join(f"{e['label']}: {e['detail']}" for e in c["evidence"]),
            " · ".join(f"[{g['severity']}] {g['title']} ({g['target']})" for g in c["gaps"]),
            sum(1 for g in c["gaps"] if not g.get("task")),
        ])  # fmt: skip
    writer.writerow([])
    writer.writerow([f"Generated {now:%Y-%m-%d %H:%M} UTC by Argus {__version__}. {DISCLAIMER}"])
    await audit(request, ws.principal, "compliance.export", framework_id, details={"format": "csv", **fw["counts"]})
    return Response(out.getvalue(), media_type="text/csv", headers={
        "Content-Disposition": f'attachment; filename="argus-{framework_id}-{now:%Y%m%d}.csv"'})  # fmt: skip


@router.get("/evidence.json")
async def evidence_pack(request: Request, ws: WorkspaceContext = VIEWER):
    """Every framework with its evidence, as one machine-readable pack (e.g. for a GRC tool)."""
    now, frameworks = await _assess(request, ws)
    pack = {"generated_at": now.isoformat(), "generator": f"Argus {__version__}",
            "workspace": {"id": ws.id, "name": ws.workspace.get("name")}, "disclaimer": DISCLAIMER,
            "frameworks": frameworks}  # fmt: skip
    await audit(request, ws.principal, "compliance.export", None, details={"format": "json"})
    return Response(json.dumps(pack, indent=2), media_type="application/json", headers={
        "Content-Disposition": f'attachment; filename="argus-compliance-evidence-{now:%Y%m%d}.json"'})  # fmt: skip
