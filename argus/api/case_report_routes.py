"""A case as one self-contained HTML report (see :mod:`argus.reports.case_html`)."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

import anyio
from fastapi import APIRouter, Depends, File, HTTPException, Request, Response, UploadFile

from argus.api.case_routes import _case, _repo
from argus.api.deps import WorkspaceContext, audit, in_workspace, throttle
from argus.api.map_routes import _scans, _timeline
from argus.intel.relationships import analyse, entity_nodes, link_edges
from argus.reports import signing
from argus.reports.case_html import case_report_html
from argus.security.auth import Role
from argus.security.ratelimit import SlidingWindowLimiter

router = APIRouter(prefix="/api", tags=["cases"])
VIEWER = Depends(in_workspace(Role.VIEWER))
MAX_VERIFY_BYTES = 16 * 1024 * 1024  # a case report with thousands of entries is a few MB
_verify_limiter = SlidingWindowLimiter(limit=30, window=60, name="case_report_verify")


async def report_signer(request: Request) -> signing.ReportSigner:
    state = request.app.state
    if getattr(state, "report_signer", None) is None:
        state.report_signer = await signing.signer_for(state.app_state, state.secret_box, state.settings)
    signer: signing.ReportSigner = state.report_signer
    return signer


def _slug(title: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:60] or "case"


@router.get("/cases/{case_id}/report.html")
async def case_report(case_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """The case in one HTML file: summary, the people researched (what was known and what was confirmed),
    network chart, timeline, evidence (hashes, custody, integrity), scans and notes. Opens offline in any browser; loads nothing and runs no scripts.

    Its SHA-256 is returned in ``X-Argus-Report-SHA256`` and recorded in the audit log, so a copy
    handed over can later be shown to be the one Argus produced.
    """
    case = await _case(request, ws, case_id)
    repo = _repo(request)
    items = await repo.items(case_id)
    nodes = entity_nodes(items)
    edges = link_edges(items, nodes)
    network = {"nodes": list(nodes.values()), "edges": edges, "analysis": analyse(nodes, edges)}
    captures = []
    for c in await repo.captures(case_id):
        await repo.log(
            c["id"], by=ws.principal.name, action="reported", detail=f"listed in the report of case {case_id}"
        )
        captures.append({**c, "custody": await repo.custody(c["id"]), "integrity": await repo.verify(c["id"])})
    timeline = await _timeline(request, case_id, facts=True)
    scans = await _scans(request, items)
    subjects = request.app.state.subjects
    people = [p for p in [await subjects.get(s["id"], case_id) for s in await subjects.for_case(case_id)] if p]
    generated_at = datetime.now(timezone.utc)
    signer = await report_signer(request)
    page = await anyio.to_thread.run_sync(
        lambda: case_report_html(
            case, items=items, captures=captures, network=network, timeline=timeline,
            scans=scans, by=ws.principal.name, generated_at=generated_at,
            signing={"tags": signer.tags(), "key_id": signer.key_id}, people=people,
        )
    )  # fmt: skip
    data = signer.sign(page).encode()
    digest = hashlib.sha256(data).hexdigest()
    await audit(request, ws.principal, "case.report", case_id,
                details={"sha256": digest, "bytes": len(data), "key_id": signer.key_id, "captures": len(captures), "entries": len(timeline)})  # fmt: skip
    name = f"argus-case-{_slug(case['title'])}-{generated_at:%Y%m%d}.html"
    return Response(data, media_type="text/html; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="{name}"', "X-Argus-Report-SHA256": digest,
        "X-Argus-Report-Key": signer.key_id,
        "Cache-Control": "no-store", "Content-Security-Policy": "sandbox; default-src 'none'; style-src 'unsafe-inline'",
    })  # fmt: skip


@router.get("/report-signing-key")
async def report_signing_key(request: Request):
    """The public key that signs this server's case reports, and its id. Public: a report's recipient
    (who may have no account) compares the id in the report with this one."""
    return (await report_signer(request)).info()


@router.post("/reports/verify")
async def verify_signed_report(request: Request, file: UploadFile = File(...), ws: WorkspaceContext = VIEWER):
    """Check a case report: unaltered since it was signed (``valid``), and signed by this server (``trusted``)."""
    await throttle(_verify_limiter, ws.principal.key_id, "Too many verifications; wait a minute")
    data = await file.read(MAX_VERIFY_BYTES + 1)
    if len(data) > MAX_VERIFY_BYTES:
        raise HTTPException(status_code=413, detail="That file is larger than any Argus report")
    signer = await report_signer(request)
    result = signing.verify(data, trusted_key=signer.public_key)
    await audit(request, ws.principal, "report.verify", None,
                details={"valid": result["valid"], "trusted": result["trusted"], "sha256": result["sha256"]})  # fmt: skip
    return {**result, "this_server_key_id": signer.key_id}
