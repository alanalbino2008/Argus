"""A case as one self-contained HTML report (see :mod:`argus.reports.case_html`)."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

import anyio
from fastapi import APIRouter, Depends, Request, Response

from argus.api.case_routes import _case, _repo
from argus.api.deps import WorkspaceContext, audit, in_workspace
from argus.api.map_routes import _scans, _timeline
from argus.intel.relationships import analyse, entity_nodes, link_edges
from argus.reports.case_html import case_report_html
from argus.security.auth import Role

router = APIRouter(prefix="/api", tags=["cases"])
VIEWER = Depends(in_workspace(Role.VIEWER))


def _slug(title: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:60] or "case"


@router.get("/cases/{case_id}/report.html")
async def case_report(case_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """The case in one HTML file: summary, network chart, timeline, evidence (hashes, custody, integrity),
    scans and notes. Opens offline in any browser; loads nothing and runs no scripts.

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
    generated_at = datetime.now(timezone.utc)
    page = await anyio.to_thread.run_sync(
        lambda: case_report_html(
            case, items=items, captures=captures, network=network, timeline=timeline,
            scans=scans, by=ws.principal.name, generated_at=generated_at,
        )
    )  # fmt: skip
    data = page.encode()
    digest = hashlib.sha256(data).hexdigest()
    await audit(request, ws.principal, "case.report", case_id,
                details={"sha256": digest, "bytes": len(data), "captures": len(captures), "entries": len(timeline)})  # fmt: skip
    name = f"argus-case-{_slug(case['title'])}-{generated_at:%Y%m%d}.html"
    return Response(data, media_type="text/html; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="{name}"', "X-Argus-Report-SHA256": digest,
        "Cache-Control": "no-store", "Content-Security-Policy": "sandbox; default-src 'none'; style-src 'unsafe-inline'",
    })  # fmt: skip
