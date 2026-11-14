"""Issue a report: the one code path shared by the API (on demand) and the scheduler.

Rendering is CPU-bound, so it runs in a worker thread. The registry record, the stored
file (scheduled reports only) and the queued deliveries are written in **one transaction**:
a report is never registered without its deliveries, nor delivered without being registered.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import anyio
from sqlalchemy.ext.asyncio import AsyncSession

from argus import __version__
from argus.core.graph import IntelligenceGraph
from argus.core.models import Investigation
from argus.observability import metrics
from argus.reports.data import ReportData, ReportOptions, build_report_data
from argus.reports.pdf import render_pdf
from argus.storage.report_repo import ReportRepository
from argus.storage.repository import InvestigationRepository

# Runs inside the registry transaction with the report record and its rendered content.
AfterRecord = Callable[[AsyncSession, dict[str, Any], ReportData], Awaitable[Any]]


@dataclass
class IssuedReport:
    data: ReportData
    pdf: bytes
    sha256: str
    filename: str
    record: dict[str, Any]
    after: Any = None


def default_issuer(workspace: dict[str, Any]) -> str:
    """Who reports say they are from until branding is set: the team's name, or "Argus" for Default."""
    return "Argus" if workspace.get("default") or not workspace.get("name") else str(workspace["name"])


def report_filename(target: str, data: ReportData) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", target.lower()).strip("-")[:60] or "target"
    return f"argus-report-{slug}-{data.generated_at:%Y%m%d}-{data.report_id}.pdf"


async def issue_report(
    *,
    investigations: InvestigationRepository,
    reports: ReportRepository,
    investigation: Investigation,
    graph: IntelligenceGraph,
    options: ReportOptions,
    workspace: dict[str, Any],
    issued_by: str,
    base_url: str | None,
    trigger: str = "manual",
    keep_file_for: timedelta | None = None,
    after_record: AfterRecord | None = None,
) -> IssuedReport:
    previous = None
    if options.compare_previous and (earlier := await investigations.find_previous(investigation)) is not None:
        earlier_graph = await investigations.load_graph(earlier.id)
        previous = (earlier, earlier_graph) if earlier_graph is not None else None
    branding = await reports.branding(workspace["id"], default_org=default_issuer(workspace))
    verify_url = f"{base_url.rstrip('/')}/api/reports/verify/<sha256>" if base_url else None

    def render() -> tuple[ReportData, bytes]:
        data = build_report_data(
            investigation, graph, options, branding, previous=previous, generator=f"Argus {__version__}"
        )
        return data, render_pdf(data, verify_url=verify_url)

    data, pdf = await anyio.to_thread.run_sync(render)
    digest = hashlib.sha256(pdf).hexdigest()
    filename = report_filename(investigation.config.target, data)
    record, after = await reports.record(
        fields={
            "id": data.report_id,
            "workspace_id": workspace["id"],
            "investigation_id": investigation.id,
            "target": investigation.config.target[:512],
            "sha256": digest,
            "size": len(pdf),
            "tlp": options.tlp,
            "prepared_for": options.prepared_for or None,
            "issued_by_org": branding.organisation,
            "created_by": issued_by,
        },
        file=(filename, pdf, keep_file_for) if keep_file_for else None,
        after_record=(lambda session, record: after_record(session, record, data)) if after_record else None,
    )
    metrics.REPORTS_GENERATED.labels(trigger).inc()
    return IssuedReport(data, pdf, digest, filename, record, after)
