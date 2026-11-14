"""Scheduled reports: every replica runs this loop; each due schedule is claimed by one.

A run takes the most recent *completed* scan of the schedule's target (the monitors from
Phase 7 keep those fresh), issues the report through the same code path as the API, and
queues it to the chosen destinations in the same transaction. Email receives the PDF;
Slack, Teams and webhooks receive a summary with the fingerprint.

* **Unattended reports are always pseudonymised.** Naming people is a decision a person
  makes for a specific report, never something a timer does every week.
* **Skip unchanged** (default): if no new scan finished since the last report, nothing is
  sent, so recipients do not learn to ignore identical weekly emails.
* A failed run is recorded on the schedule and in the audit log, and the schedule moves
  on to its next slot instead of retrying in a tight loop.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from argus.core.settings import Settings
from argus.notify.render import report_event
from argus.observability import metrics
from argus.reports.data import ReportData, ReportOptions
from argus.reports.service import issue_report
from argus.security.auth import Principal, Role
from argus.storage.notification_repo import enqueue_to_channels
from argus.storage.report_repo import ReportRepository
from argus.storage.repository import InvestigationRepository
from argus.storage.schedule_repo import ScheduleRepository
from argus.storage.security_repo import AuditLog
from argus.storage.workspace_repo import WorkspaceRepository

logger = logging.getLogger("argus.reports.scheduler")
REPORT_SCHEDULER = Principal(key_id="report-scheduler", name="report scheduler", role=Role.ANALYST)
KEEP_FILES = timedelta(days=30)
PURGE_EVERY = 3600.0


class ReportScheduler:
    def __init__(
        self,
        schedules: ScheduleRepository,
        investigations: InvestigationRepository,
        reports: ReportRepository,
        workspaces: WorkspaceRepository,
        audit: AuditLog,
        settings: Settings,
    ):
        self.schedules = schedules
        self.investigations = investigations
        self.reports = reports
        self.workspaces = workspaces
        self.audit = audit
        self.settings = settings
        self._last_purge = 0.0

    async def tick(self) -> list[str]:
        """Run every due schedule this replica manages to claim; returns their outcomes."""
        outcomes: list[str] = []
        for schedule in await self.schedules.due():
            if not await self.schedules.claim(schedule["id"]):
                continue  # another replica took it
            outcomes.append(await self.run(schedule))  # one at a time: renders are CPU-heavy
        if time.monotonic() - self._last_purge > PURGE_EVERY:
            self._last_purge = time.monotonic()
            await self.reports.purge_files()
        return outcomes

    async def run_forever(self) -> None:
        while True:
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Report scheduler tick failed")
            await asyncio.sleep(self.settings.report_poll_seconds)

    async def _finish(self, schedule: dict[str, Any], outcome: str, message: str, **ids: Any) -> str:
        await self.schedules.record_result(schedule["id"], status=outcome, message=message, **ids)
        metrics.SCHEDULED_REPORT_RUNS.labels(outcome).inc()
        await self.audit.record(
            REPORT_SCHEDULER,
            "report.scheduled",
            schedule["id"],
            outcome="success" if outcome != "failed" else "error",
            details={"schedule": schedule["name"], "outcome": outcome, "message": message[:300], **ids},
            workspace_id=schedule["workspace_id"],
        )
        return outcome

    async def run(self, schedule: dict[str, Any]) -> str:
        ws_id, target = schedule["workspace_id"], schedule["target"]
        try:
            inv = await self.investigations.latest_completed(target, workspace_id=ws_id)
            if inv is None:
                return await self._finish(
                    schedule, "no_scan", f"No completed scan of {target} yet, so nothing was sent."
                )
            if schedule["skip_unchanged"] and inv.id == schedule.get("last_investigation_id"):
                return await self._finish(
                    schedule, "skipped_unchanged", f"No new scan of {target} since the last report; nothing was sent."
                )
            graph = await self.investigations.load_graph(inv.id)
            workspace = await self.workspaces.get(ws_id)
            if graph is None or workspace is None:
                return await self._finish(schedule, "failed", "The investigation or workspace no longer exists.")
            opts = schedule["options"] or {}
            options = ReportOptions(
                prepared_for=str(opts.get("prepared_for") or ""),
                tlp=opts.get("tlp") or "AMBER",
                include_inventory=bool(opts.get("include_inventory", True)),
                compare_previous=bool(opts.get("compare_previous", True)),
                include_personal_details=False,  # never for unattended reports
            )

            async def queue(session: AsyncSession, record: dict[str, Any], data: ReportData) -> int:
                event = report_event(record, data, schedule, workspace, self.settings.public_url)
                return await enqueue_to_channels(session, ws_id, schedule["channel_ids"], event)

            issued = await issue_report(
                investigations=self.investigations,
                reports=self.reports,
                investigation=inv,
                graph=graph,
                options=options,
                workspace=workspace,
                issued_by=f"schedule: {schedule['name']}"[:128],
                base_url=self.settings.public_url,
                trigger="scheduled",
                keep_file_for=KEEP_FILES,
                after_record=queue,
            )
            queued = issued.after or 0
            return await self._finish(
                schedule,
                "sent",
                f"Report {issued.data.report_id} queued to {queued} destination(s).",
                report_id=issued.data.report_id,
                investigation_id=inv.id,
            )
        except Exception as exc:
            logger.exception("Scheduled report %s failed", schedule["id"])
            return await self._finish(schedule, "failed", f"Report generation failed ({type(exc).__name__}).")
