"""Retention: a workspace's old investigations, resolved alerts and closed cases are deleted on schedule (Phase 91).

Keeping intelligence forever is a liability: GDPR's storage limitation, client contracts and internal
policy all ask for data to be deleted once it is no longer needed. Each workspace chooses how long
to keep (0 = forever, the default, so nothing changes until someone decides):

* **investigations**: completed, failed or cancelled scans older than the period, by when they
  finished. Kept regardless: the latest scan of each target (monitoring compares against it), any
  scan a monitor or fingerprint watch points to, any scan attached to a case, any scan an open alert
  points to, and anything still running;
* **alerts**: resolved or false-positive alerts, by when they were closed. Open ones are never
  deleted;
* **cases**: closed or archived cases not touched for the period, **unless they are on legal
  hold**. Open cases are never deleted.

Nothing is purged from the audit log: its hash chain stays complete and verifiable, and each purge
adds an entry with what was removed. A dry run (``plan``) shows what would go before anything does.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import delete, select

from argus.storage.db import (
    AlertRow,
    CaseItemRow,
    CaseRow,
    FingerprintWatchRow,
    InvestigationRow,
    MonitorRow,
    RetentionPolicyRow,
)

logger = logging.getLogger("argus.retention")
POLL_SECONDS = 6 * 3600
LOCK = 0x4152_4755_5245_5431  # "ARGUSRET1": one replica purges at a time
FINISHED = ("completed", "failed", "cancelled")
CLOSED_ALERTS = ("resolved", "false_positive")
CLOSED_CASES = ("closed", "archived")
MIN_DAYS = 7  # a non-zero period shorter than a week is almost certainly a mistake


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    return value if value is None or value.tzinfo else value.replace(tzinfo=timezone.utc)


def _view(row: RetentionPolicyRow | None) -> dict[str, Any]:
    if row is None:
        return {"investigations_days": 0, "alerts_days": 0, "cases_days": 0, "updated_at": None, "updated_by": None,
                "last_run_at": None, "last_result": None}  # fmt: skip
    return {
        "investigations_days": row.investigations_days, "alerts_days": row.alerts_days, "cases_days": row.cases_days,
        "updated_at": _aware(row.updated_at).isoformat() if row.updated_at else None,  # type: ignore[union-attr]
        "updated_by": row.updated_by,
        "last_run_at": _aware(row.last_run_at).isoformat() if row.last_run_at else None,  # type: ignore[union-attr]
        "last_result": row.last_result,
    }  # fmt: skip


class Retention:
    def __init__(self, app: Any):
        self.app = app
        self.db = app.state.db

    async def policy(self, workspace_id: str) -> dict[str, Any]:
        async with self.db.session() as s:
            return _view(await s.get(RetentionPolicyRow, workspace_id))

    async def set_policy(self, workspace_id: str, *, by: str, **days: int) -> dict[str, Any]:
        async with self.db.session() as s, s.begin():
            row = await s.get(RetentionPolicyRow, workspace_id)
            if row is None:
                row = RetentionPolicyRow(workspace_id=workspace_id, investigations_days=0, alerts_days=0, cases_days=0,
                                         updated_at=_now(), updated_by=by)  # fmt: skip
                s.add(row)
            for key, value in days.items():
                setattr(row, key, value)
            row.updated_at, row.updated_by = _now(), by
        return await self.policy(workspace_id)

    # ------------------------------------------------------------------ what would go
    async def plan(self, workspace_id: str, now: datetime | None = None) -> dict[str, Any]:
        """What a purge would delete now: ids by kind, and how many were kept back and why."""
        now = now or _now()
        policy = await self.policy(workspace_id)
        out: dict[str, Any] = {"investigations": [], "alerts": [], "cases": [], "kept": {}}
        async with self.db.session() as s:
            cases = (await s.execute(select(CaseRow.id, CaseRow.status, CaseRow.updated_at, CaseRow.legal_hold)
                                     .where(CaseRow.workspace_id == workspace_id))).all()  # fmt: skip
            if policy["cases_days"]:
                cutoff = now - timedelta(days=policy["cases_days"])
                old = [c for c in cases if c.status in CLOSED_CASES and (_aware(c.updated_at) or now) < cutoff]
                out["cases"] = [c.id for c in old if not c.legal_hold]
                out["kept"]["cases_on_legal_hold"] = sum(1 for c in old if c.legal_hold)
            if policy["alerts_days"]:
                cutoff = now - timedelta(days=policy["alerts_days"])
                rows = (await s.execute(select(AlertRow.id, AlertRow.resolved_at, AlertRow.created_at).where(
                    AlertRow.workspace_id == workspace_id, AlertRow.status.in_(CLOSED_ALERTS)))).all()  # fmt: skip
                out["alerts"] = [r.id for r in rows if (_aware(r.resolved_at) or _aware(r.created_at) or now) < cutoff]
            if policy["investigations_days"]:
                out["investigations"], out["kept"]["investigations_in_use"] = await self._old_investigations(
                    s,
                    workspace_id,
                    now - timedelta(days=policy["investigations_days"]),
                    {c.id for c in cases} - set(out["cases"]),
                )
        out["counts"] = {k: len(out[k]) for k in ("investigations", "alerts", "cases")}
        return out

    async def _old_investigations(
        self, s: Any, workspace_id: str, cutoff: datetime, remaining_cases: set[str]
    ) -> tuple[list[str], int]:
        rows = (await s.execute(select(InvestigationRow.id, InvestigationRow.target, InvestigationRow.status,
                                       InvestigationRow.completed_at, InvestigationRow.created_at)
                                .where(InvestigationRow.workspace_id == workspace_id))).all()  # fmt: skip
        keep: set[str] = set()
        latest: dict[str, tuple[datetime, str]] = {}
        for r in rows:
            moment = _aware(r.completed_at) or _aware(r.created_at) or cutoff
            if r.status in FINISHED and (r.target not in latest or moment > latest[r.target][0]):
                latest[r.target] = (moment, r.id)
        keep |= {inv_id for _, inv_id in latest.values()}
        keep |= {i for (i,) in (await s.execute(select(MonitorRow.last_investigation_id).where(
            MonitorRow.workspace_id == workspace_id))).all() if i}  # fmt: skip
        keep |= {i for (i,) in (await s.execute(select(FingerprintWatchRow.investigation_id).where(
            FingerprintWatchRow.workspace_id == workspace_id))).all() if i}  # fmt: skip
        open_alerts = (await s.execute(select(AlertRow.investigation_id, AlertRow.previous_investigation_id).where(
            AlertRow.workspace_id == workspace_id, AlertRow.status.not_in(CLOSED_ALERTS)))).all()  # fmt: skip
        keep |= {i for pair in open_alerts for i in pair if i}
        if remaining_cases:
            items = (await s.scalars(select(CaseItemRow).where(CaseItemRow.case_id.in_(remaining_cases),
                                                               CaseItemRow.kind == "scan"))).all()  # fmt: skip
            keep |= {str((item.data or {}).get("investigation_id") or "") for item in items}
        old = [
            r
            for r in rows
            if r.status in FINISHED and (_aware(r.completed_at) or _aware(r.created_at) or cutoff) < cutoff
        ]
        return [r.id for r in old if r.id not in keep], sum(1 for r in old if r.id in keep)

    # ------------------------------------------------------------------ purge
    async def purge(self, workspace_id: str, *, by: Any = None) -> dict[str, Any]:
        """Delete what :meth:`plan` lists, record the result, and add one audit entry."""
        from argus.api.scheduler import SCHEDULER

        plan = await self.plan(workspace_id)
        repo = self.app.state.repo
        for inv_id in plan["investigations"]:
            await repo.delete_investigation(inv_id)
        async with self.db.session() as s, s.begin():
            if plan["alerts"]:
                await s.execute(
                    delete(AlertRow).where(AlertRow.id.in_(plan["alerts"]), AlertRow.workspace_id == workspace_id)
                )
            for case_id in plan["cases"]:
                row = await s.get(CaseRow, case_id)
                if row is not None and row.workspace_id == workspace_id and not row.legal_hold:  # re-checked here
                    await s.delete(row)
            policy = await s.get(RetentionPolicyRow, workspace_id)
            result = {**plan["counts"], "kept": plan["kept"], "at": _now().isoformat()}
            if policy is not None:
                policy.last_run_at, policy.last_result = _now(), result
        if any(plan["counts"].values()):
            await self.app.state.audit.record(by or SCHEDULER, "retention.purge", workspace_id,
                                              details={**plan["counts"], "kept": plan["kept"]},
                                              workspace_id=workspace_id)  # fmt: skip
            logger.info("Retention purge in %s: %s", workspace_id, plan["counts"])
        return result

    async def purge_all(self) -> dict[str, dict[str, Any]]:
        async with self.db.session() as s:
            ids = [w for (w,) in (await s.execute(select(RetentionPolicyRow.workspace_id))).all()]
        results = {}
        async with self.db.cluster_lock(LOCK):
            for workspace_id in ids:
                results[workspace_id] = await self.purge(workspace_id)
        return results

    async def run_forever(self, poll_seconds: float = POLL_SECONDS) -> None:
        while True:
            try:
                await self.purge_all()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Retention purge failed")
            await asyncio.sleep(poll_seconds)
