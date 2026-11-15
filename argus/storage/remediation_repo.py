"""Remediation tasks, their timeline and each workspace's policy.

Every change to a task writes a timeline event in the same transaction, so the history of who
did what, when and why cannot drift from the task's state. Overdue alerts claim their tasks with
a conditional UPDATE, so several replicas never announce the same task twice. The claim and the
alert (with its notifications) commit together.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any, cast

from sqlalchemy import select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from argus.intel.remediation import ACTIVE, AUTO_CREATE, CLOSED, DEFAULT_SLA_DAYS, due_date, verification
from argus.storage.db import AlertRow, Database, RemediationEventRow, RemediationPolicyRow, RemediationTaskRow
from argus.storage.notification_repo import enqueue_alert

EDITABLE = ("title", "description", "severity", "assignee", "due_at", "external_ref", "accepted_until")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value: datetime | None) -> str | None:
    moment = _utc(value)
    return moment.isoformat() if moment else None


def _task(row: RemediationTaskRow, now: datetime | None = None) -> dict[str, Any]:
    moment = now or _now()
    due = _utc(row.due_at)
    return {
        "id": row.id,
        "workspace_id": row.workspace_id,
        "source_type": row.source_type,
        "source_key": row.source_key,
        "target": row.target,
        "title": row.title,
        "description": row.description,
        "severity": row.severity,
        "status": row.status,
        "assignee": row.assignee,
        "due_at": _iso(row.due_at),
        "overdue": bool(due and row.status in ACTIVE and due < moment),
        "accepted_until": _iso(row.accepted_until),
        "external_ref": row.external_ref,
        "details": row.details or {},
        "reopen_count": row.reopen_count or 0,
        "verified_by": row.verified_by,
        "created_at": _iso(row.created_at),
        "created_by": row.created_by,
        "updated_at": _iso(row.updated_at),
        "closed_at": _iso(row.closed_at),
    }


def _event(row: RemediationEventRow) -> dict[str, Any]:
    return {"id": row.id, "at": _iso(row.at), "by": row.by, "kind": row.kind, "text": row.text,
            "details": row.details or {}}  # fmt: skip


def _log(s: AsyncSession, task_id: str, by: str, kind: str, text: str = "", **details: Any) -> None:
    s.add(RemediationEventRow(id=f"rev_{secrets.token_hex(8)}", task_id=task_id, at=_now(), by=by[:128], kind=kind,
                              text=text[:2000], details=details or None))  # fmt: skip


def _close(row: RemediationTaskRow, status: str, moment: datetime) -> None:
    previous = row.status
    row.status, row.updated_at = status, moment
    if status in CLOSED:
        row.closed_at = moment
    else:
        row.closed_at = None
        row.overdue_alerted_at = None  # a reopened task can be announced as overdue again
        if previous == "verified":
            row.reopen_count = (row.reopen_count or 0) + 1
    if status != "accepted":
        row.accepted_until = None
    if status != "verified":
        row.verified_by = None


class RemediationRepository:
    def __init__(self, db: Database):
        self.db = db

    # ------------------------------------------------------------------ policy
    async def policy(self, *, workspace_id: str) -> dict[str, Any]:
        async with self.db.session() as s:
            row = await s.get(RemediationPolicyRow, workspace_id)
        if row is None:
            return {"sla_days": dict(DEFAULT_SLA_DAYS), "auto_create": "off", "updated_at": None, "updated_by": None}
        return {"sla_days": {**DEFAULT_SLA_DAYS, **(row.sla_days or {})}, "auto_create": row.auto_create,
                "updated_at": _iso(row.updated_at), "updated_by": row.updated_by}  # fmt: skip

    async def set_policy(
        self, *, workspace_id: str, sla_days: dict[str, int], auto_create: str, by: str
    ) -> dict[str, Any]:
        if auto_create not in AUTO_CREATE:
            raise ValueError(f"auto_create must be one of {AUTO_CREATE}")
        async with self.db.session() as s, s.begin():
            row = await s.get(RemediationPolicyRow, workspace_id)
            if row is None:
                row = RemediationPolicyRow(workspace_id=workspace_id)
                s.add(row)
            row.sla_days, row.auto_create, row.updated_at, row.updated_by = sla_days, auto_create, _now(), by
        return await self.policy(workspace_id=workspace_id)

    # ------------------------------------------------------------------ tasks
    async def create(
        self,
        *,
        workspace_id: str,
        by: str,
        fields: dict[str, Any],
        assignee: str | None = None,
        due_at: datetime | None = None,
        external_ref: str | None = None,
        note: str = "",
    ) -> tuple[dict[str, Any], bool]:
        """(task, created). A finding already tracked returns its existing task (one task per finding)."""
        if fields.get("source_key"):
            existing = await self.by_source(workspace_id, fields["source_type"], fields["source_key"])
            if existing:
                return existing, False
        policy = await self.policy(workspace_id=workspace_id)
        moment = _now()
        row = RemediationTaskRow(
            id=f"rem_{secrets.token_hex(8)}", workspace_id=workspace_id, status="open", assignee=assignee or None,
            due_at=due_at or due_date(fields["severity"], moment, policy["sla_days"]), external_ref=external_ref or None,
            reopen_count=0, created_at=moment, created_by=by, updated_at=moment,
            **{k: fields[k] for k in ("source_type", "source_key", "target", "title", "description", "severity")
               if k in fields},
            details=fields.get("details") or {},
        )  # fmt: skip
        try:
            async with self.db.session() as s, s.begin():
                s.add(row)
                await s.flush()
                _log(s, row.id, by, "created", note or f"Created from {row.source_type.replace('_', ' ')}",
                     due_at=_iso(row.due_at), assignee=row.assignee)  # fmt: skip
        except IntegrityError:  # created concurrently by someone else
            existing = await self.by_source(workspace_id, fields["source_type"], fields.get("source_key"))
            if existing:
                return existing, False
            raise
        return _task(row), True

    async def by_source(self, workspace_id: str, source_type: str, source_key: str | None) -> dict[str, Any] | None:
        if not source_key:
            return None
        async with self.db.session() as s:
            row = await s.scalar(select(RemediationTaskRow).where(
                RemediationTaskRow.workspace_id == workspace_id, RemediationTaskRow.source_type == source_type,
                RemediationTaskRow.source_key == source_key))  # fmt: skip
        return _task(row) if row else None

    async def sources(self, *, workspace_id: str, source_type: str) -> dict[str, dict[str, Any]]:
        """``{source_key: {"id", "status"}}``, so pages can show which findings are already tracked."""
        async with self.db.session() as s:
            rows = (await s.execute(select(RemediationTaskRow.source_key, RemediationTaskRow.id, RemediationTaskRow.status)
                                    .where(RemediationTaskRow.workspace_id == workspace_id,
                                           RemediationTaskRow.source_type == source_type))).all()  # fmt: skip
        return {key: {"id": task_id, "status": status} for key, task_id, status in rows if key}

    async def get(self, task_id: str, *, workspace_id: str, events: bool = False) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.get(RemediationTaskRow, task_id)
            if row is None or row.workspace_id != workspace_id:
                return None
            task = _task(row)
            if events:
                rows = (await s.scalars(select(RemediationEventRow).where(RemediationEventRow.task_id == task_id)
                                        .order_by(RemediationEventRow.at))).all()  # fmt: skip
                task["events"] = [_event(r) for r in rows]
        return task

    async def list_tasks(self, *, workspace_id: str) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (await s.scalars(select(RemediationTaskRow).where(RemediationTaskRow.workspace_id == workspace_id)
                                    .order_by(RemediationTaskRow.due_at))).all()  # fmt: skip
        moment = _now()
        return [_task(r, moment) for r in rows]

    async def update(
        self, task_id: str, *, workspace_id: str, by: str, changes: dict[str, Any], note: str = ""
    ) -> dict[str, Any] | None:
        """Apply a person's changes; each one becomes a timeline event."""
        moment = _now()
        async with self.db.session() as s, s.begin():
            row = await s.get(RemediationTaskRow, task_id)
            if row is None or row.workspace_id != workspace_id:
                return None
            for key in EDITABLE:
                if key not in changes:
                    continue
                old, new = getattr(row, key), changes[key]
                if (_utc(old) if isinstance(old, datetime) else old) == new:
                    continue
                setattr(row, key, new)
                if key == "assignee":
                    _log(s, row.id, by, "assigned", f"Assigned to {new}" if new else "Unassigned", previous=old)
                elif key == "due_at":
                    row.overdue_alerted_at = None
                    _log(s, row.id, by, "due", f"Due date changed to {new.date().isoformat()}", previous=_iso(old))
                elif key == "external_ref":
                    _log(s, row.id, by, "edited", f"Ticket set to {new}" if new else "Ticket removed", previous=old)
                elif key != "accepted_until":
                    _log(s, row.id, by, "edited", f"{key.replace('_', ' ').capitalize()} changed",
                         field=key, previous=_iso(old) if isinstance(old, datetime) else old)  # fmt: skip
            if "status" in changes and changes["status"] != row.status:
                previous = row.status
                _close(row, changes["status"], moment)
                if changes["status"] == "accepted":
                    row.accepted_until = changes.get("accepted_until")
                if changes["status"] == "verified":
                    row.verified_by = by
                label = {"in_progress": "In progress", "fixed": "Marked fixed", "verified": "Verified fixed",
                         "accepted": "Risk accepted", "open": "Reopened"}[changes["status"]]  # fmt: skip
                if changes["status"] == "accepted" and row.accepted_until:
                    label += f" until {_utc(row.accepted_until).date().isoformat()}"  # type: ignore[union-attr]
                _log(s, row.id, by, "status", f"{label}{f': {note}' if note else ''}", previous=previous,
                     status=changes["status"])  # fmt: skip
            elif note:
                _log(s, row.id, by, "comment", note)
            row.updated_at = moment
            return _task(row, moment)

    async def comment(self, task_id: str, *, workspace_id: str, by: str, text: str) -> bool:
        async with self.db.session() as s, s.begin():
            row = await s.get(RemediationTaskRow, task_id)
            if row is None or row.workspace_id != workspace_id:
                return False
            row.updated_at = _now()
            _log(s, row.id, by, "comment", text)
        return True

    async def delete(self, task_id: str, *, workspace_id: str) -> bool:
        async with self.db.session() as s, s.begin():
            row = await s.get(RemediationTaskRow, task_id)
            if row is None or row.workspace_id != workspace_id:
                return False
            await s.delete(row)
        return True

    # ------------------------------------------------------------------ evidence from elsewhere
    async def apply_scan(
        self, *, workspace_id: str, target: str, present: set[str], scan: dict[str, Any], investigation_id: str
    ) -> dict[str, list[str]]:
        """A completed scan of ``target``: verify the attack-path tasks it no longer finds, reopen those it does."""
        outcome: dict[str, list[str]] = {"verified": [], "reopened": []}
        moment = _now()
        async with self.db.session() as s, s.begin():
            rows = (await s.scalars(select(RemediationTaskRow).where(
                RemediationTaskRow.workspace_id == workspace_id, RemediationTaskRow.source_type == "attack_path",
                RemediationTaskRow.target == target))).all()  # fmt: skip
            for row in rows:
                task = _task(row, moment)
                decision = verification(task, task["details"].get("path_id") in present, scan)
                if decision == "verified":
                    _close(row, "verified", moment)
                    row.verified_by = investigation_id
                    _log(s, row.id, f"scan {investigation_id}", "verified",
                         "Verified fixed: the attack path was not found by a comparable scan",
                         investigation_id=investigation_id)  # fmt: skip
                elif decision == "reopened":
                    was = row.status
                    _close(row, "open", moment)
                    text = ("Regression: the attack path is back" if was == "verified"
                            else "Still present: the scan found the attack path again")  # fmt: skip
                    _log(s, row.id, f"scan {investigation_id}", "reopened", text, investigation_id=investigation_id)
                else:
                    continue
                outcome[decision].append(row.id)
        return outcome

    async def close_source(
        self, *, workspace_id: str, source_type: str, source_key: str, by: str, text: str, status: str = "verified"
    ) -> dict[str, Any] | None:
        """Close the task of a finding that was dealt with elsewhere (an exposure finding, a supplier)."""
        async with self.db.session() as s, s.begin():
            row = await s.scalar(select(RemediationTaskRow).where(
                RemediationTaskRow.workspace_id == workspace_id, RemediationTaskRow.source_type == source_type,
                RemediationTaskRow.source_key == source_key))  # fmt: skip
            if row is None or row.status not in ACTIVE:
                return None
            _close(row, status, _now())
            if status == "verified":
                row.verified_by = by
            _log(s, row.id, by, "verified" if status == "verified" else "status", text, status=status)
            return _task(row)

    # ------------------------------------------------------------------ the clock
    async def expire_acceptances(self, now: datetime | None = None) -> int:
        """Risk acceptances end: the task reopens and must be decided again."""
        moment = now or _now()
        count = 0
        async with self.db.session() as s, s.begin():
            rows = (await s.scalars(select(RemediationTaskRow).where(RemediationTaskRow.status == "accepted",
                                                                      RemediationTaskRow.accepted_until.is_not(None)))).all()  # fmt: skip
            for row in rows:
                if (_utc(row.accepted_until) or moment) <= moment:
                    _close(row, "open", moment)
                    _log(s, row.id, "system", "reopened", "Risk acceptance expired: decide again")
                    count += 1
        return count

    async def announce_overdue(
        self,
        build: Callable[[str, list[dict[str, Any]]], dict[str, Any]],
        *,
        public_url: str | None,
        now: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Claim tasks that became overdue and raise one alert per workspace for them."""
        moment = now or _now()
        async with self.db.session() as s:
            candidates = (await s.scalars(select(RemediationTaskRow).where(
                RemediationTaskRow.status.in_(ACTIVE), RemediationTaskRow.overdue_alerted_at.is_(None)))).all()  # fmt: skip
        by_workspace: dict[str, list[str]] = {}
        for row in candidates:
            if (_utc(row.due_at) or moment) < moment:
                by_workspace.setdefault(row.workspace_id, []).append(row.id)
        alerts = []
        for workspace_id, ids in by_workspace.items():
            async with self.db.session() as s, s.begin():
                claimed = []
                for task_id in ids:
                    result = await s.execute(
                        update(RemediationTaskRow)
                        .where(
                            RemediationTaskRow.id == task_id,
                            RemediationTaskRow.overdue_alerted_at.is_(None),
                            RemediationTaskRow.status.in_(ACTIVE),
                        )
                        .values(overdue_alerted_at=moment)
                        .execution_options(synchronize_session=False)
                    )
                    if (cast("CursorResult[Any]", result).rowcount or 0) == 1:
                        claimed.append(task_id)
                if not claimed:
                    continue
                tasks = [_task(r, moment) for r in (await s.scalars(
                    select(RemediationTaskRow).where(RemediationTaskRow.id.in_(claimed)))).all()]  # fmt: skip
                built = build(workspace_id, tasks)
                alert_row = AlertRow(id=f"alert_{secrets.token_hex(6)}", workspace_id=workspace_id, monitor_id=None,
                               investigation_id="", previous_investigation_id="", target=built["target"],
                               severity=built["severity"], headline=built["headline"][:1024], summary=built["summary"],
                               created_at=moment)  # fmt: skip
                s.add(alert_row)
                alert: dict[str, Any] = {
                    "id": alert_row.id, "workspace_id": workspace_id, "monitor_id": None, "investigation_id": "",
                    "previous_investigation_id": "", "target": alert_row.target, "severity": alert_row.severity,
                    "headline": alert_row.headline, "summary": alert_row.summary, "created_at": _iso(moment),
                }  # fmt: skip
                alert["notifications_queued"] = await enqueue_alert(s, alert, public_url)
                alerts.append(alert)
        return alerts

    async def purge_closed(self, *, older_than_days: int) -> int:
        """Old closed tasks are kept for metrics, but not forever."""
        cutoff = _now() - timedelta(days=older_than_days)
        async with self.db.session() as s, s.begin():
            rows = (await s.scalars(select(RemediationTaskRow).where(RemediationTaskRow.status.in_(CLOSED),
                                                                      RemediationTaskRow.closed_at < cutoff))).all()  # fmt: skip
            for row in rows:
                await s.delete(row)
        return len(rows)
