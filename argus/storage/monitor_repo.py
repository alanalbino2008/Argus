"""Persistence for scheduled monitors and the drift alerts they raise."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Any, cast

from sqlalchemy import delete, select, update
from sqlalchemy.engine import CursorResult

from argus.storage.db import AlertRow, Database, MonitorRow
from argus.storage.notification_repo import enqueue_alert


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value: datetime | None) -> str | None:
    v = _utc(value)
    return v.isoformat() if v else None


def _monitor(row: MonitorRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "target": row.target,
        "target_type": row.target_type,
        "max_depth": row.max_depth,
        "workspace_id": row.workspace_id,
        "passive_only": bool(row.passive_only),
        "interval_hours": row.interval_hours,
        "purpose": row.purpose,
        "created_by": row.created_by,
        "enabled": row.enabled,
        "created_at": _iso(row.created_at),
        "next_run_at": _iso(row.next_run_at),
        "last_run_at": _iso(row.last_run_at),
        "last_investigation_id": row.last_investigation_id,
    }


def _alert(row: AlertRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "monitor_id": row.monitor_id,
        "investigation_id": row.investigation_id,
        "workspace_id": row.workspace_id,
        "previous_investigation_id": row.previous_investigation_id,
        "target": row.target,
        "severity": row.severity,
        "headline": row.headline,
        "summary": row.summary,
        "created_at": _iso(row.created_at),
        "acknowledged_at": _iso(row.acknowledged_at),
        "acknowledged_by": row.acknowledged_by,
        "status": row.status or "open",
        "assignee": row.assignee,
        "resolved_at": _iso(row.resolved_at),
        "resolved_by": row.resolved_by,
        "comments": sum(1 for a in row.activity or [] if a.get("event") == "comment"),
    }


ALERT_STATUSES = ("open", "investigating", "resolved", "false_positive")
OPEN = ("open", "investigating")
CLOSED = ("resolved", "false_positive")
MAX_ACTIVITY = 200


class MonitorRepository:
    def __init__(self, db: Database):
        self.db = db

    # ------------------------------------------------------------------ monitors
    async def create(
        self,
        *,
        target: str,
        target_type: str,
        max_depth: int,
        interval_hours: int,
        purpose: str,
        created_by: str,
        workspace_id: str,
        run_now: bool = True,
        passive_only: bool = False,
    ) -> dict[str, Any]:
        now = _now()
        row = MonitorRow(
            id=f"mon_{secrets.token_hex(6)}",
            target=target,
            target_type=target_type,
            max_depth=max_depth,
            workspace_id=workspace_id,
            passive_only=passive_only,
            interval_hours=interval_hours,
            purpose=purpose,
            created_by=created_by,
            enabled=True,
            created_at=now,
            next_run_at=now if run_now else now + timedelta(hours=interval_hours),
        )
        async with self.db.session() as s, s.begin():
            s.add(row)
        return _monitor(row)

    # Every user-facing method takes a *required* workspace_id: a call that forgets the
    # tenant boundary does not type-check, and rows of other workspaces simply do not match.
    async def get(self, monitor_id: str, *, workspace_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.get(MonitorRow, monitor_id)
        return _monitor(row) if row and row.workspace_id == workspace_id else None

    async def list_monitors(self, *, workspace_id: str) -> list[dict[str, Any]]:
        stmt = select(MonitorRow).where(MonitorRow.workspace_id == workspace_id).order_by(MonitorRow.created_at)
        async with self.db.session() as s:
            rows = (await s.execute(stmt)).scalars().all()
        return [_monitor(r) for r in rows]

    async def set_enabled(self, monitor_id: str, enabled: bool, *, workspace_id: str | None) -> bool:
        """``workspace_id=None`` is reserved for the scheduler (it acts across workspaces)."""
        stmt = update(MonitorRow).where(MonitorRow.id == monitor_id)
        if workspace_id is not None:
            stmt = stmt.where(MonitorRow.workspace_id == workspace_id)
        async with self.db.session() as s, s.begin():
            result = await s.execute(stmt.values(enabled=enabled))
        return (cast("CursorResult[Any]", result).rowcount or 0) > 0

    async def reschedule(
        self, monitor_id: str, *, workspace_id: str, interval_hours: int | None = None, run_now: bool = False
    ) -> bool:
        """Change how often a monitor runs and/or make it due immediately."""
        async with self.db.session() as s, s.begin():
            row = await s.get(MonitorRow, monitor_id)
            if row is None or row.workspace_id != workspace_id:
                return False
            if interval_hours is not None:
                row.interval_hours = interval_hours
            if run_now:
                row.next_run_at = _now()
            return True

    async def delete(self, monitor_id: str, *, workspace_id: str) -> bool:
        async with self.db.session() as s, s.begin():
            result = await s.execute(
                delete(MonitorRow).where(MonitorRow.id == monitor_id, MonitorRow.workspace_id == workspace_id)
            )
        return (cast("CursorResult[Any]", result).rowcount or 0) > 0

    async def due(self, now: datetime | None = None) -> list[dict[str, Any]]:
        moment = now or _now()
        async with self.db.session() as s:
            rows = (
                (
                    await s.execute(
                        select(MonitorRow).where(MonitorRow.enabled.is_(True)).order_by(MonitorRow.next_run_at)
                    )
                )
                .scalars()
                .all()
            )
        # Compare in Python: SQLite drops tzinfo, so normalise before comparing.
        return [_monitor(r) for r in rows if (_utc(r.next_run_at) or moment) <= moment]

    async def claim(self, monitor_id: str, now: datetime | None = None) -> bool:
        """Atomically take a due monitor: only one replica's UPDATE can still see it due.

        Moves ``next_run_at`` forward in the same statement that checks it, so two
        schedulers ticking at the same moment can never both start the same scan.
        """
        moment = now or _now()
        async with self.db.session() as s, s.begin():
            row = await s.get(MonitorRow, monitor_id)
            if row is None:
                return False
            result = await s.execute(
                update(MonitorRow)
                .where(MonitorRow.id == monitor_id, MonitorRow.next_run_at <= moment, MonitorRow.enabled.is_(True))
                .values(next_run_at=moment + timedelta(hours=row.interval_hours), last_run_at=moment)
                .execution_options(synchronize_session=False)
            )
        return (cast("CursorResult[Any]", result).rowcount or 0) == 1

    async def release(self, monitor_id: str) -> None:
        """Undo a claim whose scan could not start, so the next tick retries it."""
        async with self.db.session() as s, s.begin():
            await s.execute(update(MonitorRow).where(MonitorRow.id == monitor_id).values(next_run_at=_now()))

    async def mark_started(self, monitor_id: str, investigation_id: str) -> None:
        """Record a run and schedule the next one (before the scan finishes, so it is never double-started)."""
        async with self.db.session() as s, s.begin():
            row = await s.get(MonitorRow, monitor_id)
            if row is None:
                return
            now = _now()
            row.last_run_at = now
            row.next_run_at = now + timedelta(hours=row.interval_hours)
            row.last_investigation_id = investigation_id

    # -------------------------------------------------------------------- alerts
    async def create_alert(
        self,
        *,
        monitor_id: str | None,
        investigation_id: str,
        previous_investigation_id: str,
        target: str,
        severity: str,
        headline: str,
        summary: dict[str, Any],
        workspace_id: str,
        notify: bool = True,
        public_url: str | None = None,
    ) -> dict[str, Any]:
        """Save the alert and, in the same transaction, queue its notifications (outbox)."""
        row = AlertRow(
            id=f"alert_{secrets.token_hex(6)}",
            workspace_id=workspace_id,
            monitor_id=monitor_id,
            investigation_id=investigation_id,
            previous_investigation_id=previous_investigation_id,
            target=target,
            severity=severity,
            headline=headline[:1024],
            summary=summary,
            created_at=_now(),
        )
        async with self.db.session() as s, s.begin():
            s.add(row)
            alert = _alert(row)
            if notify:
                alert["notifications_queued"] = await enqueue_alert(s, alert, public_url)
        return alert

    async def alerts(
        self, *, workspace_id: str, limit: int = 50, unacknowledged_only: bool = False,
        statuses: list[str] | None = None, assignee: str | None = None,
    ) -> list[dict[str, Any]]:  # fmt: skip
        stmt = (
            select(AlertRow)
            .where(AlertRow.workspace_id == workspace_id)
            .order_by(AlertRow.created_at.desc())
            .limit(limit)
        )
        if unacknowledged_only:
            stmt = stmt.where(AlertRow.acknowledged_at.is_(None))
        if statuses:
            stmt = stmt.where(AlertRow.status.in_(statuses))
        if assignee is not None:
            stmt = stmt.where(AlertRow.assignee == assignee) if assignee else stmt.where(AlertRow.assignee.is_(None))
        async with self.db.session() as s:
            rows = (await s.execute(stmt)).scalars().all()
        return [_alert(r) for r in rows]

    async def acknowledge(self, alert_id: str, by: str, *, workspace_id: str) -> bool:
        """Seen, and someone is on it: an open alert moves to *investigating*."""
        async with self.db.session() as s, s.begin():
            row = await s.get(AlertRow, alert_id)
            if row is None or row.workspace_id != workspace_id or row.acknowledged_at is not None:
                return False
            row.acknowledged_at, row.acknowledged_by = _now(), by
            if (row.status or "open") == "open":
                row.status = "investigating"
            row.activity = [*(row.activity or []), {"at": _now().isoformat(), "by": by, "event": "acknowledged"}][
                -MAX_ACTIVITY:
            ]
            return True

    async def get_alert(self, alert_id: str, *, workspace_id: str) -> dict[str, Any] | None:
        """One alert with its activity (comments, status changes, assignments)."""
        async with self.db.session() as s:
            row = await s.get(AlertRow, alert_id)
        if row is None or row.workspace_id != workspace_id:
            return None
        return {**_alert(row), "activity": list(row.activity or [])}

    async def update_alert(
        self, alert_id: str, *, workspace_id: str, by: str, status: str | None = None,
        assignee: str | None = None, unassign: bool = False, note: str = "",
    ) -> dict[str, Any] | None:  # fmt: skip
        """Change an alert's status and/or assignee; every change is recorded in its activity."""
        async with self.db.session() as s, s.begin():
            row = await s.get(AlertRow, alert_id)
            if row is None or row.workspace_id != workspace_id:
                return None
            now = _now()
            events: list[dict[str, Any]] = []
            if status is not None and status != (row.status or "open"):
                events.append({"event": "status", "from": row.status or "open", "to": status})
                row.status = status
                if status in CLOSED:
                    row.resolved_at, row.resolved_by = now, by
                else:
                    row.resolved_at = row.resolved_by = None
                if row.acknowledged_at is None:  # any decision means someone has seen it
                    row.acknowledged_at, row.acknowledged_by = now, by
            if unassign and row.assignee is not None:
                events.append({"event": "assigned", "from": row.assignee, "to": None})
                row.assignee = None
            elif assignee is not None and assignee != row.assignee:
                events.append({"event": "assigned", "from": row.assignee, "to": assignee})
                row.assignee = assignee
            if events:
                stamp = now.isoformat()
                extra = {"note": note} if note else {}
                row.activity = [*(row.activity or []), *({"at": stamp, "by": by, **e, **extra} for e in events)][
                    -MAX_ACTIVITY:
                ]
            return {**_alert(row), "activity": list(row.activity or [])}

    async def comment(self, alert_id: str, *, workspace_id: str, by: str, body: str) -> dict[str, Any] | None:
        async with self.db.session() as s, s.begin():
            row = await s.get(AlertRow, alert_id)
            if row is None or row.workspace_id != workspace_id:
                return None
            entry = {"at": _now().isoformat(), "by": by, "event": "comment", "body": body}
            row.activity = [*(row.activity or []), entry][-MAX_ACTIVITY:]
            return entry

    async def alert_stats(self, *, workspace_id: str, days: int, now: datetime | None = None) -> dict[str, Any]:
        """Open work by severity, and how fast alerts are acknowledged and resolved (medians, in hours)."""
        moment = now or _now()
        since = moment - timedelta(days=days)
        async with self.db.session() as s:
            open_rows = (await s.execute(select(AlertRow.severity, AlertRow.assignee).where(
                AlertRow.workspace_id == workspace_id, AlertRow.status.in_(OPEN)))).all()  # fmt: skip
            recent = (await s.execute(select(AlertRow.created_at, AlertRow.acknowledged_at, AlertRow.resolved_at,
                                             AlertRow.status).where(AlertRow.workspace_id == workspace_id,
                                                                    AlertRow.created_at >= since))).all()  # fmt: skip

        def hours(start: datetime | None, end: datetime | None) -> float | None:
            a, b = _utc(start), _utc(end)
            return round((b - a).total_seconds() / 3600, 1) if a and b else None

        to_ack = [h for h in (hours(c, a) for c, a, _r, _s in recent) if h is not None]
        to_resolve = [h for h in (hours(c, r) for c, _a, r, st in recent if st in CLOSED) if h is not None]
        by_severity: dict[str, int] = {}
        for severity, _who in open_rows:
            by_severity[severity] = by_severity.get(severity, 0) + 1
        closed = [st for *_x, st in recent if st in CLOSED]
        return {
            "period_days": days,
            "open": len(open_rows),
            "open_by_severity": by_severity,
            "unassigned": sum(1 for _sev, who in open_rows if not who),
            "raised": len(recent),
            "resolved": len(closed),
            "false_positive_rate": round(closed.count("false_positive") / len(closed), 3) if closed else None,
            "median_hours_to_acknowledge": median(to_ack) if to_ack else None,
            "median_hours_to_resolve": median(to_resolve) if to_resolve else None,
        }
