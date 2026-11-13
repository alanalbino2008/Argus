"""Persistence for scheduled monitors and the drift alerts they raise."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, cast

from sqlalchemy import delete, select, update
from sqlalchemy.engine import CursorResult

from argus.storage.db import AlertRow, Database, MonitorRow


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
        "previous_investigation_id": row.previous_investigation_id,
        "target": row.target,
        "severity": row.severity,
        "headline": row.headline,
        "summary": row.summary,
        "created_at": _iso(row.created_at),
        "acknowledged_at": _iso(row.acknowledged_at),
        "acknowledged_by": row.acknowledged_by,
    }


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
        run_now: bool = True,
    ) -> dict[str, Any]:
        now = _now()
        row = MonitorRow(
            id=f"mon_{secrets.token_hex(6)}",
            target=target,
            target_type=target_type,
            max_depth=max_depth,
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

    async def get(self, monitor_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.get(MonitorRow, monitor_id)
        return _monitor(row) if row else None

    async def list_monitors(self) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (await s.execute(select(MonitorRow).order_by(MonitorRow.created_at))).scalars().all()
        return [_monitor(r) for r in rows]

    async def set_enabled(self, monitor_id: str, enabled: bool) -> bool:
        async with self.db.session() as s, s.begin():
            result = await s.execute(update(MonitorRow).where(MonitorRow.id == monitor_id).values(enabled=enabled))
        return (cast("CursorResult[Any]", result).rowcount or 0) > 0

    async def delete(self, monitor_id: str) -> bool:
        async with self.db.session() as s, s.begin():
            result = await s.execute(delete(MonitorRow).where(MonitorRow.id == monitor_id))
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
    ) -> dict[str, Any]:
        row = AlertRow(
            id=f"alert_{secrets.token_hex(6)}",
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
        return _alert(row)

    async def alerts(self, limit: int = 50, unacknowledged_only: bool = False) -> list[dict[str, Any]]:
        stmt = select(AlertRow).order_by(AlertRow.created_at.desc()).limit(limit)
        if unacknowledged_only:
            stmt = stmt.where(AlertRow.acknowledged_at.is_(None))
        async with self.db.session() as s:
            rows = (await s.execute(stmt)).scalars().all()
        return [_alert(r) for r in rows]

    async def acknowledge(self, alert_id: str, by: str) -> bool:
        async with self.db.session() as s, s.begin():
            result = await s.execute(
                update(AlertRow)
                .where(AlertRow.id == alert_id, AlertRow.acknowledged_at.is_(None))
                .values(acknowledged_at=_now(), acknowledged_by=by)
            )
        return (cast("CursorResult[Any]", result).rowcount or 0) > 0
