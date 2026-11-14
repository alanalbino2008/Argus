"""Persistence for scheduled reports."""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any, cast

from sqlalchemy import select, update
from sqlalchemy.engine import CursorResult

from argus.reports.schedule import describe, next_run
from argus.storage.db import Database, ReportScheduleRow

TIMING = ("frequency", "weekday", "day_of_month", "hour", "minute", "timezone")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value: datetime | None) -> str | None:
    v = _utc(value)
    return v.isoformat() if v else None


def _next(row: ReportScheduleRow, after: datetime) -> datetime:
    return next_run(row.frequency, row.weekday, row.day_of_month, row.hour, row.minute, row.timezone, after)


def _schedule(row: ReportScheduleRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "workspace_id": row.workspace_id,
        "name": row.name,
        "target": row.target,
        "frequency": row.frequency,
        "weekday": row.weekday,
        "day_of_month": row.day_of_month,
        "hour": row.hour,
        "minute": row.minute,
        "timezone": row.timezone,
        "description": describe(row.frequency, row.weekday, row.day_of_month, row.hour, row.minute, row.timezone),
        "options": row.options or {},
        "channel_ids": list(row.channel_ids or []),
        "skip_unchanged": bool(row.skip_unchanged),
        "enabled": bool(row.enabled),
        "next_run_at": _iso(row.next_run_at),
        "last_run_at": _iso(row.last_run_at),
        "last_status": row.last_status,
        "last_message": row.last_message,
        "last_report_id": row.last_report_id,
        "last_investigation_id": row.last_investigation_id,
        "created_at": _iso(row.created_at),
        "created_by": row.created_by,
    }


class ScheduleRepository:
    def __init__(self, db: Database):
        self.db = db

    async def create(self, *, workspace_id: str, by: str, **fields: Any) -> dict[str, Any]:
        moment = _now()
        row = ReportScheduleRow(
            id=f"rsch_{secrets.token_hex(8)}",
            workspace_id=workspace_id,
            created_at=moment,
            created_by=by,
            next_run_at=moment,
            **fields,
        )
        row.next_run_at = _next(row, moment)
        async with self.db.session() as s, s.begin():
            s.add(row)
        return _schedule(row)

    async def _row(self, s: Any, schedule_id: str, workspace_id: str) -> ReportScheduleRow | None:
        row = await s.get(ReportScheduleRow, schedule_id)
        return row if row is not None and row.workspace_id == workspace_id else None

    async def list_schedules(self, *, workspace_id: str) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = await s.scalars(
                select(ReportScheduleRow)
                .where(ReportScheduleRow.workspace_id == workspace_id)
                .order_by(ReportScheduleRow.created_at)
            )
            return [_schedule(r) for r in rows]

    async def get(self, schedule_id: str, *, workspace_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await self._row(s, schedule_id, workspace_id)
            return _schedule(row) if row else None

    async def update(self, schedule_id: str, *, workspace_id: str, **changes: Any) -> dict[str, Any] | None:
        async with self.db.session() as s, s.begin():
            row = await self._row(s, schedule_id, workspace_id)
            if row is None:
                return None
            for key, value in changes.items():
                setattr(row, key, value)
            if any(k in changes for k in TIMING) or changes.get("enabled") is True:
                row.next_run_at = _next(row, _now())
            return _schedule(row)

    async def delete(self, schedule_id: str, *, workspace_id: str) -> bool:
        async with self.db.session() as s, s.begin():
            row = await self._row(s, schedule_id, workspace_id)
            if row is None:
                return False
            await s.delete(row)
            return True

    async def run_now(self, schedule_id: str, *, workspace_id: str) -> dict[str, Any] | None:
        """Make the schedule due immediately; the next scheduler tick (on any replica) runs it."""
        async with self.db.session() as s, s.begin():
            row = await self._row(s, schedule_id, workspace_id)
            if row is None:
                return None
            row.next_run_at = _now()
            return _schedule(row)

    async def due(self, now: datetime | None = None) -> list[dict[str, Any]]:
        moment = now or _now()
        async with self.db.session() as s:
            rows = (await s.scalars(select(ReportScheduleRow).where(ReportScheduleRow.enabled.is_(True)))).all()
        # Compare in Python: SQLite drops tzinfo, so normalise before comparing.
        return [_schedule(r) for r in rows if (_utc(r.next_run_at) or moment) <= moment]

    async def claim(self, schedule_id: str, now: datetime | None = None) -> bool:
        """Atomically take a due schedule: only one replica's UPDATE still sees it due."""
        moment = now or _now()
        async with self.db.session() as s, s.begin():
            row = await s.get(ReportScheduleRow, schedule_id)
            if row is None:
                return False
            result = await s.execute(
                update(ReportScheduleRow)
                .where(
                    ReportScheduleRow.id == schedule_id,
                    ReportScheduleRow.next_run_at <= moment,
                    ReportScheduleRow.enabled.is_(True),
                )
                .values(next_run_at=_next(row, moment), last_run_at=moment)
                .execution_options(synchronize_session=False)
            )
        return (cast("CursorResult[Any]", result).rowcount or 0) == 1

    async def record_result(
        self,
        schedule_id: str,
        *,
        status: str,
        message: str,
        report_id: str | None = None,
        investigation_id: str | None = None,
    ) -> None:
        async with self.db.session() as s, s.begin():
            row = await s.get(ReportScheduleRow, schedule_id)
            if row is None:
                return
            row.last_status, row.last_message = status, message[:512]
            if report_id:
                row.last_report_id = report_id
            if investigation_id:
                row.last_investigation_id = investigation_id
