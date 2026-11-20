"""Fingerprint watches: scheduled internet-wide searches for a fingerprint, per workspace."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select, update

from argus.storage.db import Database, FingerprintWatchRow

MAX_WATCHES = 50  # per workspace: each check can spend a search credit
MAX_KNOWN = 2000  # servers remembered per watch


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value: datetime | None) -> str | None:
    moment = _utc(value)
    return moment.isoformat() if moment else None


def _view(row: FingerprintWatchRow) -> dict[str, Any]:
    data = row.data or {}
    return {
        "id": row.id,
        "engine": row.engine,
        "entity_id": row.entity_id,
        "investigation_id": row.investigation_id,
        "label": data.get("label", ""),
        "query": data.get("query", ""),
        "known": len(data.get("known") or []),
        "last_new": data.get("last_new") or [],
        "last_message": data.get("last_message", ""),
        "baselined": bool(data.get("baselined")),
        "interval_hours": row.interval_hours,
        "severity": row.severity,
        "enabled": row.enabled,
        "next_run_at": _iso(row.next_run_at),
        "last_run_at": _iso(row.last_run_at),
        "last_status": row.last_status,
        "last_total": row.last_total,
        "alerts_raised": row.alerts_raised,
        "created_by": row.created_by,
        "workspace_id": row.workspace_id,
    }


class FingerprintWatchRepository:
    def __init__(self, db: Database):
        self.db = db

    async def count(self, workspace_id: str) -> int:
        async with self.db.session() as s:
            query = select(func.count()).where(FingerprintWatchRow.workspace_id == workspace_id)
            return int(await s.scalar(query) or 0)

    async def find(self, workspace_id: str, engine: str, entity_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.scalar(select(FingerprintWatchRow).where(
                FingerprintWatchRow.workspace_id == workspace_id, FingerprintWatchRow.engine == engine,
                FingerprintWatchRow.entity_id == entity_id))  # fmt: skip
        return _view(row) if row else None

    async def create(
        self, *, workspace_id: str, engine: str, entity_id: str, investigation_id: str, label: str, query: str,
        interval_hours: int, severity: str, by: str,
    ) -> dict[str, Any]:  # fmt: skip
        now = _now()
        row = FingerprintWatchRow(
            id=f"fpw_{secrets.token_hex(8)}", workspace_id=workspace_id, engine=engine, entity_id=entity_id,
            investigation_id=investigation_id, data={"label": label, "query": query, "known": []},
            interval_hours=interval_hours, severity=severity, enabled=True, next_run_at=now, alerts_raised=0,
            created_by=by, created_at=now,
        )  # fmt: skip
        async with self.db.session() as s, s.begin():
            s.add(row)
        return _view(row)

    async def list_watches(self, workspace_id: str) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (await s.scalars(select(FingerprintWatchRow).where(FingerprintWatchRow.workspace_id == workspace_id)
                                    .order_by(FingerprintWatchRow.created_at.desc()))).all()  # fmt: skip
        return [_view(r) for r in rows]

    async def get(self, watch_id: str, workspace_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.get(FingerprintWatchRow, watch_id)
        return _view(row) if row is not None and row.workspace_id == workspace_id else None

    async def delete(self, watch_id: str, workspace_id: str) -> bool:
        async with self.db.session() as s, s.begin():
            row = await s.get(FingerprintWatchRow, watch_id)
            if row is None or row.workspace_id != workspace_id:
                return False
            await s.delete(row)
            return True

    async def make_due(self, watch_id: str, workspace_id: str) -> bool:
        async with self.db.session() as s, s.begin():
            row = await s.get(FingerprintWatchRow, watch_id)
            if row is None or row.workspace_id != workspace_id:
                return False
            row.next_run_at = _now()
            return True

    async def due(self, now: datetime | None = None) -> list[dict[str, Any]]:
        moment = now or _now()
        async with self.db.session() as s:
            rows = (await s.scalars(select(FingerprintWatchRow).where(FingerprintWatchRow.enabled.is_(True)))).all()
        return [_view(r) for r in rows if (_utc(r.next_run_at) or moment) <= moment]  # in Python: SQLite drops tzinfo

    async def claim(self, watch_id: str, now: datetime | None = None) -> bool:
        """Atomically take a due watch: only one replica's UPDATE still sees it due."""
        moment = now or _now()
        async with self.db.session() as s, s.begin():
            row = await s.get(FingerprintWatchRow, watch_id)
            if row is None:
                return False
            result = await s.execute(
                update(FingerprintWatchRow)
                .where(FingerprintWatchRow.id == watch_id, FingerprintWatchRow.next_run_at <= moment,
                       FingerprintWatchRow.enabled.is_(True))
                .values(next_run_at=moment + timedelta(hours=row.interval_hours))
                .execution_options(synchronize_session=False)
            )  # fmt: skip
        return bool(getattr(result, "rowcount", 0))

    async def known(self, watch_id: str) -> list[str]:
        async with self.db.session() as s:
            row = await s.get(FingerprintWatchRow, watch_id)
        return list((row.data or {}).get("known") or []) if row else []

    async def record(
        self, watch_id: str, *, status: str, total: int | None = None, known: list[str] | None = None,
        new: list[str] | None = None, message: str = "", alerted: bool = False,
    ) -> None:  # fmt: skip
        async with self.db.session() as s, s.begin():
            row = await s.get(FingerprintWatchRow, watch_id)
            if row is None:
                return
            data = dict(row.data or {})
            if known is not None:
                data["known"] = known[-MAX_KNOWN:]
            if new is not None:
                data["last_new"] = new[:50]
            data["last_message"] = message[:300]
            if status == "ok":
                data["baselined"] = True  # the first successful run records today's servers
            row.data = data
            row.last_run_at, row.last_status = _now(), status
            if total is not None:
                row.last_total = total
            if alerted:
                row.alerts_raised = (row.alerts_raised or 0) + 1
