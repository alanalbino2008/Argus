"""Saved queries: named Argus Query Language queries, per workspace."""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select

from argus.storage.db import Database, SavedQueryRow

MAX_SAVED_QUERIES = 200  # per workspace


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()


def _view(row: SavedQueryRow) -> dict[str, Any]:
    data = row.data or {}
    return {
        "id": row.id,
        "name": data.get("name", ""),
        "query": data.get("query", ""),
        "description": data.get("description", ""),
        "alert": row.alert,
        "severity": row.severity,
        "created_by": row.created_by,
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
        "last_checked_at": _iso(row.last_checked_at),
        "last_alert_at": _iso(row.last_alert_at),
        "alerts_raised": row.alerts_raised,
    }


class SavedQueryRepository:
    def __init__(self, db: Database):
        self.db = db

    async def count(self, workspace_id: str) -> int:
        async with self.db.session() as s:
            return int(await s.scalar(select(func.count()).where(SavedQueryRow.workspace_id == workspace_id)) or 0)

    async def create(
        self, *, workspace_id: str, name: str, query: str, description: str, alert: bool, severity: str, by: str
    ) -> dict[str, Any]:
        now = _now()
        row = SavedQueryRow(
            id=f"sq_{secrets.token_hex(8)}",
            workspace_id=workspace_id,
            data={"name": name, "query": query, "description": description},
            alert=alert,
            severity=severity,
            created_by=by,
            created_at=now,
            updated_at=now,
            alerts_raised=0,
        )
        async with self.db.session() as s, s.begin():
            s.add(row)
        return _view(row)

    async def list(self, workspace_id: str, *, alerting_only: bool = False) -> list[dict[str, Any]]:
        stmt = select(SavedQueryRow).where(SavedQueryRow.workspace_id == workspace_id)
        if alerting_only:
            stmt = stmt.where(SavedQueryRow.alert.is_(True))
        async with self.db.session() as s:
            rows = (await s.scalars(stmt.order_by(SavedQueryRow.created_at.desc()))).all()
        return [_view(r) for r in rows]

    async def get(self, query_id: str, workspace_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.get(SavedQueryRow, query_id)
        return _view(row) if row is not None and row.workspace_id == workspace_id else None

    async def update(self, query_id: str, workspace_id: str, **changes: Any) -> dict[str, Any] | None:
        async with self.db.session() as s, s.begin():
            row = await s.get(SavedQueryRow, query_id)
            if row is None or row.workspace_id != workspace_id:
                return None
            data = dict(row.data or {})
            for key in ("name", "query", "description"):
                if changes.get(key) is not None:
                    data[key] = changes[key]
            row.data = data
            if changes.get("alert") is not None:
                row.alert = bool(changes["alert"])
            if changes.get("severity") is not None:
                row.severity = changes["severity"]
            row.updated_at = _now()
            return _view(row)

    async def delete(self, query_id: str, workspace_id: str) -> bool:
        async with self.db.session() as s, s.begin():
            row = await s.get(SavedQueryRow, query_id)
            if row is None or row.workspace_id != workspace_id:
                return False
            await s.delete(row)
            return True

    async def mark_checked(self, query_id: str, *, alerted: bool) -> None:
        async with self.db.session() as s, s.begin():
            row = await s.get(SavedQueryRow, query_id)
            if row is None:
                return
            now = _now()
            row.last_checked_at = now
            if alerted:
                row.last_alert_at = now
                row.alerts_raised = (row.alerts_raised or 0) + 1
