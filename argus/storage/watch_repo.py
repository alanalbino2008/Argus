"""Watched accounts: what each looked like, and every change since."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, cast

from sqlalchemy import CursorResult, delete, select, update

from argus.storage.db import AccountSnapshotRow, AccountWatchRow, Database

MAX_SNAPSHOTS = 500  # per watch; the oldest go first (the baseline is kept)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()


def _watch(row: AccountWatchRow) -> dict[str, Any]:
    return {
        "id": row.id, "workspace_id": row.workspace_id, "case_id": row.case_id, "platform": row.platform,
        "handle": row.handle, "profile_url": row.profile_url, "interval_hours": row.interval_hours,
        "capture_on_change": bool(row.capture_on_change), "enabled": bool(row.enabled), "status": row.status,
        "message": row.message, "snapshot": row.snapshot or None, "missing_count": row.missing_count,
        "changes_count": row.changes_count, "next_check_at": _iso(row.next_check_at),
        "last_checked_at": _iso(row.last_checked_at), "last_changed_at": _iso(row.last_changed_at),
        "created_by": row.created_by, "created_at": _iso(row.created_at),
    }  # fmt: skip


def _snapshot(row: AccountSnapshotRow) -> dict[str, Any]:
    return {"id": row.id, "taken_at": _iso(row.taken_at), "exists": row.exists, "facts": row.facts or {},
            "changes": list(row.changes or []), "capture_id": row.capture_id}  # fmt: skip


class AccountWatchRepository:
    def __init__(self, db: Database):
        self.db = db

    async def create(self, *, workspace_id: str, case_id: str, by: str, **fields: Any) -> dict[str, Any] | None:
        """A new watch, due straight away; None if the case already watches this account."""
        moment = _now()
        async with self.db.session() as s, s.begin():
            exists = await s.scalar(select(AccountWatchRow.id).where(
                AccountWatchRow.case_id == case_id, AccountWatchRow.platform == fields["platform"],
                AccountWatchRow.handle == fields["handle"]))  # fmt: skip
            if exists:
                return None
            row = AccountWatchRow(id=f"aw_{secrets.token_hex(8)}", workspace_id=workspace_id, case_id=case_id,
                                  created_by=by, created_at=moment, next_check_at=moment, status="pending",
                                  message="", missing_count=0, changes_count=0, enabled=True, **fields)  # fmt: skip
            s.add(row)
        return _watch(row)

    async def list_for_case(self, case_id: str) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (await s.scalars(select(AccountWatchRow).where(AccountWatchRow.case_id == case_id)
                                    .order_by(AccountWatchRow.created_at))).all()  # fmt: skip
        return [_watch(r) for r in rows]

    async def get(self, watch_id: str, case_id: str | None = None) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.get(AccountWatchRow, watch_id)
        if row is None or (case_id is not None and row.case_id != case_id):
            return None
        return _watch(row)

    async def update(self, watch_id: str, case_id: str, **changes: Any) -> dict[str, Any] | None:
        async with self.db.session() as s, s.begin():
            row = await s.get(AccountWatchRow, watch_id)
            if row is None or row.case_id != case_id:
                return None
            for key, value in changes.items():
                setattr(row, key, value)
            if "interval_hours" in changes or changes.get("enabled"):
                row.next_check_at = _now()
        return _watch(row)

    async def delete(self, watch_id: str, case_id: str) -> bool:
        async with self.db.session() as s, s.begin():
            result = await s.execute(delete(AccountWatchRow).where(AccountWatchRow.id == watch_id,
                                                                  AccountWatchRow.case_id == case_id))  # fmt: skip
        return (cast("CursorResult[Any]", result).rowcount or 0) == 1

    async def due(self, now: datetime | None = None, limit: int = 50) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (await s.scalars(select(AccountWatchRow).where(
                AccountWatchRow.enabled.is_(True), AccountWatchRow.next_check_at <= (now or _now()))
                .order_by(AccountWatchRow.next_check_at).limit(limit))).all()  # fmt: skip
        return [_watch(r) for r in rows]

    async def claim(self, watch_id: str, now: datetime | None = None) -> bool:
        """Atomically take a due watch: only one replica's UPDATE still sees it due."""
        moment = now or _now()
        async with self.db.session() as s, s.begin():
            row = await s.get(AccountWatchRow, watch_id)
            if row is None:
                return False
            result = await s.execute(
                update(AccountWatchRow)
                .where(AccountWatchRow.id == watch_id, AccountWatchRow.next_check_at <= moment,
                       AccountWatchRow.enabled.is_(True))
                .values(next_check_at=moment + timedelta(hours=row.interval_hours))
                .execution_options(synchronize_session=False)
            )  # fmt: skip
        return (cast("CursorResult[Any]", result).rowcount or 0) == 1

    async def record(self, watch_id: str, *, status: str, message: str, snapshot: dict[str, Any] | None,
                     missing_count: int, changes: list[dict[str, Any]], exists: bool | None,
                     baseline: bool, capture_id: str | None = None) -> dict[str, Any] | None:  # fmt: skip
        """Store a check; a snapshot is kept for the baseline and for every change."""
        moment = _now()
        async with self.db.session() as s, s.begin():
            row = await s.get(AccountWatchRow, watch_id)
            if row is None:
                return None  # deleted while being checked
            row.status, row.message, row.missing_count, row.last_checked_at = (
                status,
                message[:512],
                missing_count,
                moment,
            )
            if snapshot is not None:
                row.snapshot = snapshot
            if changes:
                row.changes_count += len(changes)
                row.last_changed_at = moment
            if baseline or changes:
                s.add(AccountSnapshotRow(id=f"as_{secrets.token_hex(8)}", watch_id=watch_id, taken_at=moment,
                                         exists=exists, facts=snapshot or {}, changes=changes,
                                         capture_id=capture_id))  # fmt: skip
        await self._trim(watch_id)
        return await self.get(watch_id)

    async def _trim(self, watch_id: str) -> None:
        async with self.db.session() as s, s.begin():
            ids = (await s.scalars(select(AccountSnapshotRow.id).where(AccountSnapshotRow.watch_id == watch_id)
                                   .order_by(AccountSnapshotRow.taken_at))).all()  # fmt: skip
            if len(ids) > MAX_SNAPSHOTS:
                await s.execute(
                    delete(AccountSnapshotRow).where(AccountSnapshotRow.id.in_(ids[1 : len(ids) - MAX_SNAPSHOTS + 1]))
                )

    async def history(self, watch_id: str) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (await s.scalars(select(AccountSnapshotRow).where(AccountSnapshotRow.watch_id == watch_id)
                                    .order_by(AccountSnapshotRow.taken_at.desc()))).all()  # fmt: skip
        return [_snapshot(r) for r in rows]
