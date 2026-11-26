"""Subjects: the people researched in a case, what is known about them, and what was found from it.

Every change goes through :meth:`SubjectRepository.change`, which reads, changes and writes the
row in one transaction (locking the row on PostgreSQL; one change at a time on SQLite), so a run saving its progress never overwrites
a candidate the investigator has just confirmed or rejected.
"""

from __future__ import annotations

import asyncio
import copy
import secrets
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm.attributes import flag_modified

from argus.storage.db import Database, SubjectRow


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()


VERDICT_ORDER = {"likely": 0, "possible": 1, "weak": 2, "unlikely": 3}


def as_dict(row: SubjectRow, *, candidates: bool = True) -> dict[str, Any]:
    data = row.data or {}
    cands = list((data.get("candidates") or {}).values())
    cands.sort(
        key=lambda c: (c.get("status") != "open", VERDICT_ORDER.get(c.get("verdict"), 9), -(c.get("score") or 0))
    )
    counts = {s: sum(1 for c in cands if c.get("status") == s) for s in ("open", "confirmed", "rejected")}
    out = {
        "id": row.id, "case_id": row.case_id, "name": row.name, "known": data.get("known") or {},
        "status": row.status, "run": data.get("run"), "counts": counts,
        "likely": sum(1 for c in cands if c.get("status") == "open" and c.get("verdict") == "likely"),
        "watch": bool(row.watch), "next_watch_at": _iso(row.next_watch_at), "last_watch": data.get("last_watch"),
        "suggestions": data.get("suggestions") or [],
        "created_by": row.created_by, "created_at": _iso(row.created_at), "updated_at": _iso(row.updated_at),
    }  # fmt: skip
    if candidates:
        out["candidates"] = cands
    return out


class SubjectRepository:
    def __init__(self, db: Database):
        self.db = db
        # SQLite has no row locks: changes are serialised here instead (SQLite serves one process).
        self._lock = asyncio.Lock()

    async def create(
        self, *, workspace_id: str, case_id: str, name: str, known: dict[str, Any], by: str
    ) -> dict[str, Any]:
        moment = _now()
        row = SubjectRow(id=f"subj_{secrets.token_hex(8)}", workspace_id=workspace_id, case_id=case_id, name=name[:300],
                         data={"known": known, "candidates": {}, "searched": []}, status="idle", watch=False,
                         next_watch_at=None, created_by=by, created_at=moment, updated_at=moment)  # fmt: skip
        async with self.db.session() as s, s.begin():
            s.add(row)
        return as_dict(row)

    async def get(self, subject_id: str, case_id: str | None = None) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.get(SubjectRow, subject_id)
        if row is None or (case_id is not None and row.case_id != case_id):
            return None
        return as_dict(row)

    async def data(self, subject_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.get(SubjectRow, subject_id)
        return dict(row.data or {}) if row is not None else None

    async def for_case(self, case_id: str) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (await s.scalars(select(SubjectRow).where(SubjectRow.case_id == case_id)
                                    .order_by(SubjectRow.created_at))).all()  # fmt: skip
        return [as_dict(r, candidates=False) for r in rows]

    async def change(
        self, subject_id: str, fn: Callable[[SubjectRow, dict[str, Any]], Any]
    ) -> tuple[dict[str, Any] | None, Any]:
        """Apply ``fn(row, data)`` to the subject in one transaction; ``data`` is a copy saved afterwards."""
        if self.db.dialect == "sqlite":
            async with self._lock:
                return await self._change(subject_id, fn)
        return await self._change(subject_id, fn)

    async def _change(
        self, subject_id: str, fn: Callable[[SubjectRow, dict[str, Any]], Any]
    ) -> tuple[dict[str, Any] | None, Any]:
        async with self.db.session() as s, s.begin():
            query = select(SubjectRow).where(SubjectRow.id == subject_id)
            if self.db.dialect != "sqlite":
                query = query.with_for_update()
            row = (await s.scalars(query)).first()
            if row is None:
                return None, None
            data = copy.deepcopy(row.data or {})
            data.setdefault("candidates", {})
            result = fn(row, data)
            row.data = data
            flag_modified(row, "data")  # nested changes are not seen by comparing values
            row.updated_at = _now()
        return as_dict(row), result

    async def delete(self, subject_id: str) -> None:
        async with self.db.session() as s, s.begin():
            row = await s.get(SubjectRow, subject_id)
            if row is not None:
                await s.delete(row)

    async def set_watch(
        self, subject_id: str, on: bool, every_days: int, by: str | None = None
    ) -> dict[str, Any] | None:
        def apply(row: SubjectRow, data: dict[str, Any]) -> None:
            if on and not row.watch:
                row.next_watch_at = _now() + timedelta(days=every_days)
            elif not on:
                row.next_watch_at = None
            row.watch = on
            if by:
                data["watch_by"] = by

        subject, _ = await self.change(subject_id, apply)
        return subject

    async def claim_watch(self, subject_id: str, every_days: int) -> bool:
        """Move a due watch to its next week; False if another replica already did."""

        def apply(row: SubjectRow, data: dict[str, Any]) -> bool:
            due = row.next_watch_at
            if not row.watch or due is None:
                return False
            if (due if due.tzinfo else due.replace(tzinfo=timezone.utc)) > _now():
                return False
            row.next_watch_at = _now() + timedelta(days=every_days)
            return True

        _, claimed = await self.change(subject_id, apply)
        return bool(claimed)

    async def note_watch(self, subject_id: str, note: dict[str, Any]) -> None:
        def apply(row: SubjectRow, data: dict[str, Any]) -> None:
            data["last_watch"] = note

        await self.change(subject_id, apply)

    async def due(self, limit: int = 20) -> list[SubjectRow]:
        async with self.db.session() as s:
            return list((await s.scalars(select(SubjectRow).where(SubjectRow.watch.is_(True),
                                                                  SubjectRow.next_watch_at <= _now())
                                         .order_by(SubjectRow.next_watch_at).limit(limit))).all())  # fmt: skip

    async def interrupt_running(self, owner: str) -> int:
        """At start-up: this server's runs left running when it stopped can never finish; say so."""
        async with self.db.session() as s:
            ids = list((await s.scalars(select(SubjectRow.id).where(SubjectRow.status == "running"))).all())
        count = 0
        for subject_id in ids:

            def apply(row: SubjectRow, data: dict[str, Any]) -> bool:
                run = dict(data.get("run") or {})
                if row.status != "running" or run.get("owner") != owner:
                    return False
                run.update(status="interrupted", finished_at=_now().isoformat())
                data["run"] = run
                row.status = "idle"
                return True

            _, changed = await self.change(subject_id, apply)
            count += bool(changed)
        return count
