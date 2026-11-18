"""Playbook runs: what each run did, step by step, and what stood out."""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, update

from argus.storage.db import Database, PlaybookRunRow


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()


def _run(row: PlaybookRunRow) -> dict[str, Any]:
    data = row.data or {}
    return {
        "id": row.id, "case_id": row.case_id, "playbook": row.playbook, "seed": row.seed, "seed_type": row.seed_type,
        "status": row.status, "steps": data.get("steps", []), "highlights": data.get("highlights", []),
        "options": data.get("options", {}), "error": data.get("error"), "created_by": row.created_by,
        "created_at": _iso(row.created_at), "finished_at": _iso(row.finished_at),
    }  # fmt: skip


class PlaybookRepository:
    def __init__(self, db: Database):
        self.db = db

    async def create(self, *, workspace_id: str, case_id: str, playbook: str, seed: str, seed_type: str, by: str,
                     steps: list[dict[str, Any]], options: dict[str, Any], owner: str) -> dict[str, Any]:  # fmt: skip
        row = PlaybookRunRow(
            id=f"pb_{secrets.token_hex(8)}", workspace_id=workspace_id, case_id=case_id, playbook=playbook,
            seed=seed[:500], seed_type=seed_type, status="running",
            data={"steps": steps, "highlights": [], "options": options, "owner": owner}, created_by=by, created_at=_now(),
        )  # fmt: skip
        async with self.db.session() as s, s.begin():
            s.add(row)
        return _run(row)

    async def get(self, run_id: str, case_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.get(PlaybookRunRow, run_id)
        return _run(row) if row is not None and row.case_id == case_id else None

    async def for_case(self, case_id: str) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (await s.scalars(select(PlaybookRunRow).where(PlaybookRunRow.case_id == case_id)
                                    .order_by(PlaybookRunRow.created_at.desc()).limit(50))).all()  # fmt: skip
        return [_run(r) for r in rows]

    async def save(self, run_id: str, *, steps: list[dict[str, Any]], highlights: list[dict[str, Any]] | None = None,
                   status: str | None = None, error: str | None = None) -> None:  # fmt: skip
        async with self.db.session() as s, s.begin():
            row = await s.get(PlaybookRunRow, run_id)
            if row is None:
                return
            data = dict(row.data or {})
            data["steps"] = steps
            if highlights is not None:
                data["highlights"] = highlights
            if error is not None:
                data["error"] = error[:500]
            row.data = data
            if status is not None and row.status in ("running",):
                row.status = status
                if status != "running":
                    row.finished_at = _now()

    async def status(self, run_id: str) -> str | None:
        async with self.db.session() as s:
            row = await s.get(PlaybookRunRow, run_id)
        return row.status if row else None

    async def cancel(self, run_id: str) -> bool:
        async with self.db.session() as s, s.begin():
            result = await s.execute(update(PlaybookRunRow).where(PlaybookRunRow.id == run_id,
                                                                  PlaybookRunRow.status == "running")
                                     .values(status="cancelled", finished_at=_now()))  # fmt: skip
        return bool(result.rowcount)  # type: ignore[attr-defined]

    async def interrupt_running(self, owner: str) -> int:
        """At start-up: this server's runs left "running" when it stopped can never finish; say so.

        Runs belong to the server instance that started them (``owner``), so in a cluster one server
        restarting never marks another server's runs as interrupted.
        """
        async with self.db.session() as s, s.begin():
            rows = (await s.scalars(select(PlaybookRunRow).where(PlaybookRunRow.status == "running"))).all()
            stale = [r for r in rows if (r.data or {}).get("owner") == owner]
            for row in stale:
                row.status, row.finished_at = "interrupted", _now()
        return len(stale)
