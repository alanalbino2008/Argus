"""Cached security ratings, for trends and portfolio benchmarks."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from argus.intel.rating import METHODOLOGY_VERSION
from argus.storage.db import Database, RatingRow


def _iso(value: datetime) -> str:
    return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()


def _row(row: RatingRow) -> dict[str, Any]:
    return {
        **row.data,
        "investigation_id": row.investigation_id,
        "target": row.target,
        "assessed_at": _iso(row.assessed_at),
    }


class RatingRepository:
    def __init__(self, db: Database):
        self.db = db

    async def get(self, investigation_id: str, *, workspace_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.get(RatingRow, investigation_id)
        if row is None or row.workspace_id != workspace_id or row.methodology != METHODOLOGY_VERSION:
            return None  # missing, foreign, or computed under an older methodology
        return _row(row)

    async def save(self, *, investigation_id: str, workspace_id: str, target: str, rating: dict[str, Any],
                   assessed_at: datetime) -> None:  # fmt: skip
        async with self.db.session() as s, s.begin():
            row = await s.get(RatingRow, investigation_id) or RatingRow(investigation_id=investigation_id)
            row.workspace_id, row.target = workspace_id, target.strip().lower()
            row.methodology, row.score, row.grade = rating["methodology"], rating["score"], rating["grade"]
            row.confidence, row.data, row.assessed_at = rating["confidence"], rating, assessed_at
            s.add(row)

    async def history(self, target: str, *, workspace_id: str, limit: int = 12) -> list[dict[str, Any]]:
        """Oldest first: score and grade over time for one target."""
        async with self.db.session() as s:
            rows = (
                await s.scalars(
                    select(RatingRow)
                    .where(
                        RatingRow.workspace_id == workspace_id,
                        RatingRow.target == target.strip().lower(),
                        RatingRow.methodology == METHODOLOGY_VERSION,
                    )
                    .order_by(RatingRow.assessed_at.desc())
                    .limit(limit)
                )
            ).all()
        return [{"investigation_id": r.investigation_id, "score": r.score, "grade": r.grade,
                 "assessed_at": _iso(r.assessed_at)} for r in reversed(rows)]  # fmt: skip

    async def latest_per_target(self, *, workspace_id: str) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (
                await s.scalars(
                    select(RatingRow)
                    .where(RatingRow.workspace_id == workspace_id, RatingRow.methodology == METHODOLOGY_VERSION)
                    .order_by(RatingRow.assessed_at.desc())
                )
            ).all()
        latest: dict[str, RatingRow] = {}
        for row in rows:
            latest.setdefault(row.target, row)
        return [_row(r) for r in latest.values()]
