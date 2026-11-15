"""The supplier register."""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from argus.storage.db import Database, SupplierRow

EDITABLE = ("name", "tier", "data_access", "owner", "notes", "min_grade_override")


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()


def _supplier(row: SupplierRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "workspace_id": row.workspace_id,
        "name": row.name,
        "domain": row.domain,
        "tier": row.tier,
        "data_access": row.data_access,
        "owner": row.owner,
        "notes": row.notes,
        "min_grade_override": row.min_grade_override,
        "monitor_id": row.monitor_id,
        "last_grade": row.last_grade,
        "last_score": row.last_score,
        "last_investigation_id": row.last_investigation_id,
        "last_assessed_at": _iso(row.last_assessed_at),
        "created_at": _iso(row.created_at),
        "created_by": row.created_by,
        "basis": row.basis,
    }


class SupplierRepository:
    def __init__(self, db: Database):
        self.db = db

    async def create(self, *, workspace_id: str, by: str, **fields: Any) -> dict[str, Any]:
        row = SupplierRow(
            id=f"sup_{secrets.token_hex(8)}", workspace_id=workspace_id, created_by=by,
            created_at=datetime.now(timezone.utc), **fields,
        )  # fmt: skip
        async with self.db.session() as s, s.begin():
            s.add(row)
        return _supplier(row)

    async def list_suppliers(self, *, workspace_id: str) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = await s.scalars(
                select(SupplierRow).where(SupplierRow.workspace_id == workspace_id).order_by(SupplierRow.name)
            )
            return [_supplier(r) for r in rows]

    async def domains(self, *, workspace_id: str) -> set[str]:
        async with self.db.session() as s:
            return set(await s.scalars(select(SupplierRow.domain).where(SupplierRow.workspace_id == workspace_id)))

    async def get(self, supplier_id: str, *, workspace_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.get(SupplierRow, supplier_id)
        return _supplier(row) if row is not None and row.workspace_id == workspace_id else None

    async def by_monitor(self, monitor_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.scalar(select(SupplierRow).where(SupplierRow.monitor_id == monitor_id))
        return _supplier(row) if row else None

    async def update(self, supplier_id: str, *, workspace_id: str, **changes: Any) -> dict[str, Any] | None:
        async with self.db.session() as s, s.begin():
            row = await s.get(SupplierRow, supplier_id)
            if row is None or row.workspace_id != workspace_id:
                return None
            for key, value in changes.items():
                setattr(row, key, value)
            return _supplier(row)

    async def record_assessment(
        self, supplier_id: str, *, grade: str, score: float, investigation_id: str, assessed_at: datetime
    ) -> None:
        async with self.db.session() as s, s.begin():
            row = await s.get(SupplierRow, supplier_id)
            if row is not None:
                row.last_grade, row.last_score = grade, score
                row.last_investigation_id, row.last_assessed_at = investigation_id, assessed_at

    async def delete(self, supplier_id: str, *, workspace_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s, s.begin():
            row = await s.get(SupplierRow, supplier_id)
            if row is None or row.workspace_id != workspace_id:
                return None
            gone = _supplier(row)
            await s.delete(row)
            return gone
