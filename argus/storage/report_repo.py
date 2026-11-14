"""Report branding per workspace, and the registry of issued reports."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from argus.reports.data import Branding
from argus.storage.db import Database, ReportBrandingRow, ReportRow

_KEEP: Any = object()  # "leave the logo as it is"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()


def _report(row: ReportRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "workspace_id": row.workspace_id,
        "investigation_id": row.investigation_id,
        "target": row.target,
        "sha256": row.sha256,
        "size": row.size,
        "tlp": row.tlp,
        "prepared_for": row.prepared_for,
        "issued_by_org": row.issued_by_org,
        "created_at": _iso(row.created_at),
        "created_by": row.created_by,
    }


class ReportRepository:
    KEEP = _KEEP

    def __init__(self, db: Database):
        self.db = db

    async def branding(self, workspace_id: str, default_org: str = "Argus") -> Branding:
        async with self.db.session() as s:
            row = await s.get(ReportBrandingRow, workspace_id)
        if row is None:
            return Branding(organisation=default_org)
        return Branding(row.organisation, row.accent, row.logo_png, row.footer_note or "")

    async def branding_public(self, workspace_id: str, default_org: str) -> dict[str, Any]:
        async with self.db.session() as s:
            row = await s.get(ReportBrandingRow, workspace_id)
        current = await self.branding(workspace_id, default_org)
        return {
            "organisation": current.organisation,
            "accent": current.accent,
            "footer_note": current.footer_note,
            "has_logo": current.logo_png is not None,
            "updated_at": _iso(row.updated_at) if row else None,
            "updated_by": row.updated_by if row else None,
        }

    async def set_branding(
        self,
        workspace_id: str,
        *,
        organisation: str,
        accent: str,
        footer_note: str,
        logo_png: bytes | Any | None = _KEEP,
        by: str,
    ) -> None:
        async with self.db.session() as s, s.begin():
            row = await s.get(ReportBrandingRow, workspace_id)
            if row is None:
                row = ReportBrandingRow(workspace_id=workspace_id, logo_png=None)
                s.add(row)
            row.organisation, row.accent, row.footer_note = organisation, accent, footer_note
            if logo_png is not _KEEP:
                row.logo_png = logo_png
            row.updated_at, row.updated_by = _now(), by

    async def logo(self, workspace_id: str) -> bytes | None:
        async with self.db.session() as s:
            row = await s.get(ReportBrandingRow, workspace_id)
        return row.logo_png if row else None

    async def record(self, **fields: Any) -> dict[str, Any]:
        row = ReportRow(created_at=_now(), **fields)
        async with self.db.session() as s, s.begin():
            s.add(row)
        return _report(row)

    async def list_reports(
        self, *, workspace_id: str, investigation_id: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        stmt = (
            select(ReportRow)
            .where(ReportRow.workspace_id == workspace_id)
            .order_by(ReportRow.created_at.desc())
            .limit(limit)
        )
        if investigation_id:
            stmt = stmt.where(ReportRow.investigation_id == investigation_id)
        async with self.db.session() as s:
            return [_report(r) for r in await s.scalars(stmt)]

    async def find_by_sha256(self, sha256: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.scalar(select(ReportRow).where(ReportRow.sha256 == sha256.lower()))
        return _report(row) if row else None
