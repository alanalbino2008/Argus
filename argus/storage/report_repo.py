"""Report branding per workspace, and the registry of issued reports."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from typing import Any, cast

from sqlalchemy import delete, select
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession

from argus.reports.data import Branding
from argus.storage.db import Database, ReportBrandingRow, ReportFileRow, ReportRow

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

    async def record(
        self,
        *,
        fields: dict[str, Any],
        file: tuple[str, bytes, timedelta] | None = None,
        after_record: Callable[[AsyncSession, dict[str, Any]], Awaitable[Any]] | None = None,
    ) -> tuple[dict[str, Any], Any]:
        """Register a report, optionally keep its file, and run ``after_record`` in the same transaction."""
        row = ReportRow(created_at=_now(), **fields)
        result = None
        async with self.db.session() as s, s.begin():
            s.add(row)
            await s.flush()  # the report row must exist before its file (foreign key)
            if file is not None:
                filename, pdf, keep = file
                s.add(ReportFileRow(report_id=row.id, workspace_id=row.workspace_id, filename=filename, pdf=pdf,
                                    expires_at=_now() + keep))  # fmt: skip
            report = _report(row)
            report["file_available"] = file is not None
            report["filename"] = file[0] if file is not None else None
            if after_record is not None:
                result = await after_record(s, report)
        return report, result

    async def file(self, report_id: str, *, workspace_id: str | None = None) -> tuple[str, bytes] | None:
        """A stored report file, if it has not expired (and belongs to ``workspace_id`` when given)."""
        async with self.db.session() as s:
            row = await s.get(ReportFileRow, report_id)
        if row is None or (workspace_id is not None and row.workspace_id != workspace_id):
            return None
        expires = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=timezone.utc)
        return (row.filename, row.pdf) if expires > _now() else None

    async def purge_files(self) -> int:
        async with self.db.session() as s, s.begin():
            result = await s.execute(delete(ReportFileRow).where(ReportFileRow.expires_at < _now()))
        return cast("CursorResult[Any]", result).rowcount or 0

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
            rows = list(await s.scalars(stmt))
            stored = (
                set(
                    await s.scalars(
                        select(ReportFileRow.report_id).where(
                            ReportFileRow.report_id.in_([r.id for r in rows]), ReportFileRow.expires_at > _now()
                        )
                    )
                )
                if rows
                else set()
            )
        return [{**_report(r), "file_available": r.id in stored} for r in rows]

    async def find_by_sha256(self, sha256: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.scalar(select(ReportRow).where(ReportRow.sha256 == sha256.lower()))
        return _report(row) if row else None
