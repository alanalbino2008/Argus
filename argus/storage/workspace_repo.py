"""Workspaces (teams) and their members."""

from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone
from typing import Any, cast

from sqlalchemy import delete, func, select
from sqlalchemy.engine import CursorResult

from argus.core.models import DEFAULT_WORKSPACE_ID
from argus.storage.db import (
    AlertRow,
    Database,
    InvestigationRow,
    MonitorRow,
    UserRow,
    WorkspaceMemberRow,
    WorkspaceRow,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ws(row: WorkspaceRow, role: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": row.id,
        "name": row.name,
        "slug": row.slug,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "default": row.id == DEFAULT_WORKSPACE_ID,
    }
    if role is not None:
        out["role"] = role
    return out


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:48]
    return slug or "workspace"


class WorkspaceError(Exception):
    pass


class WorkspaceRepository:
    def __init__(self, db: Database):
        self.db = db

    # ------------------------------------------------------------------ workspaces
    async def get(self, ref: str) -> dict[str, Any] | None:
        """Look a workspace up by id or slug."""
        async with self.db.session() as s:
            row = (
                await s.execute(select(WorkspaceRow).where((WorkspaceRow.id == ref) | (WorkspaceRow.slug == ref)))
            ).scalar_one_or_none()
        return _ws(row) if row else None

    async def list_all(self) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (await s.execute(select(WorkspaceRow).order_by(WorkspaceRow.created_at))).scalars().all()
        return [_ws(r) for r in rows]

    async def list_for_user(self, user_id: str) -> list[dict[str, Any]]:
        stmt = (
            select(WorkspaceRow, WorkspaceMemberRow.role)
            .join(WorkspaceMemberRow, WorkspaceMemberRow.workspace_id == WorkspaceRow.id)
            .where(WorkspaceMemberRow.user_id == user_id)
            .order_by(WorkspaceRow.created_at)
        )
        async with self.db.session() as s:
            rows = (await s.execute(stmt)).all()
        return [_ws(ws, role) for ws, role in rows]

    async def create(self, name: str, created_by: str | None) -> dict[str, Any]:
        base = slugify(name)
        async with self.db.session() as s, s.begin():
            slug = base
            while (await s.execute(select(WorkspaceRow.id).where(WorkspaceRow.slug == slug))).first():
                slug = f"{base}-{secrets.token_hex(2)}"
            row = WorkspaceRow(
                id=f"ws_{secrets.token_hex(8)}", name=name.strip()[:128], slug=slug, created_at=_now(),
                created_by=created_by,
            )  # fmt: skip
            s.add(row)
        return _ws(row)

    async def rename(self, workspace_id: str, name: str) -> dict[str, Any] | None:
        async with self.db.session() as s, s.begin():
            row = await s.get(WorkspaceRow, workspace_id)
            if row is None:
                return None
            row.name = name.strip()[:128]
            return _ws(row)

    async def usage(self, workspace_id: str) -> dict[str, int]:
        async with self.db.session() as s:
            counts = {}
            for key, table in (("investigations", InvestigationRow), ("monitors", MonitorRow), ("alerts", AlertRow)):
                stmt = select(func.count()).select_from(table).where(table.workspace_id == workspace_id)
                counts[key] = int((await s.execute(stmt)).scalar_one())
        return counts

    async def delete(self, workspace_id: str) -> bool:
        """Delete an *empty* workspace. Data is never removed implicitly."""
        if workspace_id == DEFAULT_WORKSPACE_ID:
            raise WorkspaceError("The default workspace cannot be deleted")
        if any((await self.usage(workspace_id)).values()):
            raise WorkspaceError("Delete or move its investigations and monitors first")
        async with self.db.session() as s, s.begin():
            result = await s.execute(delete(WorkspaceRow).where(WorkspaceRow.id == workspace_id))
        return (cast("CursorResult[Any]", result).rowcount or 0) > 0

    # ------------------------------------------------------------------ members
    async def members(self, workspace_id: str) -> list[dict[str, Any]]:
        stmt = (
            select(WorkspaceMemberRow, UserRow)
            .join(UserRow, UserRow.id == WorkspaceMemberRow.user_id)
            .where(WorkspaceMemberRow.workspace_id == workspace_id)
            .order_by(UserRow.email)
        )
        async with self.db.session() as s:
            rows = (await s.execute(stmt)).all()
        return [
            {
                "user_id": user.id,
                "email": user.email,
                "name": user.name,
                "role": member.role,
                "disabled": bool(user.disabled),
                "added_at": member.added_at.isoformat() if member.added_at else None,
            }
            for member, user in rows
        ]

    async def role_of(self, workspace_id: str, user_id: str) -> str | None:
        async with self.db.session() as s:
            row = await s.get(WorkspaceMemberRow, (workspace_id, user_id))
        return row.role if row else None

    async def set_member(self, workspace_id: str, user_id: str, role: str, added_by: str | None) -> None:
        async with self.db.session() as s, s.begin():
            row = await s.get(WorkspaceMemberRow, (workspace_id, user_id))
            if row is None:
                s.add(WorkspaceMemberRow(workspace_id=workspace_id, user_id=user_id, role=role, added_at=_now(),
                                         added_by=added_by))  # fmt: skip
            else:
                row.role = role
                if added_by:  # whoever sets it now owns it: SCIM then leaves a membership an admin changed alone
                    row.added_by = added_by

    async def remove_member(self, workspace_id: str, user_id: str) -> bool:
        async with self.db.session() as s, s.begin():
            result = await s.execute(
                delete(WorkspaceMemberRow).where(
                    WorkspaceMemberRow.workspace_id == workspace_id, WorkspaceMemberRow.user_id == user_id
                )
            )
        return (cast("CursorResult[Any]", result).rowcount or 0) > 0
