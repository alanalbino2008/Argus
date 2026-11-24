"""The team's tags and notes on entities (per workspace, shared by every investigation)."""

from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select

from argus.storage.db import Database, EntityAnnotationRow

MAX_TAGS = 20
MAX_TAG_LENGTH = 40
MAX_NOTE_LENGTH = 4000
MAX_ANNOTATIONS = 20000  # per workspace


class AnnotationLimit(ValueError):
    pass


_TAG_RE = re.compile(r"[^\w .:/@+-]", re.UNICODE)


def clean_tags(tags: list[str]) -> list[str]:
    """Trimmed, de-duplicated (case-insensitively), safe tags, in the order given."""
    seen: set[str] = set()
    out: list[str] = []
    for raw in tags:
        tag = _TAG_RE.sub("", str(raw)).strip()[:MAX_TAG_LENGTH]
        if tag and tag.lower() not in seen:
            seen.add(tag.lower())
            out.append(tag)
    return out[:MAX_TAGS]


def _view(row: EntityAnnotationRow) -> dict[str, Any]:
    data = row.data or {}
    updated = row.updated_at if row.updated_at.tzinfo else row.updated_at.replace(tzinfo=timezone.utc)
    return {
        "entity_id": row.entity_id,
        "entity_type": row.entity_type,
        "value": data.get("value", ""),
        "tags": list(data.get("tags") or []),
        "note": data.get("note", ""),
        "updated_by": row.updated_by,
        "updated_at": updated.isoformat(),
    }


class AnnotationRepository:
    def __init__(self, db: Database):
        self.db = db

    async def all(self, workspace_id: str) -> dict[str, dict[str, Any]]:
        """Every annotation of the workspace, by entity id (for queries, hunts and graphs)."""
        async with self.db.session() as s:
            rows = (await s.scalars(select(EntityAnnotationRow).where(
                EntityAnnotationRow.workspace_id == workspace_id))).all()  # fmt: skip
        return {r.entity_id: _view(r) for r in rows}

    async def get(self, workspace_id: str, entity_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.scalar(select(EntityAnnotationRow).where(
                EntityAnnotationRow.workspace_id == workspace_id, EntityAnnotationRow.entity_id == entity_id))  # fmt: skip
        return _view(row) if row else None

    async def put(
        self, workspace_id: str, entity_id: str, *, entity_type: str, value: str, tags: list[str], note: str, by: str
    ) -> dict[str, Any] | None:
        """Set an entity's tags and note; both empty removes the annotation (returns None)."""
        tags, note = clean_tags(tags), note.strip()[:MAX_NOTE_LENGTH]
        async with self.db.session() as s, s.begin():
            row = await s.scalar(select(EntityAnnotationRow).where(
                EntityAnnotationRow.workspace_id == workspace_id, EntityAnnotationRow.entity_id == entity_id))  # fmt: skip
            if not tags and not note:
                if row is not None:
                    await s.delete(row)
                return None
            data = {"value": value[:2000], "tags": tags, "note": note}
            now = datetime.now(timezone.utc)
            if row is None:
                count = int(
                    await s.scalar(select(func.count()).where(EntityAnnotationRow.workspace_id == workspace_id)) or 0
                )
                if count >= MAX_ANNOTATIONS:  # every query, hunt and feed reads them all
                    raise AnnotationLimit(f"A workspace can annotate up to {MAX_ANNOTATIONS:,} entities")
                row = EntityAnnotationRow(id=f"ann_{secrets.token_hex(8)}", workspace_id=workspace_id,
                                          entity_id=entity_id, entity_type=entity_type, data=data,
                                          updated_by=by, updated_at=now)  # fmt: skip
                s.add(row)
            else:
                row.data, row.entity_type, row.updated_by, row.updated_at = data, entity_type, by, now
            return _view(row)

    async def tags(self, workspace_id: str) -> list[dict[str, Any]]:
        """Every tag in use, with how many entities carry it (most used first)."""
        counts: dict[str, int] = {}
        for annotation in (await self.all(workspace_id)).values():
            for tag in annotation["tags"]:
                counts[tag] = counts.get(tag, 0) + 1
        return [{"tag": t, "count": n} for t, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0].lower()))]
