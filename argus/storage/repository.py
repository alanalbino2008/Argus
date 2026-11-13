"""Repository: the only place in Argus that speaks SQL.

The API and recorder call intent-level methods (``save_investigation``,
``load_graph``, ``search_entities``...) and never build queries themselves,
so swapping SQLite for PostgreSQL - or adding caching - touches one file.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Dict, Iterable, List, Optional, Sequence

from sqlalchemy import Table, delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, Investigation, InvestigationStatus, Relation
from argus.storage.db import Database, EntityRow, InvestigationRow, RelationRow

logger = logging.getLogger("argus.storage")

UPSERT_CHUNK = 400
ACTIVE_STATUSES = (InvestigationStatus.INITIALIZING.value, InvestigationStatus.RUNNING.value)


def _entity_row(investigation_id: str, entity: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "investigation_id": investigation_id,
        "entity_id": entity["id"],
        "type": entity["type"],
        "value": entity["value"][:2048],
        "label": entity.get("label", entity["value"])[:2048],
        "data": entity,
    }


def _relation_row(investigation_id: str, relation: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "investigation_id": investigation_id,
        "relation_id": relation["id"],
        "source_id": relation["source_id"],
        "target_id": relation["target_id"],
        "type": relation["type"],
        "data": relation,
    }


def _investigation_row(inv: Investigation) -> Dict[str, Any]:
    return {
        "id": inv.id,
        "target": inv.config.target[:512],
        "target_type": inv.config.target_type.value,
        "status": inv.status.value,
        "created_at": inv.created_at,
        "completed_at": inv.completed_at,
        "node_count": inv.node_count,
        "edge_count": inv.edge_count,
        "data": inv.model_dump(mode="json"),
    }


class InvestigationRepository:
    def __init__(self, db: Database):
        self.db = db

    # ---------------------------------------------------------------- writes
    async def save_investigation(self, inv: Investigation) -> None:
        """Insert or update the investigation record."""
        async with self.db.session() as s, s.begin():
            await self._upsert(s, InvestigationRow.__table__, [_investigation_row(inv)], ["id"])

    async def upsert_entities(self, investigation_id: str, entities: Iterable[Dict[str, Any]]) -> int:
        rows = [_entity_row(investigation_id, e) for e in entities]
        if rows:
            async with self.db.session() as s, s.begin():
                await self._upsert(s, EntityRow.__table__, rows, ["investigation_id", "entity_id"])
        return len(rows)

    async def upsert_relations(self, investigation_id: str, relations: Iterable[Dict[str, Any]]) -> int:
        rows = [_relation_row(investigation_id, r) for r in relations]
        if rows:
            async with self.db.session() as s, s.begin():
                await self._upsert(s, RelationRow.__table__, rows, ["investigation_id", "relation_id"])
        return len(rows)

    async def save_graph(self, graph: IntelligenceGraph) -> None:
        """Full snapshot of a graph (captures metadata merged into existing nodes)."""
        await self.upsert_entities(graph.investigation_id, (e.model_dump(mode="json") for e in graph.get_all_entities()))
        await self.upsert_relations(graph.investigation_id, (r.model_dump(mode="json") for r in graph.get_all_relations()))

    async def delete_investigation(self, investigation_id: str) -> bool:
        async with self.db.session() as s, s.begin():
            # Explicit child deletes keep this portable even where FK cascades are off.
            await s.execute(delete(RelationRow).where(RelationRow.investigation_id == investigation_id))
            await s.execute(delete(EntityRow).where(EntityRow.investigation_id == investigation_id))
            result = await s.execute(delete(InvestigationRow).where(InvestigationRow.id == investigation_id))
        return (result.rowcount or 0) > 0

    async def mark_interrupted(self) -> int:
        """Investigations left 'running' by a crash/restart can never finish: mark them failed."""
        async with self.db.session() as s, s.begin():
            rows = (await s.execute(
                select(InvestigationRow).where(InvestigationRow.status.in_(ACTIVE_STATUSES))
            )).scalars().all()
            now = datetime.now(timezone.utc)
            for row in rows:
                data = dict(row.data)
                data["status"] = InvestigationStatus.FAILED.value
                data["completed_at"] = now.isoformat()
                data["errors"] = [*data.get("errors", []), "Interrupted: server stopped before the scan finished."]
                await s.execute(
                    update(InvestigationRow)
                    .where(InvestigationRow.id == row.id)
                    .values(status=InvestigationStatus.FAILED.value, completed_at=now, data=data)
                )
        return len(rows)

    # ----------------------------------------------------------------- reads
    async def get_investigation(self, investigation_id: str) -> Optional[Investigation]:
        async with self.db.session() as s:
            row = await s.get(InvestigationRow, investigation_id)
        return Investigation.model_validate(row.data) if row else None

    async def list_investigations(
        self, limit: int = 50, offset: int = 0, status: Optional[str] = None, target: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        stmt = select(InvestigationRow).order_by(InvestigationRow.created_at.desc()).limit(limit).offset(offset)
        if status:
            stmt = stmt.where(InvestigationRow.status == status)
        if target:
            stmt = stmt.where(func.lower(InvestigationRow.target).contains(target.lower()))
        async with self.db.session() as s:
            rows = (await s.execute(stmt)).scalars().all()
        return [
            {
                "id": r.id,
                "name": r.data.get("name"),
                "status": r.status,
                "target": r.target,
                "target_type": r.target_type,
                "nodes_count": r.node_count,
                "edges_count": r.edge_count,
                "created_at": _iso(r.created_at),
                "completed_at": _iso(r.completed_at),
                "threat_exposure_score": (r.data.get("analytics") or {}).get("threat_exposure_score"),
            }
            for r in rows
        ]

    async def load_graph(self, investigation_id: str) -> Optional[IntelligenceGraph]:
        async with self.db.session() as s:
            if await s.get(InvestigationRow, investigation_id) is None:
                return None
            ents = (await s.execute(
                select(EntityRow.data).where(EntityRow.investigation_id == investigation_id)
            )).scalars().all()
            rels = (await s.execute(
                select(RelationRow.data).where(RelationRow.investigation_id == investigation_id)
            )).scalars().all()

        graph = IntelligenceGraph(investigation_id)
        entities = sorted((Entity.model_validate(e) for e in ents), key=lambda e: e.depth)
        for ent in entities:
            graph.add_entity(ent, is_seed=ent.depth == 0)
        for rel in rels:
            graph.add_relation(Relation.model_validate(rel))
        return graph

    async def search_entities(self, query: str, entity_type: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Cross-investigation pivot: where else have we seen this IP / email / domain?"""
        stmt = (
            select(EntityRow, InvestigationRow.target, InvestigationRow.created_at)
            .join(InvestigationRow, InvestigationRow.id == EntityRow.investigation_id)
            .where(func.lower(EntityRow.value).contains(query.lower()))
            .order_by(InvestigationRow.created_at.desc())
            .limit(limit)
        )
        if entity_type:
            stmt = stmt.where(EntityRow.type == entity_type)
        async with self.db.session() as s:
            rows = (await s.execute(stmt)).all()
        return [
            {
                "investigation_id": ent.investigation_id,
                "investigation_target": target,
                "investigation_created_at": _iso(created),
                "entity": ent.data,
            }
            for ent, target, created in rows
        ]

    # -------------------------------------------------------------- helpers
    async def _upsert(self, s: AsyncSession, table: Table, rows: Sequence[Dict[str, Any]], keys: List[str]) -> None:
        dialect = self.db.dialect
        if dialect == "sqlite":
            from sqlalchemy.dialects.sqlite import insert
        elif dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert
        else:  # pragma: no cover - generic fallback for other backends
            for row in rows:
                await s.merge(_row_to_orm(table, row))
            return

        update_cols = [c.name for c in table.columns if c.name not in keys]
        for i in range(0, len(rows), UPSERT_CHUNK):
            stmt = insert(table).values(list(rows[i:i + UPSERT_CHUNK]))
            stmt = stmt.on_conflict_do_update(
                index_elements=keys, set_={c: stmt.excluded[c] for c in update_cols}
            )
            await s.execute(stmt)


def _row_to_orm(table: Table, row: Dict[str, Any]):  # pragma: no cover
    model = {t.__table__: t for t in (InvestigationRow, EntityRow, RelationRow)}[table]
    return model(**row)


def _iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    if value.tzinfo is None:  # SQLite drops tzinfo; values are always stored in UTC
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()
