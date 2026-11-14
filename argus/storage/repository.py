"""Repository: the only place in Argus that speaks SQL.

The API and recorder call intent-level methods (``save_investigation``,
``load_graph``, ``search_entities``...) and never build queries themselves,
so swapping SQLite for PostgreSQL - or adding caching - touches one file.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any, cast

from sqlalchemy import Table, delete, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession

from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, Investigation, InvestigationStatus, Relation
from argus.storage.db import Database, EntityRow, InvestigationRow, RelationRow

logger = logging.getLogger("argus.storage")

UPSERT_CHUNK = 400
ACTIVE_STATUSES = (InvestigationStatus.INITIALIZING.value, InvestigationStatus.RUNNING.value)


def _entity_row(investigation_id: str, entity: dict[str, Any]) -> dict[str, Any]:
    return {
        "investigation_id": investigation_id,
        "entity_id": entity["id"],
        "type": entity["type"],
        "value": entity["value"][:2048],
        "label": entity.get("label", entity["value"])[:2048],
        "data": entity,
    }


def _relation_row(investigation_id: str, relation: dict[str, Any]) -> dict[str, Any]:
    return {
        "investigation_id": investigation_id,
        "relation_id": relation["id"],
        "source_id": relation["source_id"],
        "target_id": relation["target_id"],
        "type": relation["type"],
        "data": relation,
    }


def _investigation_row(inv: Investigation) -> dict[str, Any]:
    return {
        "id": inv.id,
        "target": inv.config.target[:512],
        "target_type": inv.config.target_type.value,
        "status": inv.status.value,
        "created_at": inv.created_at,
        "completed_at": inv.completed_at,
        "node_count": inv.node_count,
        "edge_count": inv.edge_count,
        "workspace_id": inv.workspace_id,
        "data": inv.model_dump(mode="json"),
    }


class InvestigationRepository:
    def __init__(self, db: Database):
        self.db = db

    # ---------------------------------------------------------------- writes
    async def save_investigation(self, inv: Investigation) -> None:
        """Insert or update the investigation record."""
        async with self.db.session() as s, s.begin():
            await self._upsert(s, _table(InvestigationRow), [_investigation_row(inv)], ["id"])

    async def upsert_entities(self, investigation_id: str, entities: Iterable[dict[str, Any]]) -> int:
        rows = [_entity_row(investigation_id, e) for e in entities]
        if rows:
            async with self.db.session() as s, s.begin():
                await self._upsert(s, _table(EntityRow), rows, ["investigation_id", "entity_id"])
        return len(rows)

    async def upsert_relations(self, investigation_id: str, relations: Iterable[dict[str, Any]]) -> int:
        rows = [_relation_row(investigation_id, r) for r in relations]
        if rows:
            async with self.db.session() as s, s.begin():
                await self._upsert(s, _table(RelationRow), rows, ["investigation_id", "relation_id"])
        return len(rows)

    async def save_graph(self, graph: IntelligenceGraph) -> None:
        """Full snapshot of a graph (captures metadata merged into existing nodes)."""
        await self.upsert_entities(
            graph.investigation_id, (e.model_dump(mode="json") for e in graph.get_all_entities())
        )
        await self.upsert_relations(
            graph.investigation_id, (r.model_dump(mode="json") for r in graph.get_all_relations())
        )

    async def delete_investigation(self, investigation_id: str) -> bool:
        async with self.db.session() as s, s.begin():
            # Explicit child deletes keep this portable even where FK cascades are off.
            await s.execute(delete(RelationRow).where(RelationRow.investigation_id == investigation_id))
            await s.execute(delete(EntityRow).where(EntityRow.investigation_id == investigation_id))
            result = await s.execute(delete(InvestigationRow).where(InvestigationRow.id == investigation_id))
        return (cast("CursorResult[Any]", result).rowcount or 0) > 0

    # ------------------------------------------------------- cluster coordination
    async def claim(self, investigation_id: str, owner: str) -> None:
        """Record which instance runs a scan; its heartbeat starts now."""
        async with self.db.session() as s, s.begin():
            await s.execute(
                update(InvestigationRow)
                .where(InvestigationRow.id == investigation_id)
                .values(owner=owner, heartbeat_at=datetime.now(timezone.utc), cancel_requested=False)
            )

    async def heartbeat(self, investigation_id: str) -> bool:
        """Refresh a running scan's heartbeat; returns True if another replica asked to cancel it."""
        async with self.db.session() as s, s.begin():
            await s.execute(
                update(InvestigationRow)
                .where(InvestigationRow.id == investigation_id)
                .values(heartbeat_at=datetime.now(timezone.utc))
            )
            flag = await s.scalar(
                select(InvestigationRow.cancel_requested).where(InvestigationRow.id == investigation_id)
            )
        return bool(flag)

    async def request_cancel(self, investigation_id: str) -> bool:
        """Ask whichever replica owns a running scan to stop it (picked up on its next heartbeat)."""
        async with self.db.session() as s, s.begin():
            result = await s.execute(
                update(InvestigationRow)
                .where(InvestigationRow.id == investigation_id, InvestigationRow.status.in_(ACTIVE_STATUSES))
                .values(cancel_requested=True)
            )
        return (cast("CursorResult[Any]", result).rowcount or 0) > 0

    async def active_scans(self, stale_seconds: float) -> list[dict[str, Any]]:
        """Scans running anywhere in the cluster (owner alive = heartbeat within ``stale_seconds``)."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=stale_seconds)
        async with self.db.session() as s:
            rows = (
                await s.execute(
                    select(InvestigationRow.id, InvestigationRow.owner, InvestigationRow.heartbeat_at).where(
                        InvestigationRow.status.in_(ACTIVE_STATUSES)
                    )
                )
            ).all()
        return [
            {"id": r.id, "owner": r.owner}
            for r in rows
            if r.heartbeat_at is not None and _aware(r.heartbeat_at) >= cutoff
        ]

    async def progress(self, investigation_id: str) -> tuple[str, int, int] | None:
        """Cheap poll for replicas tailing a scan they don't run: (status, nodes, edges)."""
        async with self.db.session() as s:
            row = (
                await s.execute(
                    select(InvestigationRow.status, InvestigationRow.node_count, InvestigationRow.edge_count).where(
                        InvestigationRow.id == investigation_id
                    )
                )
            ).first()
        return (row.status, row.node_count, row.edge_count) if row else None

    async def mark_interrupted(
        self,
        *,
        owned_by: str | None = None,
        stale_seconds: float | None = None,
        exclude: Iterable[str] = (),
        reason: str = "Interrupted: server stopped before the scan finished.",
    ) -> int:
        """Mark scans that can never finish as failed.

        With no arguments every active scan is affected (single-instance restart). In a cluster,
        pass ``owned_by`` (this instance's earlier scans, e.g. after a restart with the same name)
        and/or ``stale_seconds`` (scans whose owner stopped sending heartbeats - it crashed).
        Scans in ``exclude`` (running locally right now) are never touched.
        """
        skip = set(exclude)
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=stale_seconds) if stale_seconds is not None else None
        everything = owned_by is None and stale_seconds is None

        def dead(row: InvestigationRow) -> bool:
            if row.id in skip:
                return False
            if everything or row.owner is None:
                return True
            if owned_by is not None and row.owner == owned_by:
                return True
            beat = _aware(row.heartbeat_at) if row.heartbeat_at else None
            return cutoff is not None and (beat is None or beat < cutoff)

        async with self.db.session() as s, s.begin():
            candidates = (
                (await s.execute(select(InvestigationRow).where(InvestigationRow.status.in_(ACTIVE_STATUSES))))
                .scalars()
                .all()
            )
            rows = [r for r in candidates if dead(r)]
            now = datetime.now(timezone.utc)
            for row in rows:
                data = dict(row.data)
                data["status"] = InvestigationStatus.FAILED.value
                data["completed_at"] = now.isoformat()
                data["errors"] = [*data.get("errors", []), reason]
                await s.execute(
                    update(InvestigationRow)
                    .where(InvestigationRow.id == row.id)
                    # cancel_requested fences the old owner: if it was only frozen, it stops on its
                    # next heartbeat instead of carrying on with a scan the cluster gave up on.
                    .values(status=InvestigationStatus.FAILED.value, completed_at=now, data=data, cancel_requested=True)
                )
        return len(rows)

    # ----------------------------------------------------------------- reads
    async def get_investigation(self, investigation_id: str) -> Investigation | None:
        async with self.db.session() as s:
            row = await s.get(InvestigationRow, investigation_id)
        return Investigation.model_validate(row.data) if row else None

    async def list_investigations(
        self,
        *,
        workspace_id: str,
        limit: int = 50,
        offset: int = 0,
        status: str | None = None,
        target: str | None = None,
    ) -> list[dict[str, Any]]:
        stmt = (
            select(InvestigationRow)
            .where(InvestigationRow.workspace_id == workspace_id)
            .order_by(InvestigationRow.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
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

    async def find_previous(self, inv: Investigation) -> Investigation | None:
        """Most recent *completed* investigation of the same target (and workspace) before this one started."""
        stmt = (
            select(InvestigationRow)
            .where(
                InvestigationRow.workspace_id == inv.workspace_id,
                func.lower(InvestigationRow.target) == inv.config.target.lower(),
                InvestigationRow.target_type == inv.config.target_type.value,
                InvestigationRow.status == InvestigationStatus.COMPLETED.value,
                InvestigationRow.id != inv.id,
                InvestigationRow.created_at < inv.created_at,
            )
            .order_by(InvestigationRow.created_at.desc())
            .limit(1)
        )
        async with self.db.session() as s:
            row = (await s.execute(stmt)).scalars().first()
        return Investigation.model_validate(row.data) if row else None

    async def load_graph(self, investigation_id: str) -> IntelligenceGraph | None:
        async with self.db.session() as s:
            if await s.get(InvestigationRow, investigation_id) is None:
                return None
            ents = (
                (await s.execute(select(EntityRow.data).where(EntityRow.investigation_id == investigation_id)))
                .scalars()
                .all()
            )
            rels = (
                (await s.execute(select(RelationRow.data).where(RelationRow.investigation_id == investigation_id)))
                .scalars()
                .all()
            )

        graph = IntelligenceGraph(investigation_id)
        entities = sorted((Entity.model_validate(e) for e in ents), key=lambda e: e.depth)
        for ent in entities:
            graph.add_entity(ent, is_seed=ent.depth == 0)
        for rel in rels:
            graph.add_relation(Relation.model_validate(rel))
        return graph

    async def search_entities(
        self, query: str, *, workspace_id: str, entity_type: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        """Cross-investigation pivot within one workspace: where else have we seen this IP / email / domain?"""
        stmt = (
            select(EntityRow, InvestigationRow.target, InvestigationRow.created_at)
            .join(InvestigationRow, InvestigationRow.id == EntityRow.investigation_id)
            .where(
                InvestigationRow.workspace_id == workspace_id,
                func.lower(EntityRow.value).contains(query.lower()),
            )
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
    async def _upsert(self, s: AsyncSession, table: Table, rows: Sequence[dict[str, Any]], keys: list[str]) -> None:
        dialect = self.db.dialect
        insert: Any
        if dialect == "sqlite":
            insert = sqlite_insert
        elif dialect == "postgresql":
            insert = pg_insert
        else:  # pragma: no cover - generic fallback for other backends
            for row in rows:
                await s.merge(_row_to_orm(table, row))
            return

        # Update only the columns this write supplies: columns managed elsewhere (e.g. a scan's
        # owner and heartbeat) must survive a checkpoint of the investigation document.
        supplied = set(rows[0]) if rows else set()
        update_cols = [c.name for c in table.columns if c.name not in keys and c.name in supplied]
        for i in range(0, len(rows), UPSERT_CHUNK):
            stmt = insert(table).values(list(rows[i : i + UPSERT_CHUNK]))
            stmt = stmt.on_conflict_do_update(index_elements=keys, set_={c: stmt.excluded[c] for c in update_cols})
            await s.execute(stmt)


def _row_to_orm(table: Table, row: dict[str, Any]):  # pragma: no cover
    model = {t.__table__: t for t in (InvestigationRow, EntityRow, RelationRow)}[table]
    return model(**row)


def _table(model: type[Any]) -> Table:
    """ORM class -> its Table (typed, so the upsert helper can accept it)."""
    return cast(Table, model.__table__)


def _aware(value: datetime) -> datetime:
    """SQLite returns naive datetimes; everything Argus stores is UTC."""
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:  # SQLite drops tzinfo; values are always stored in UTC
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()
