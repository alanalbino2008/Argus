"""Database engine, ORM tables and session management.

Design: each row keeps a few *indexed* columns that we query on (status,
target, entity type/value) plus the full Pydantic model as a JSON document.
The JSON copy means adding a field to a model never needs a schema change,
while the indexed columns keep listing and cross-investigation search fast.
Works unchanged on SQLite (default) and PostgreSQL.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String, event
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

SCHEMA_VERSION = 1


class Base(DeclarativeBase):
    type_annotation_map = {Dict[str, Any]: JSON}


class InvestigationRow(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    target: Mapped[str] = mapped_column(String(512), index=True)
    target_type: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    node_count: Mapped[int] = mapped_column(Integer, default=0)
    edge_count: Mapped[int] = mapped_column(Integer, default=0)
    data: Mapped[Dict[str, Any]] = mapped_column(JSON)


class EntityRow(Base):
    __tablename__ = "entities"

    investigation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("investigations.id", ondelete="CASCADE"), primary_key=True
    )
    entity_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    type: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(String(2048))
    label: Mapped[str] = mapped_column(String(2048))
    data: Mapped[Dict[str, Any]] = mapped_column(JSON)

    __table_args__ = (
        Index("ix_entities_type_value", "type", "value"),
        Index("ix_entities_entity_id", "entity_id"),
    )


class RelationRow(Base):
    __tablename__ = "relations"

    investigation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("investigations.id", ondelete="CASCADE"), primary_key=True
    )
    relation_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source_id: Mapped[str] = mapped_column(String(64))
    target_id: Mapped[str] = mapped_column(String(64))
    type: Mapped[str] = mapped_column(String(32))
    data: Mapped[Dict[str, Any]] = mapped_column(JSON)


class Database:
    """Owns the async engine and session factory for one database URL."""

    def __init__(self, url: str, echo: bool = False):
        self.url = make_url(url)
        kwargs: Dict[str, Any] = {"echo": echo, "pool_pre_ping": True}
        if self.url.get_backend_name() == "sqlite":
            database = self.url.database
            if database and database != ":memory:":
                Path(database).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self.engine: AsyncEngine = create_async_engine(self.url, **kwargs)
        if self.url.get_backend_name() == "sqlite":
            event.listen(self.engine.sync_engine, "connect", _sqlite_pragmas)
        self.sessionmaker = async_sessionmaker(self.engine, expire_on_commit=False)

    @property
    def dialect(self) -> str:
        return self.engine.dialect.name

    async def create_all(self) -> None:
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    def session(self) -> AsyncSession:
        return self.sessionmaker()

    async def dispose(self) -> None:
        await self.engine.dispose()


def _sqlite_pragmas(dbapi_conn, _record) -> None:
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA foreign_keys=ON")      # enforce ON DELETE CASCADE
    cur.execute("PRAGMA journal_mode=WAL")     # readers don't block the writer
    cur.execute("PRAGMA synchronous=NORMAL")   # safe with WAL, much faster
    cur.close()
