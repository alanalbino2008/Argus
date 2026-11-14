"""Database engine, ORM tables and session management.

Design: each row keeps a few *indexed* columns that we query on (status,
target, entity type/value) plus the full Pydantic model as a JSON document.
The JSON copy means adding a field to a model never needs a schema change,
while the indexed columns keep listing and cross-investigation search fast.
Works unchanged on SQLite (default) and PostgreSQL.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, LargeBinary, String, event, false, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

SCHEMA_VERSION = 1


class Base(DeclarativeBase):
    type_annotation_map: ClassVar[dict[Any, Any]] = {dict[str, Any]: JSON}


class InvestigationRow(Base):
    __tablename__ = "investigations"
    workspace_id: Mapped[str] = mapped_column(String(32), index=True, server_default="ws_default")

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    target: Mapped[str] = mapped_column(String(512), index=True)
    target_type: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    node_count: Mapped[int] = mapped_column(Integer, default=0)
    edge_count: Mapped[int] = mapped_column(Integer, default=0)
    data: Mapped[dict[str, Any]] = mapped_column(JSON)
    # Cluster coordination (several API replicas share one database):
    owner: Mapped[str | None] = mapped_column(String(128), nullable=True)  # instance running the scan
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())


class EntityRow(Base):
    __tablename__ = "entities"

    investigation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("investigations.id", ondelete="CASCADE"), primary_key=True
    )
    entity_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    type: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(String(2048))
    label: Mapped[str] = mapped_column(String(2048))
    data: Mapped[dict[str, Any]] = mapped_column(JSON)

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
    data: Mapped[dict[str, Any]] = mapped_column(JSON)


class ApiKeyRow(Base):
    """API credentials. Only a SHA-256 hash of each key is stored, never the key itself."""

    __tablename__ = "api_keys"
    # None = a platform-wide key (administers every workspace); otherwise bound to one workspace.
    workspace_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    prefix: Mapped[str] = mapped_column(String(16))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    role: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class WsTicketRow(Base):
    """Single-use WebSocket tickets, shared by every replica (only a SHA-256 hash is stored)."""

    __tablename__ = "ws_tickets"
    workspace_id: Mapped[str | None] = mapped_column(String(32), nullable=True)

    ticket_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    key_id: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(16))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class WorkspaceRow(Base):
    """A team's private space: its investigations, monitors, alerts, keys and audit trail."""

    __tablename__ = "workspaces"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str | None] = mapped_column(String(128), nullable=True)


class WorkspaceMemberRow(Base):
    """A user's role inside one workspace."""

    __tablename__ = "workspace_members"

    workspace_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("workspaces.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[str] = mapped_column(String(32), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    role: Mapped[str] = mapped_column(String(16))
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    added_by: Mapped[str | None] = mapped_column(String(128), nullable=True)


class UserRow(Base):
    """A person who signs in through the organisation's identity provider (OIDC)."""

    __tablename__ = "users"
    __table_args__ = (Index("ux_users_issuer_subject", "issuer", "subject", unique=True),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    issuer: Mapped[str] = mapped_column(String(512))
    subject: Mapped[str] = mapped_column(String(255))  # the provider's stable user id ("sub")
    email: Mapped[str | None] = mapped_column(String(320), nullable=True, index=True)
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role: Mapped[str] = mapped_column(String(16))
    disabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SessionRow(Base):
    """A signed-in browser. Only a SHA-256 hash of the cookie value is stored."""

    __tablename__ = "sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)


class OidcLoginRow(Base):
    """An OIDC login in progress (state, nonce, PKCE verifier) - single use, minutes long, cluster-wide."""

    __tablename__ = "oidc_logins"

    state_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    nonce: Mapped[str] = mapped_column(String(128))
    code_verifier: Mapped[str] = mapped_column(String(128))
    return_to: Mapped[str] = mapped_column(String(512))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class AuditEventRow(Base):
    """Append-only, hash-chained security audit trail."""

    __tablename__ = "audit_events"
    workspace_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[str] = mapped_column(String(40), index=True)  # ISO-8601 UTC string: part of the hash
    actor_id: Mapped[str] = mapped_column(String(64), index=True)
    actor_name: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64), index=True)
    resource: Mapped[str | None] = mapped_column(String(256), nullable=True)
    outcome: Mapped[str] = mapped_column(String(16))
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class MonitorRow(Base):
    """A target re-scanned on a schedule; material changes between scans raise alerts."""

    __tablename__ = "monitors"
    workspace_id: Mapped[str] = mapped_column(String(32), index=True, server_default="ws_default")

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    target: Mapped[str] = mapped_column(String(512))
    target_type: Mapped[str] = mapped_column(String(32))
    max_depth: Mapped[int] = mapped_column(Integer, default=2)
    passive_only: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    interval_hours: Mapped[int] = mapped_column(Integer)
    purpose: Mapped[str] = mapped_column(String(500))
    created_by: Mapped[str] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_investigation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)


class AlertRow(Base):
    """Material attack-surface drift detected by a monitor."""

    __tablename__ = "alerts"
    workspace_id: Mapped[str] = mapped_column(String(32), index=True, server_default="ws_default")

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    monitor_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    investigation_id: Mapped[str] = mapped_column(String(64))
    previous_investigation_id: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(16))
    headline: Mapped[str] = mapped_column(String(1024))
    summary: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_by: Mapped[str | None] = mapped_column(String(128), nullable=True)


class NotificationChannelRow(Base):
    """Where a workspace's alerts are sent: Slack, Microsoft Teams, email or a signed webhook."""

    __tablename__ = "notification_channels"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(32), ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128))
    type: Mapped[str] = mapped_column(String(16))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    min_severity: Mapped[str] = mapped_column(String(16))
    # Non-secret settings and display hints (destination host, recipients).
    config: Mapped[dict[str, Any]] = mapped_column(JSON)
    # URL and signing secrets, AES-256-GCM encrypted and bound to this row (argus/security/crypto.py).
    sealed: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_failure_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(512), nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)


class NotificationDeliveryRow(Base):
    """Transactional outbox: one event for one channel, retried until delivered or given up."""

    __tablename__ = "notification_deliveries"
    __table_args__ = (Index("ix_notification_deliveries_due", "status", "next_attempt_at"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(32), index=True)
    channel_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("notification_channels.id", ondelete="CASCADE"), index=True
    )
    event_type: Mapped[str] = mapped_column(String(64))
    event_id: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16))  # pending | sending | delivered | failed | cancelled
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    claimed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ReportBrandingRow(Base):
    """How a workspace's client reports look: organisation name, accent colour, logo."""

    __tablename__ = "report_branding"

    workspace_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("workspaces.id", ondelete="CASCADE"), primary_key=True
    )
    organisation: Mapped[str] = mapped_column(String(128))
    accent: Mapped[str] = mapped_column(String(7))
    footer_note: Mapped[str] = mapped_column(String(200), default="")
    logo_png: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)  # re-encoded, metadata stripped
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_by: Mapped[str | None] = mapped_column(String(128), nullable=True)


class ReportRow(Base):
    """Every report issued, with the SHA-256 of the exact file, so a copy can be verified later."""

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(32), index=True)
    investigation_id: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(512))
    sha256: Mapped[str] = mapped_column(String(64), unique=True)
    size: Mapped[int] = mapped_column(Integer)
    tlp: Mapped[str] = mapped_column(String(16))
    prepared_for: Mapped[str | None] = mapped_column(String(200), nullable=True)
    issued_by_org: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_by: Mapped[str] = mapped_column(String(128))


class ReportScheduleRow(Base):
    """A report generated and sent automatically, e.g. every Monday at 08:00 Europe/London."""

    __tablename__ = "report_schedules"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(32), ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128))
    target: Mapped[str] = mapped_column(String(512))
    frequency: Mapped[str] = mapped_column(String(16))
    weekday: Mapped[int | None] = mapped_column(Integer, nullable=True)
    day_of_month: Mapped[int | None] = mapped_column(Integer, nullable=True)
    hour: Mapped[int] = mapped_column(Integer)
    minute: Mapped[int] = mapped_column(Integer)
    timezone: Mapped[str] = mapped_column(String(64))
    options: Mapped[dict[str, Any]] = mapped_column(JSON)
    channel_ids: Mapped[list[str]] = mapped_column(JSON)
    skip_unchanged: Mapped[bool] = mapped_column(Boolean, default=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_message: Mapped[str | None] = mapped_column(String(512), nullable=True)
    last_report_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_investigation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(128))


class ReportFileRow(Base):
    """The PDF of a scheduled report, kept for a limited time so email retries can attach it."""

    __tablename__ = "report_files"

    report_id: Mapped[str] = mapped_column(String(32), ForeignKey("reports.id", ondelete="CASCADE"), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(32), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    pdf: Mapped[bytes] = mapped_column(LargeBinary)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class Database:
    """Owns the async engine and session factory for one database URL."""

    def __init__(self, url: str, echo: bool = False):
        self.url = make_url(url)
        kwargs: dict[str, Any] = {"echo": echo, "pool_pre_ping": True}
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

    @asynccontextmanager
    async def cluster_lock(self, key: int) -> AsyncIterator[None]:
        """Run a check-then-act step on one replica at a time (PostgreSQL advisory lock).

        A no-op on SQLite, which is a single-node backend.
        """
        if self.dialect != "postgresql":
            yield
            return
        async with self.engine.connect() as conn:
            await conn.execute(text("SELECT pg_advisory_lock(:k)"), {"k": key})
            try:
                yield
            finally:
                await conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": key})

    async def dispose(self) -> None:
        await self.engine.dispose()


def _sqlite_pragmas(dbapi_conn, _record) -> None:
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA foreign_keys=ON")  # enforce ON DELETE CASCADE
    cur.execute("PRAGMA journal_mode=WAL")  # readers don't block the writer
    cur.execute("PRAGMA synchronous=NORMAL")  # safe with WAL, much faster
    cur.close()
