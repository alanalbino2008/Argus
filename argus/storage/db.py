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

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    event,
    false,
    text,
    true,
)
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from argus.security.vault import EncryptedBytes, EncryptedJSON, EncryptedLongText, EncryptedText

SCHEMA_VERSION = 1


class Base(DeclarativeBase):
    type_annotation_map: ClassVar[dict[Any, Any]] = {dict[str, Any]: JSON}


class InvestigationRow(Base):
    __tablename__ = "investigations"
    workspace_id: Mapped[str] = mapped_column(String(32), index=True, server_default="ws_default")

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    target: Mapped[str] = mapped_column(EncryptedText(512, label="investigations.target"), index=True)
    target_type: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    node_count: Mapped[int] = mapped_column(Integer, default=0)
    edge_count: Mapped[int] = mapped_column(Integer, default=0)
    data: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON(label="investigations.data"))
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
    value: Mapped[str] = mapped_column(EncryptedText(2048, label="entities.value"))
    label: Mapped[str] = mapped_column(EncryptedText(2048, label="entities.label"))
    data: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON(label="entities.data"))

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
    data: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON(label="relations.data"))


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


class SubscriberAccountRow(Base):
    """An Argus subscription account (account service): who may use the personal edition, on which plan."""

    __tablename__ = "subscriber_accounts"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True)  # stored lower-case
    name: Mapped[str] = mapped_column(String(255), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    plan: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16))  # trialing | active | past_due | cancelled | suspended
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))  # end of the paid or trial period
    max_devices: Mapped[int | None] = mapped_column(Integer, nullable=True)  # None: the plan's default
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    billing_reference: Mapped[str] = mapped_column(String(255), default="")  # e.g. a payment provider's customer id
    allowance_month: Mapped[str] = mapped_column(String(7), default="", server_default="")  # "2026-11"
    allowance_remaining: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    purchased_credits: Mapped[int] = mapped_column(Integer, default=0, server_default="0")  # never expire
    reminder_emails: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())  # trial reminders
    team_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)  # the team owner's account
    seats: Mapped[int] = mapped_column(Integer, default=1, server_default="1")  # a team owner: seats paid for
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    terms_version: Mapped[str] = mapped_column(String(32), default="", server_default="")  # accepted version
    terms_accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)  # details erased


class SubscriberDeviceRow(Base):
    """A computer signed in to an Argus account (each holds its own licence)."""

    __tablename__ = "subscriber_devices"
    __table_args__ = (Index("ux_subscriber_devices", "account_id", "device_id", unique=True),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    account_id: Mapped[str] = mapped_column(String(32), ForeignKey("subscriber_accounts.id", ondelete="CASCADE"))
    device_id: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(128), default="")
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class CreditLedgerRow(Base):
    """Every change to an account's Argus credits: allowance, purchase, use, refund, adjustment."""

    __tablename__ = "credit_ledger"
    __table_args__ = (Index("ix_credit_ledger_account", "account_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    account_id: Mapped[str] = mapped_column(String(32), ForeignKey("subscriber_accounts.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(16))  # allowance | purchase | usage | refund | adjustment
    delta: Mapped[int] = mapped_column(Integer)
    balance_after: Mapped[int] = mapped_column(Integer)
    detail: Mapped[str] = mapped_column(String(255), default="")  # e.g. "companies_house/officers"
    used_by: Mapped[str] = mapped_column(String(32), default="", server_default="")  # a team member's account
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class TeamInviteRow(Base):
    """An invitation to join a team (only its hash is kept); single use, a week to accept."""

    __tablename__ = "team_invites"
    __table_args__ = (Index("ix_team_invites_team", "team_id", "created_at"),)

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    team_id: Mapped[str] = mapped_column(String(32), ForeignKey("subscriber_accounts.id", ondelete="CASCADE"))
    email: Mapped[str] = mapped_column(String(320))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancelled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AccountEmailRow(Base):
    """An email to an account holder (account service): queued, sent once, retried if the mail server fails."""

    __tablename__ = "account_emails"
    __table_args__ = (Index("ix_account_emails_due", "status", "next_attempt_at"),
                      Index("ix_account_emails_account", "account_id", "created_at"))  # fmt: skip

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    account_id: Mapped[str] = mapped_column(String(32), ForeignKey("subscriber_accounts.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(32))
    dedupe_key: Mapped[str] = mapped_column(String(255), unique=True)  # each email at most once
    recipient: Mapped[str] = mapped_column(String(320))
    subject: Mapped[str] = mapped_column(String(255))
    body_text: Mapped[str] = mapped_column(Text, default="")  # cleared once sent (or given up on)
    body_html: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16))  # pending | sent | failed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PasswordResetRow(Base):
    """A password reset link (only its hash is kept); single use, short-lived."""

    __tablename__ = "password_resets"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    account_id: Mapped[str] = mapped_column(String(32), ForeignKey("subscriber_accounts.id", ondelete="CASCADE"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class BillingPaymentRow(Base):
    """A payment Argus may have to undo: credits it bought, and any refund or dispute of it."""

    __tablename__ = "billing_payments"
    __table_args__ = (Index("ix_billing_payments_account", "account_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(255), primary_key=True)  # the provider's payment id (pi_..., ch_...)
    account_id: Mapped[str] = mapped_column(String(32), ForeignKey("subscriber_accounts.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(16))  # credits | subscription
    credits: Mapped[int] = mapped_column(Integer, default=0)  # credits this payment bought
    amount: Mapped[int] = mapped_column(Integer, default=0)  # in the currency's smallest unit
    currency: Mapped[str] = mapped_column(String(8), default="")
    refunded: Mapped[int] = mapped_column(Integer, default=0)  # amount refunded so far
    refund_credits_taken: Mapped[int] = mapped_column(Integer, default=0)
    dispute_id: Mapped[str] = mapped_column(String(255), default="")
    dispute_status: Mapped[str] = mapped_column(String(32), default="")  # open | won | lost
    dispute_credits_taken: Mapped[int] = mapped_column(Integer, default=0)
    status_before_hold: Mapped[str] = mapped_column(String(16), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class BillingEventRow(Base):
    """A payment provider event already applied (each is applied once, however often it is re-sent)."""

    __tablename__ = "billing_events"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)  # the provider's event id
    type: Mapped[str] = mapped_column(String(64))
    account_id: Mapped[str] = mapped_column(String(32), default="")
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class OwnerRow(Base):
    """The one owner of this Argus server (the owner console). There is never more than one row."""

    __tablename__ = "owner"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)  # always "owner"
    email: Mapped[str] = mapped_column(String(320))
    password_hash: Mapped[str] = mapped_column(String(255))
    totp_sealed: Mapped[str] = mapped_column(Text)  # the authenticator secret, encrypted
    totp_last_counter: Mapped[int] = mapped_column(Integer, default=-1)  # no code is accepted twice
    recovery_hashes: Mapped[list[str]] = mapped_column(JSON, default=list)  # one-time codes, hashed
    failed: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class OwnerSessionRow(Base):
    """A signed-in owner console session (only its hash is kept)."""

    __tablename__ = "owner_sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    stage: Mapped[str] = mapped_column(String(16))  # "code": password accepted, waiting for the code; "full"
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)  # last code
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")


class AppStateRow(Base):
    """Small facts about this installation (its device id, the personal edition's licence...)."""

    __tablename__ = "app_state"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


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
    details: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON(label="audit_events.details"))
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class MonitorRow(Base):
    """A target re-scanned on a schedule; material changes between scans raise alerts."""

    __tablename__ = "monitors"
    workspace_id: Mapped[str] = mapped_column(String(32), index=True, server_default="ws_default")

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    target: Mapped[str] = mapped_column(EncryptedText(512, label="monitors.target"))
    target_type: Mapped[str] = mapped_column(String(32))
    max_depth: Mapped[int] = mapped_column(Integer, default=2)
    passive_only: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    interval_hours: Mapped[int] = mapped_column(Integer)
    purpose: Mapped[str] = mapped_column(EncryptedText(500, label="monitors.purpose"))
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
    target: Mapped[str] = mapped_column(EncryptedText(512, label="alerts.target"))
    severity: Mapped[str] = mapped_column(String(16))
    headline: Mapped[str] = mapped_column(EncryptedText(1024, label="alerts.headline"))
    summary: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON(label="alerts.summary"))
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
    payload: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON(label="notification_deliveries.payload"))
    status: Mapped[str] = mapped_column(String(16))  # pending | sending | delivered | failed | cancelled
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    claimed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # What the receiver created, e.g. a Jira issue key or ServiceNow incident number.
    reference: Mapped[str | None] = mapped_column(String(128), nullable=True)


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
    target: Mapped[str] = mapped_column(EncryptedText(512, label="reports.target"))
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
    target: Mapped[str] = mapped_column(EncryptedText(512, label="report_schedules.target"))
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
    pdf: Mapped[bytes] = mapped_column(EncryptedBytes(label="report_files.pdf"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class RatingRow(Base):
    """A computed security rating for one completed investigation (cached; recomputed if the methodology changes)."""

    __tablename__ = "ratings"

    investigation_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(32), index=True)
    target: Mapped[str] = mapped_column(String(512), index=True)  # lower-cased
    methodology: Mapped[str] = mapped_column(String(32))
    score: Mapped[float] = mapped_column(Float)
    grade: Mapped[str] = mapped_column(String(2))
    confidence: Mapped[float] = mapped_column(Float)
    data: Mapped[dict[str, Any]] = mapped_column(JSON)
    assessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class SupplierRow(Base):
    """A third party in the workspace's supplier register, assessed passively on a schedule."""

    __tablename__ = "suppliers"
    __table_args__ = (Index("ux_suppliers_workspace_domain", "workspace_id", "domain", unique=True),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(32), ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    domain: Mapped[str] = mapped_column(String(253))
    tier: Mapped[str] = mapped_column(String(16))
    data_access: Mapped[str] = mapped_column(String(16))
    owner: Mapped[str] = mapped_column(String(200), default="")
    notes: Mapped[str] = mapped_column(String(500), default="")
    min_grade_override: Mapped[str | None] = mapped_column(String(1), nullable=True)
    monitor_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_grade: Mapped[str | None] = mapped_column(String(1), nullable=True)
    last_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    last_investigation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_assessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(128))
    basis: Mapped[str] = mapped_column(String(300))  # why assessing this third party is legitimate


class ExposureWatchRow(Base):
    """A domain (or a workspace's whole supplier register) checked for breach and dark-web exposure."""

    __tablename__ = "exposure_watches"
    __table_args__ = (Index("ux_exposure_watches_scope", "workspace_id", "scope", "domain", unique=True),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(32), ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
    scope: Mapped[str] = mapped_column(String(16))  # "domain" | "suppliers"
    domain: Mapped[str] = mapped_column(String(253), default="")  # empty for the supplier sweep
    organisation: Mapped[str] = mapped_column(String(200), default="")
    basis: Mapped[str] = mapped_column(String(300))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    demo: Mapped[bool] = mapped_column(Boolean, default=False)
    interval_hours: Mapped[int] = mapped_column(Integer, default=24)
    next_check_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    checks: Mapped[int] = mapped_column(Integer, default=0)  # completed checks; the first is the baseline
    last_status: Mapped[str | None] = mapped_column(String(16), nullable=True)  # ok | partial | error
    last_message: Mapped[str | None] = mapped_column(String(512), nullable=True)
    sources: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)  # what each source said last time
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(128))


class ExposureFindingRow(Base):
    """One piece of exposure (a breached account, an infostealer infection, a leak-site post...)."""

    __tablename__ = "exposure_findings"
    __table_args__ = (
        Index("ux_exposure_findings_key", "workspace_id", "key_hash", unique=True),
        Index("ix_exposure_findings_status", "workspace_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(32), ForeignKey("workspaces.id", ondelete="CASCADE"))
    watch_id: Mapped[str] = mapped_column(String(32), ForeignKey("exposure_watches.id", ondelete="CASCADE"), index=True)
    key_hash: Mapped[str] = mapped_column(String(64))  # SHA-256 of the finding's stable key
    subject: Mapped[str] = mapped_column(String(253))  # the domain concerned
    subject_name: Mapped[str] = mapped_column(String(200), default="")
    supplier_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    kind: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(512))
    account: Mapped[str | None] = mapped_column(String(320), nullable=True)  # personal data: masked in the API
    occurred_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16), default="open")  # open | resolved | accepted
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    note: Mapped[str] = mapped_column(String(500), default="")


class RemediationTaskRow(Base):
    """A piece of remediation work: from an attack path, an exposure finding, a supplier, or a person."""

    __tablename__ = "remediation_tasks"
    __table_args__ = (
        Index("ux_remediation_source", "workspace_id", "source_type", "source_key", unique=True),
        Index("ix_remediation_status", "workspace_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(32), ForeignKey("workspaces.id", ondelete="CASCADE"))
    source_type: Mapped[str] = mapped_column(String(16))  # attack_path | exposure | supplier | manual
    source_key: Mapped[str | None] = mapped_column(String(300), nullable=True)  # one task per source finding
    target: Mapped[str] = mapped_column(String(253), default="")
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(String(4000), default="")
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16))  # open | in_progress | fixed | verified | accepted
    assignee: Mapped[str | None] = mapped_column(String(128), nullable=True)
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    accepted_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    external_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)  # e.g. a Jira key
    details: Mapped[dict[str, Any]] = mapped_column(JSON)
    reopen_count: Mapped[int] = mapped_column(Integer, default=0)
    verified_by: Mapped[str | None] = mapped_column(String(128), nullable=True)  # a scan id or a person
    overdue_alerted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(128))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RemediationEventRow(Base):
    """A task's timeline: created, assigned, status changes, comments, scan verifications."""

    __tablename__ = "remediation_events"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    task_id: Mapped[str] = mapped_column(String(32), ForeignKey("remediation_tasks.id", ondelete="CASCADE"), index=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    by: Mapped[str] = mapped_column(String(128))
    kind: Mapped[str] = mapped_column(String(16))  # created | status | assigned | due | comment | verified | reopened
    text: Mapped[str] = mapped_column(String(2000), default="")
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)


class RemediationPolicyRow(Base):
    """A workspace's remediation deadlines and automation."""

    __tablename__ = "remediation_policies"

    workspace_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("workspaces.id", ondelete="CASCADE"), primary_key=True
    )
    sla_days: Mapped[dict[str, Any]] = mapped_column(JSON)
    auto_create: Mapped[str] = mapped_column(String(16), default="off")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_by: Mapped[str] = mapped_column(String(128))


class CaseRow(Base):
    """An investigation as a body of work: its purpose, notes, people, links, timeline and evidence."""

    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(32), ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(EncryptedText(200, label="cases.title"))
    purpose: Mapped[str] = mapped_column(EncryptedText(500, label="cases.purpose"))
    summary: Mapped[str] = mapped_column(EncryptedLongText(label="cases.summary"), default="")
    status: Mapped[str] = mapped_column(String(16), default="open")  # open | closed | archived
    restricted: Mapped[bool] = mapped_column(Boolean, default=False)  # only the owner and members can open it
    members: Mapped[list[str]] = mapped_column(JSON)
    tags: Mapped[list[str]] = mapped_column(JSON)
    egress: Mapped[str] = mapped_column(String(32), default="", server_default="")  # route name; "" is direct
    opsec_mode: Mapped[str] = mapped_column(String(16), default="standard", server_default="standard")  # | anonymous
    created_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class AccountWatchRow(Base):
    """An online account a case keeps an eye on: its profile is re-read and changes are recorded."""

    __tablename__ = "account_watches"
    __table_args__ = (Index("ux_account_watches_case", "case_id", "platform", "handle", unique=True),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(32), ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[str] = mapped_column(String(32), ForeignKey("cases.id", ondelete="CASCADE"))
    platform: Mapped[str] = mapped_column(String(80))
    handle: Mapped[str] = mapped_column(String(128))
    profile_url: Mapped[str] = mapped_column(EncryptedText(512, label="account_watches.profile_url"))
    interval_hours: Mapped[int] = mapped_column(Integer, default=24)
    capture_on_change: Mapped[bool] = mapped_column(Boolean, default=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending | active | gone | error
    message: Mapped[str] = mapped_column(EncryptedText(512, label="account_watches.message"), default="")
    snapshot: Mapped[dict[str, Any] | None] = mapped_column(
        EncryptedJSON(label="account_watches.snapshot"), nullable=True
    )  # the profile as last seen
    missing_count: Mapped[int] = mapped_column(Integer, default=0)  # consecutive "not there" observations
    changes_count: Mapped[int] = mapped_column(Integer, default=0)
    next_check_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AccountSnapshotRow(Base):
    """A watched account's profile when first seen and each time it changed."""

    __tablename__ = "account_snapshots"
    __table_args__ = (Index("ix_account_snapshots_watch", "watch_id", "taken_at"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    watch_id: Mapped[str] = mapped_column(String(32), ForeignKey("account_watches.id", ondelete="CASCADE"))
    taken_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    exists: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    facts: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON(label="account_snapshots.facts"))
    changes: Mapped[list[dict[str, Any]]] = mapped_column(EncryptedJSON(label="account_snapshots.changes"))
    capture_id: Mapped[str | None] = mapped_column(String(32), nullable=True)  # evidence taken at the time


class PlaybookRunRow(Base):
    """One run of a playbook in a case: its steps as they ran, and what stood out."""

    __tablename__ = "playbook_runs"
    __table_args__ = (Index("ix_playbook_runs_case", "case_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(32))
    case_id: Mapped[str] = mapped_column(String(32), ForeignKey("cases.id", ondelete="CASCADE"))
    playbook: Mapped[str] = mapped_column(String(64))
    seed: Mapped[str] = mapped_column(EncryptedText(500, label="playbook_runs.seed"))
    seed_type: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16))  # running | completed | failed | cancelled | interrupted
    data: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON(label="playbook_runs.data")
    )  # steps, highlights, options
    created_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SavedQueryRow(Base):
    """A named Argus Query Language query, optionally checked after every scan (alerting on new matches)."""

    __tablename__ = "saved_queries"
    __table_args__ = (Index("ix_saved_queries_workspace", "workspace_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(32), ForeignKey("workspaces.id", ondelete="CASCADE"))
    data: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON(label="saved_queries.data"))  # name, query, description
    alert: Mapped[bool] = mapped_column(Boolean, default=False)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    created_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_alert_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    alerts_raised: Mapped[int] = mapped_column(Integer, default=0)


class EntityAnnotationRow(Base):
    """The team's tags and note on an entity. Entity ids are derived from type and value, so one
    annotation applies to that entity in every investigation of the workspace, past and future."""

    __tablename__ = "entity_annotations"
    __table_args__ = (Index("ux_entity_annotations", "workspace_id", "entity_id", unique=True),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(32), ForeignKey("workspaces.id", ondelete="CASCADE"))
    entity_id: Mapped[str] = mapped_column(String(64))
    entity_type: Mapped[str] = mapped_column(String(32))
    data: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON(label="entity_annotations.data"))  # value, tags, note
    updated_by: Mapped[str] = mapped_column(String(128))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class FingerprintWatchRow(Base):
    """A fingerprint whose internet-wide search is re-run on a schedule; new servers raise an alert."""

    __tablename__ = "fingerprint_watches"
    __table_args__ = (Index("ux_fingerprint_watches", "workspace_id", "engine", "entity_id", unique=True),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(32), ForeignKey("workspaces.id", ondelete="CASCADE"))
    engine: Mapped[str] = mapped_column(String(16))  # shodan | censys
    entity_id: Mapped[str] = mapped_column(String(64))
    investigation_id: Mapped[str] = mapped_column(String(64))  # where it was watched from (alert links)
    data: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON(label="fingerprint_watches.data"))  # label, query, known
    interval_hours: Mapped[int] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String(16))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    last_total: Mapped[int | None] = mapped_column(Integer, nullable=True)
    alerts_raised: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class CaseItemRow(Base):
    """Something in a case: a note, a person or other entity, a link between two, a scan, an event."""

    __tablename__ = "case_items"
    __table_args__ = (Index("ix_case_items_case_kind", "case_id", "kind"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    case_id: Mapped[str] = mapped_column(String(32), ForeignKey("cases.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(16))  # note | entity | link | scan | event
    title: Mapped[str] = mapped_column(EncryptedText(300, label="case_items.title"))
    body: Mapped[str] = mapped_column(EncryptedLongText(label="case_items.body"), default="")
    data: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON(label="case_items.data"))
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class EvidenceCaptureRow(Base):
    """A preserved web page or uploaded file, with its manifest, digest and optional trusted timestamp."""

    __tablename__ = "evidence_captures"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    case_id: Mapped[str] = mapped_column(String(32), ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    workspace_id: Mapped[str] = mapped_column(String(32))
    kind: Mapped[str] = mapped_column(String(16))  # web | upload
    url: Mapped[str | None] = mapped_column(EncryptedText(2048, label="evidence_captures.url"), nullable=True)
    title: Mapped[str] = mapped_column(EncryptedText(300, label="evidence_captures.title"), default="")
    note: Mapped[str] = mapped_column(EncryptedText(1000, label="evidence_captures.note"), default="")
    digest: Mapped[str] = mapped_column(String(64), index=True)  # SHA-256 of the canonical manifest
    manifest: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON(label="evidence_captures.manifest"))
    timestamp_token: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)  # RFC 3161 reply
    warnings: Mapped[list[str]] = mapped_column(EncryptedJSON(label="evidence_captures.warnings"))
    captured_by: Mapped[str] = mapped_column(String(128))
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class EvidenceFileRow(Base):
    __tablename__ = "evidence_files"

    capture_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("evidence_captures.id", ondelete="CASCADE"), primary_key=True
    )
    name: Mapped[str] = mapped_column(String(200), primary_key=True)
    media_type: Mapped[str] = mapped_column(String(128))
    sha256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(Integer)
    data: Mapped[bytes] = mapped_column(EncryptedBytes(label="evidence_files.data"))


class EvidenceCustodyRow(Base):
    """Chain of custody: who did what with a piece of evidence, each entry chained to the last by hash."""

    __tablename__ = "evidence_custody"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    capture_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("evidence_captures.id", ondelete="CASCADE"), index=True
    )
    seq: Mapped[int] = mapped_column(Integer)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    by: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(32))  # captured | viewed | downloaded | exported | verified
    detail: Mapped[str] = mapped_column(EncryptedText(500, label="evidence_custody.detail"), default="")
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


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
    cur.execute("PRAGMA secure_delete=ON")  # deleted and overwritten data is zeroed, not left in free pages
    cur.execute("PRAGMA journal_mode=WAL")  # readers don't block the writer
    cur.execute("PRAGMA synchronous=NORMAL")  # safe with WAL, much faster
    cur.close()
