"""breach and dark-web exposure

Revision ID: 0013
Revises: 0012
Create Date: 2026-11-15

Domains (and supplier registers) watched for breached accounts, infostealer infections,
ransomware leak-site posts and breaches of the organisation, and what was found.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "exposure_watches",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("workspace_id", sa.String(length=32), nullable=False),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("domain", sa.String(length=253), nullable=False),
        sa.Column("organisation", sa.String(length=200), nullable=False),
        sa.Column("basis", sa.String(length=300), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("demo", sa.Boolean(), nullable=False),
        sa.Column("interval_hours", sa.Integer(), nullable=False),
        sa.Column("next_check_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("checks", sa.Integer(), nullable=False),
        sa.Column("last_status", sa.String(length=16), nullable=True),
        sa.Column("last_message", sa.String(length=512), nullable=True),
        sa.Column("sources", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("exposure_watches", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_exposure_watches_workspace_id"), ["workspace_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_exposure_watches_next_check_at"), ["next_check_at"], unique=False)
        batch_op.create_index("ux_exposure_watches_scope", ["workspace_id", "scope", "domain"], unique=True)

    op.create_table(
        "exposure_findings",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("workspace_id", sa.String(length=32), nullable=False),
        sa.Column("watch_id", sa.String(length=32), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("subject", sa.String(length=253), nullable=False),
        sa.Column("subject_name", sa.String(length=200), nullable=False),
        sa.Column("supplier_id", sa.String(length=32), nullable=True),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("account", sa.String(length=320), nullable=True),
        sa.Column("occurred_at", sa.String(length=32), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", sa.String(length=128), nullable=True),
        sa.Column("note", sa.String(length=500), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["watch_id"], ["exposure_watches.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("exposure_findings", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_exposure_findings_watch_id"), ["watch_id"], unique=False)
        batch_op.create_index("ux_exposure_findings_key", ["workspace_id", "key_hash"], unique=True)
        batch_op.create_index("ix_exposure_findings_status", ["workspace_id", "status"], unique=False)


def downgrade() -> None:
    op.drop_table("exposure_findings")
    op.drop_table("exposure_watches")
