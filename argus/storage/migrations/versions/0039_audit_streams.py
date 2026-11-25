"""audit streams: forwarding the audit log to a SIEM, with a checkpoint

Revision ID: 0039
Revises: 0038
Create Date: 2026-11-25
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0039"
down_revision: str | None = "0038"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_streams",
        sa.Column("id", sa.String(length=32), primary_key=True),
        sa.Column("workspace_id", sa.String(length=32), nullable=False),
        sa.Column("platform", sa.Boolean(), nullable=False),
        sa.Column("channel_id", sa.String(length=32), nullable=False),
        sa.Column("last_id", sa.BigInteger(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("sent", sa.BigInteger(), nullable=False),
        sa.Column("last_sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=500), nullable=True),
        sa.Column("failing_since", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_streams_workspace_id", "audit_streams", ["workspace_id"])


def downgrade() -> None:
    op.drop_index("ix_audit_streams_workspace_id", table_name="audit_streams")
    op.drop_table("audit_streams")
