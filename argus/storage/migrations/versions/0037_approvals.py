"""two-person approval: per-workspace policy and approval requests

Revision ID: 0037
Revises: 0036
Create Date: 2026-11-25
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0037"
down_revision: str | None = "0036"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "approval_policies",
        sa.Column("workspace_id", sa.String(length=32), primary_key=True),
        sa.Column("actions", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(length=128), nullable=False),
    )
    op.create_table(
        "approvals",
        sa.Column("id", sa.String(length=32), primary_key=True),
        sa.Column("workspace_id", sa.String(length=32), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("resource", sa.String(length=128), nullable=False),
        sa.Column("summary", sa.String(length=500), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=False),
        sa.Column("requested_by", sa.String(length=128), nullable=False),
        sa.Column("requested_key", sa.String(length=64), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("decided_by", sa.String(length=128), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_note", sa.String(length=500), nullable=True),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_approvals_ws_status", "approvals", ["workspace_id", "status"])


def downgrade() -> None:
    op.drop_index("ix_approvals_ws_status", table_name="approvals")
    op.drop_table("approvals")
    op.drop_table("approval_policies")
