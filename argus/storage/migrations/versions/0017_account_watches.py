"""account watches

Revision ID: 0017
Revises: 0016
Create Date: 2026-11-15

Online accounts a case watches, and the profile as first seen and after each change.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "account_watches",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("workspace_id", sa.String(length=32), nullable=False),
        sa.Column("case_id", sa.String(length=32), nullable=False),
        sa.Column("platform", sa.String(length=80), nullable=False),
        sa.Column("handle", sa.String(length=128), nullable=False),
        sa.Column("profile_url", sa.String(length=512), nullable=False),
        sa.Column("interval_hours", sa.Integer(), nullable=False),
        sa.Column("capture_on_change", sa.Boolean(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("message", sa.String(length=512), nullable=False),
        sa.Column("snapshot", sa.JSON(), nullable=True),
        sa.Column("missing_count", sa.Integer(), nullable=False),
        sa.Column("changes_count", sa.Integer(), nullable=False),
        sa.Column("next_check_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_account_watches_workspace_id", "account_watches", ["workspace_id"])
    op.create_index("ix_account_watches_next_check_at", "account_watches", ["next_check_at"])
    op.create_index("ux_account_watches_case", "account_watches", ["case_id", "platform", "handle"], unique=True)
    op.create_table(
        "account_snapshots",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("watch_id", sa.String(length=32), nullable=False),
        sa.Column("taken_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("exists", sa.Boolean(), nullable=True),
        sa.Column("facts", sa.JSON(), nullable=False),
        sa.Column("changes", sa.JSON(), nullable=False),
        sa.Column("capture_id", sa.String(length=32), nullable=True),
        sa.ForeignKeyConstraint(["watch_id"], ["account_watches.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_account_snapshots_watch", "account_snapshots", ["watch_id", "taken_at"])


def downgrade() -> None:
    op.drop_index("ix_account_snapshots_watch", table_name="account_snapshots")
    op.drop_table("account_snapshots")
    op.drop_index("ux_account_watches_case", table_name="account_watches")
    op.drop_index("ix_account_watches_next_check_at", table_name="account_watches")
    op.drop_index("ix_account_watches_workspace_id", table_name="account_watches")
    op.drop_table("account_watches")
