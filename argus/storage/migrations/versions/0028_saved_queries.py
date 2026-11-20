"""saved queries

Revision ID: 0028
Revises: 0027
Create Date: 2026-11-20

Named Argus Query Language queries per workspace. Those marked for alerting are checked after
every completed scan, and raise an alert when the scan matches something the previous scan of
the same target did not.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0028"
down_revision: str | None = "0027"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "saved_queries",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("workspace_id", sa.String(length=32), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("alert", sa.Boolean(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_alert_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("alerts_raised", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_saved_queries_workspace", "saved_queries", ["workspace_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_saved_queries_workspace", table_name="saved_queries")
    op.drop_table("saved_queries")
