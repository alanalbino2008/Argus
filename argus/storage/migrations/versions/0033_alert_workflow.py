"""alert workflow: status, assignee, resolution and activity

Revision ID: 0033
Revises: 0032
Create Date: 2026-11-23

Alerts acknowledged before this change were treated as dealt with: they become ``resolved``.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0033"
down_revision: str | None = "0032"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("alerts") as batch:
        batch.add_column(sa.Column("status", sa.String(length=16), nullable=False, server_default="open"))
        batch.add_column(sa.Column("assignee", sa.String(length=128), nullable=True))
        batch.add_column(sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("resolved_by", sa.String(length=128), nullable=True))
        batch.add_column(sa.Column("activity", sa.JSON(), nullable=True))
        batch.create_index("ix_alerts_status", ["status"])
        batch.create_index("ix_alerts_assignee", ["assignee"])
    op.execute(
        "UPDATE alerts SET status = 'resolved', resolved_at = acknowledged_at, resolved_by = acknowledged_by "
        "WHERE acknowledged_at IS NOT NULL"
    )


def downgrade() -> None:
    with op.batch_alter_table("alerts") as batch:
        batch.drop_index("ix_alerts_assignee")
        batch.drop_index("ix_alerts_status")
        for column in ("activity", "resolved_by", "resolved_at", "assignee", "status"):
            batch.drop_column(column)
