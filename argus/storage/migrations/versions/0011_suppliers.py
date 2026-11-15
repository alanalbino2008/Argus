"""supplier register

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-15

Third parties in each workspace's supplier register, assessed passively on a schedule.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "suppliers",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("workspace_id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("domain", sa.String(length=253), nullable=False),
        sa.Column("tier", sa.String(length=16), nullable=False),
        sa.Column("data_access", sa.String(length=16), nullable=False),
        sa.Column("owner", sa.String(length=200), nullable=False),
        sa.Column("notes", sa.String(length=500), nullable=False),
        sa.Column("min_grade_override", sa.String(length=1), nullable=True),
        sa.Column("monitor_id", sa.String(length=32), nullable=True),
        sa.Column("last_grade", sa.String(length=1), nullable=True),
        sa.Column("last_score", sa.Float(), nullable=True),
        sa.Column("last_investigation_id", sa.String(length=64), nullable=True),
        sa.Column("last_assessed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("basis", sa.String(length=300), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("suppliers", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_suppliers_workspace_id"), ["workspace_id"], unique=False)
        batch_op.create_index("ux_suppliers_workspace_domain", ["workspace_id", "domain"], unique=True)


def downgrade() -> None:
    op.drop_table("suppliers")
