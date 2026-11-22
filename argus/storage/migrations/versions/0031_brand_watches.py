"""brand watches

Revision ID: 0031
Revises: 0030
Create Date: 2026-11-22

A brand whose lookalike domains are looked for in Certificate Transparency on a schedule.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0031"
down_revision: str | None = "0030"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "brand_watches",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("workspace_id", sa.String(length=32), nullable=False),
        sa.Column("domain", sa.String(length=253), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("interval_hours", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(length=16), nullable=True),
        sa.Column("alerts_raised", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ux_brand_watches", "brand_watches", ["workspace_id", "domain"], unique=True)
    op.create_index("ix_brand_watches_next_run_at", "brand_watches", ["next_run_at"])


def downgrade() -> None:
    op.drop_index("ix_brand_watches_next_run_at", table_name="brand_watches")
    op.drop_index("ux_brand_watches", table_name="brand_watches")
    op.drop_table("brand_watches")
