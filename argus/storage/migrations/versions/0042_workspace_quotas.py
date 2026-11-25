"""per-workspace quotas

Revision ID: 0042
Revises: 0041
Create Date: 2026-11-25
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0042"
down_revision: str | None = "0041"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "workspace_quotas",
        sa.Column("workspace_id", sa.String(length=32), primary_key=True),
        sa.Column("scans_per_day", sa.Integer(), nullable=True),
        sa.Column("evidence_mb", sa.Integer(), nullable=True),
        sa.Column("watches", sa.Integer(), nullable=True),
        sa.Column("api_keys", sa.Integer(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(length=128), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("workspace_quotas")
