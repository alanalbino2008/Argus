"""rate limit counters shared by every replica

Revision ID: 0035
Revises: 0034
Create Date: 2026-11-25
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0035"
down_revision: str | None = "0034"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "rate_limit_counters",
        sa.Column("name", sa.String(length=64), primary_key=True),
        sa.Column("key", sa.String(length=32), primary_key=True),
        sa.Column("window_start", sa.BigInteger(), primary_key=True, autoincrement=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_table("rate_limit_counters")
