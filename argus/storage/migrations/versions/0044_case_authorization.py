"""cases: the legal authorisation reference

Revision ID: 0044
Revises: 0043
Create Date: 2026-11-26
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0044"
down_revision: str | None = "0043"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # A plain ADD COLUMN: SQLite batch rebuilds of a table with cascading children lose rows (see 1.93.1).
    op.add_column("cases", sa.Column("authorization", sa.String(length=300), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("cases") as batch:
        batch.drop_column("authorization")
