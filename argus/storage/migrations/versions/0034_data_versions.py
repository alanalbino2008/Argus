"""data versions: a counter per workspace for caching campaigns and TAXII collections

Revision ID: 0034
Revises: 0033
Create Date: 2026-11-24
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0034"
down_revision: str | None = "0033"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "data_versions",
        sa.Column("workspace_id", sa.String(length=32), primary_key=True),
        sa.Column("version", sa.BigInteger(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_table("data_versions")
