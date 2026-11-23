"""brand lookalikes in their own table

Revision ID: 0032
Revises: 0031
Create Date: 2026-11-22

One row per lookalike domain a brand watch found (with its triage and takedown), instead of one
encrypted document per watch that grew to megabytes. Existing watches are converted the first time
Argus reads them (the documents are encrypted with the application's key, which migrations do not
hold).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0032"
down_revision: str | None = "0031"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "brand_lookalikes",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("watch_id", sa.String(length=32), nullable=False),
        sa.Column("workspace_id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=253), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("verdict", sa.String(length=16), nullable=False),
        sa.Column("technique", sa.String(length=16), nullable=False),
        sa.Column("display", sa.String(length=253), nullable=False),
        sa.Column("detail", sa.String(length=160), nullable=False),
        sa.Column("takedown_status", sa.String(length=16), nullable=True),
        sa.Column("infra", sa.JSON(), nullable=True),
        sa.Column("finding", sa.JSON(), nullable=False),
        sa.Column("triage", sa.JSON(), nullable=True),
        sa.Column("takedown", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(["watch_id"], ["brand_watches.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ux_brand_lookalikes", "brand_lookalikes", ["watch_id", "name"], unique=True)
    op.create_index("ix_brand_lookalikes_recent", "brand_lookalikes", ["watch_id", "first_seen_at"])
    op.create_index("ix_brand_lookalikes_checked", "brand_lookalikes", ["watch_id", "checked_at"])
    op.create_index("ix_brand_lookalikes_workspace_id", "brand_lookalikes", ["workspace_id"])
    op.create_index("ix_brand_lookalikes_takedown_status", "brand_lookalikes", ["takedown_status"])


def downgrade() -> None:
    for name in ("ix_brand_lookalikes_takedown_status", "ix_brand_lookalikes_workspace_id",
                 "ix_brand_lookalikes_checked", "ix_brand_lookalikes_recent", "ux_brand_lookalikes"):  # fmt: skip
        op.drop_index(name, table_name="brand_lookalikes")
    op.drop_table("brand_lookalikes")
