"""security ratings

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-15

Cached security ratings per completed investigation, for trends and portfolio benchmarks.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ratings",
        sa.Column("investigation_id", sa.String(length=64), nullable=False),
        sa.Column("workspace_id", sa.String(length=32), nullable=False),
        sa.Column("target", sa.String(length=512), nullable=False),
        sa.Column("methodology", sa.String(length=32), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("grade", sa.String(length=2), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("assessed_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("investigation_id"),
    )
    with op.batch_alter_table("ratings", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_ratings_assessed_at"), ["assessed_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_ratings_target"), ["target"], unique=False)
        batch_op.create_index(batch_op.f("ix_ratings_workspace_id"), ["workspace_id"], unique=False)


def downgrade() -> None:
    op.drop_table("ratings")
