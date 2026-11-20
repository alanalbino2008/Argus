"""entity annotations

Revision ID: 0029
Revises: 0028
Create Date: 2026-11-20

The team's tags and notes on entities. Entity ids are derived from type and value, so an annotation
applies to that entity in every investigation of the workspace.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0029"
down_revision: str | None = "0028"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "entity_annotations",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("workspace_id", sa.String(length=32), nullable=False),
        sa.Column("entity_id", sa.String(length=64), nullable=False),
        sa.Column("entity_type", sa.String(length=32), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("updated_by", sa.String(length=128), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ux_entity_annotations", "entity_annotations", ["workspace_id", "entity_id"], unique=True)


def downgrade() -> None:
    op.drop_index("ux_entity_annotations", table_name="entity_annotations")
    op.drop_table("entity_annotations")
