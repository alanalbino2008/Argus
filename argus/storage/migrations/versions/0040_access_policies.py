"""workspace access policies: the networks a workspace may be used from

Revision ID: 0040
Revises: 0039
Create Date: 2026-11-25
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0040"
down_revision: str | None = "0039"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "access_policies",
        sa.Column("workspace_id", sa.String(length=32), primary_key=True),
        sa.Column("allowed_networks", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(length=128), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("access_policies")
