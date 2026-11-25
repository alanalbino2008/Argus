"""API keys: expiry, allowed networks and rotation

Revision ID: 0036
Revises: 0035
Create Date: 2026-11-25

Existing keys keep working as before: no expiry and no network restriction.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0036"
down_revision: str | None = "0035"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("api_keys") as batch:
        batch.add_column(sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("allowed_networks", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("replaced_by", sa.String(length=32), nullable=True))
        batch.add_column(sa.Column("expiry_warned_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("api_keys") as batch:
        batch.drop_column("expiry_warned_at")
        batch.drop_column("replaced_by")
        batch.drop_column("allowed_networks")
        batch.drop_column("expires_at")
