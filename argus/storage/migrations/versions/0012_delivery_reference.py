"""delivery reference

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-15

What an integration created for a delivery (a Jira issue key, a ServiceNow incident number).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("notification_deliveries") as batch:
        batch.add_column(sa.Column("reference", sa.String(length=128), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("notification_deliveries") as batch:
        batch.drop_column("reference")
