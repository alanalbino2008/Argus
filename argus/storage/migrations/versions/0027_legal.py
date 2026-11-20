"""legal: terms acceptance and account deletion

Revision ID: 0027
Revises: 0026
Create Date: 2026-11-20

Which version of the terms each account accepted, and when; and when an account was deleted
(its personal details are then removed; payment records stay, as tax law requires).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0027"
down_revision: str | None = "0026"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("subscriber_accounts", schema=None) as batch_op:
        batch_op.add_column(sa.Column("terms_version", sa.String(length=32), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("terms_accepted_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("subscriber_accounts", schema=None) as batch_op:
        batch_op.drop_column("deleted_at")
        batch_op.drop_column("terms_accepted_at")
        batch_op.drop_column("terms_version")
