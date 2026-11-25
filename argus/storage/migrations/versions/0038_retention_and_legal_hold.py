"""retention policies per workspace, and legal hold on cases

Revision ID: 0038
Revises: 0037
Create Date: 2026-11-25

Nothing is purged until a workspace sets a retention period; existing cases are not on hold.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0038"
down_revision: str | None = "0037"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "retention_policies",
        sa.Column("workspace_id", sa.String(length=32), primary_key=True),
        sa.Column("investigations_days", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("alerts_days", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cases_days", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(length=128), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_result", sa.JSON(), nullable=True),
    )
    with op.batch_alter_table("cases") as batch:
        batch.add_column(sa.Column("legal_hold", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.add_column(sa.Column("legal_hold_note", sa.String(length=500), nullable=True))
        batch.add_column(sa.Column("legal_hold_by", sa.String(length=128), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("cases") as batch:
        batch.drop_column("legal_hold_by")
        batch.drop_column("legal_hold_note")
        batch.drop_column("legal_hold")
    op.drop_table("retention_policies")
