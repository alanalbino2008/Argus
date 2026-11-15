"""argus credits

Revision ID: 0019
Revises: 0018
Create Date: 2026-11-15

Argus credits for brokered data sources: a monthly allowance and purchased credits per account,
and a ledger of every change.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0019"
down_revision: str | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("subscriber_accounts") as batch:
        batch.add_column(sa.Column("allowance_month", sa.String(length=7), nullable=False, server_default=""))
        batch.add_column(sa.Column("allowance_remaining", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("purchased_credits", sa.Integer(), nullable=False, server_default="0"))
    op.create_table(
        "credit_ledger",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("account_id", sa.String(length=32), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("delta", sa.Integer(), nullable=False),
        sa.Column("balance_after", sa.Integer(), nullable=False),
        sa.Column("detail", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["account_id"], ["subscriber_accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_credit_ledger_account", "credit_ledger", ["account_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_credit_ledger_account", table_name="credit_ledger")
    op.drop_table("credit_ledger")
    with op.batch_alter_table("subscriber_accounts") as batch:
        batch.drop_column("purchased_credits")
        batch.drop_column("allowance_remaining")
        batch.drop_column("allowance_month")
