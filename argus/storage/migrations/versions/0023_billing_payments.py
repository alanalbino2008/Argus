"""billing payments: refunds and disputes

Revision ID: 0023
Revises: 0022
Create Date: 2026-11-19

Payments Argus may have to undo: the credits each credit pack bought, how much of it was
refunded and what was taken back, and any dispute (chargeback) with the account's status before
it was put on hold.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0023"
down_revision: str | None = "0022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "billing_payments",
        sa.Column("id", sa.String(length=255), nullable=False),
        sa.Column("account_id", sa.String(length=32), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("credits", sa.Integer(), nullable=False),
        sa.Column("amount", sa.Integer(), nullable=False),
        sa.Column("currency", sa.String(length=8), nullable=False),
        sa.Column("refunded", sa.Integer(), nullable=False),
        sa.Column("refund_credits_taken", sa.Integer(), nullable=False),
        sa.Column("dispute_id", sa.String(length=255), nullable=False),
        sa.Column("dispute_status", sa.String(length=32), nullable=False),
        sa.Column("dispute_credits_taken", sa.Integer(), nullable=False),
        sa.Column("status_before_hold", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["account_id"], ["subscriber_accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_billing_payments_account", "billing_payments", ["account_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_billing_payments_account", table_name="billing_payments")
    op.drop_table("billing_payments")
