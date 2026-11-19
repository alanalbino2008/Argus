"""team plans

Revision ID: 0024
Revises: 0023
Create Date: 2026-11-19

Team plans: an owner pays for seats and invites investigators, who sign in with their own
accounts and share the team's credits. Members point at the owner's account; the owner records
the seats paid for; each credit movement records which member used it; invitations are stored
only as hashes.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0024"
down_revision: str | None = "0023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("subscriber_accounts") as batch:
        batch.add_column(sa.Column("team_id", sa.String(length=32), nullable=True))
        batch.add_column(sa.Column("seats", sa.Integer(), nullable=False, server_default="1"))
        batch.create_index(batch.f("ix_subscriber_accounts_team_id"), ["team_id"], unique=False)
    with op.batch_alter_table("credit_ledger") as batch:
        batch.add_column(sa.Column("used_by", sa.String(length=32), nullable=False, server_default=""))
    op.create_table(
        "team_invites",
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("team_id", sa.String(length=32), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancelled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["team_id"], ["subscriber_accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("token_hash"),
    )
    op.create_index("ix_team_invites_team", "team_invites", ["team_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_team_invites_team", table_name="team_invites")
    op.drop_table("team_invites")
    with op.batch_alter_table("credit_ledger") as batch:
        batch.drop_column("used_by")
    with op.batch_alter_table("subscriber_accounts") as batch:
        batch.drop_index(batch.f("ix_subscriber_accounts_team_id"))
        batch.drop_column("seats")
        batch.drop_column("team_id")
