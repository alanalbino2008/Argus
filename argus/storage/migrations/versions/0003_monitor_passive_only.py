"""monitor passive_only

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-14

Monitors remember whether their scans must stay passive (no contact with the
target's own systems), so scheduled re-scans keep the same rules of engagement.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("monitors", schema=None) as batch_op:
        batch_op.add_column(sa.Column("passive_only", sa.Boolean(), server_default=sa.false(), nullable=False))


def downgrade() -> None:
    with op.batch_alter_table("monitors", schema=None) as batch_op:
        batch_op.drop_column("passive_only")
