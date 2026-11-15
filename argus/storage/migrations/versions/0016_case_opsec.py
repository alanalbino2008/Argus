"""case opsec

Revision ID: 0016
Revises: 0015
Create Date: 2026-11-15

Each case remembers which egress route (Tor, VPN or proxy) its captures and scans use, and whether
it is anonymous: an anonymous case never touches its subjects directly.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("cases") as batch:
        batch.add_column(sa.Column("egress", sa.String(length=32), nullable=False, server_default=""))
        batch.add_column(sa.Column("opsec_mode", sa.String(length=16), nullable=False, server_default="standard"))


def downgrade() -> None:
    with op.batch_alter_table("cases") as batch:
        batch.drop_column("opsec_mode")
        batch.drop_column("egress")
