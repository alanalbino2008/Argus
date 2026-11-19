"""business plan

Revision ID: 0025
Revises: 0024
Create Date: 2026-11-20

The Team plan is now called the Business plan.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0025"
down_revision: str | None = "0024"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(sa.text("UPDATE subscriber_accounts SET plan = 'business' WHERE plan = 'team'"))


def downgrade() -> None:
    op.execute(sa.text("UPDATE subscriber_accounts SET plan = 'team' WHERE plan = 'business'"))
