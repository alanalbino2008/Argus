"""playbook runs

Revision ID: 0020
Revises: 0019
Create Date: 2026-11-18

Playbooks: the standard steps of an investigation run in order inside a case. Each run keeps its
steps and what stood out.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0020"
down_revision: str | None = "0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "playbook_runs",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("workspace_id", sa.String(length=32), nullable=False),
        sa.Column("case_id", sa.String(length=32), nullable=False),
        sa.Column("playbook", sa.String(length=64), nullable=False),
        sa.Column("seed", sa.String(length=500), nullable=False),
        sa.Column("seed_type", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_playbook_runs_case", "playbook_runs", ["case_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_playbook_runs_case", table_name="playbook_runs")
    op.drop_table("playbook_runs")
