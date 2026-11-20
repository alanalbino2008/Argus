"""fingerprint watches

Revision ID: 0030
Revises: 0029
Create Date: 2026-11-20

A fingerprint (favicon, JARM, HASSH, certificate) whose Shodan or Censys search is re-run on a
schedule; servers that newly share it raise an alert.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0030"
down_revision: str | None = "0029"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "fingerprint_watches",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("workspace_id", sa.String(length=32), nullable=False),
        sa.Column("engine", sa.String(length=16), nullable=False),
        sa.Column("entity_id", sa.String(length=64), nullable=False),
        sa.Column("investigation_id", sa.String(length=64), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("interval_hours", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(length=16), nullable=True),
        sa.Column("last_total", sa.Integer(), nullable=True),
        sa.Column("alerts_raised", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ux_fingerprint_watches", "fingerprint_watches", ["workspace_id", "engine", "entity_id"], unique=True
    )
    op.create_index("ix_fingerprint_watches_next_run_at", "fingerprint_watches", ["next_run_at"])


def downgrade() -> None:
    op.drop_index("ix_fingerprint_watches_next_run_at", table_name="fingerprint_watches")
    op.drop_index("ux_fingerprint_watches", table_name="fingerprint_watches")
    op.drop_table("fingerprint_watches")
