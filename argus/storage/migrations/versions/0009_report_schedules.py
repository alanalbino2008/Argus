"""scheduled reports

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-14

Report schedules per workspace, and the stored PDFs of scheduled reports (kept 30 days so
email deliveries can be retried with their attachment).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "report_schedules",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("workspace_id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("target", sa.String(length=512), nullable=False),
        sa.Column("frequency", sa.String(length=16), nullable=False),
        sa.Column("weekday", sa.Integer(), nullable=True),
        sa.Column("day_of_month", sa.Integer(), nullable=True),
        sa.Column("hour", sa.Integer(), nullable=False),
        sa.Column("minute", sa.Integer(), nullable=False),
        sa.Column("timezone", sa.String(length=64), nullable=False),
        sa.Column("options", sa.JSON(), nullable=False),
        sa.Column("channel_ids", sa.JSON(), nullable=False),
        sa.Column("skip_unchanged", sa.Boolean(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(length=32), nullable=True),
        sa.Column("last_message", sa.String(length=512), nullable=True),
        sa.Column("last_report_id", sa.String(length=32), nullable=True),
        sa.Column("last_investigation_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("report_schedules", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_report_schedules_next_run_at"), ["next_run_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_report_schedules_workspace_id"), ["workspace_id"], unique=False)
    op.create_table(
        "report_files",
        sa.Column("report_id", sa.String(length=32), nullable=False),
        sa.Column("workspace_id", sa.String(length=32), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("pdf", sa.LargeBinary(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["report_id"], ["reports.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("report_id"),
    )
    with op.batch_alter_table("report_files", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_report_files_expires_at"), ["expires_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_report_files_workspace_id"), ["workspace_id"], unique=False)


def downgrade() -> None:
    op.drop_table("report_files")
    op.drop_table("report_schedules")
