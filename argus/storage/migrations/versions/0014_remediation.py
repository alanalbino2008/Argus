"""remediation workflow

Revision ID: 0014
Revises: 0013
Create Date: 2026-11-15

Remediation tasks (from attack paths, exposure findings, suppliers or people), their timeline,
and each workspace's deadlines and automation.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "remediation_tasks",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("workspace_id", sa.String(length=32), nullable=False),
        sa.Column("source_type", sa.String(length=16), nullable=False),
        sa.Column("source_key", sa.String(length=300), nullable=True),
        sa.Column("target", sa.String(length=253), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("description", sa.String(length=4000), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("assignee", sa.String(length=128), nullable=True),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("external_ref", sa.String(length=128), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("reopen_count", sa.Integer(), nullable=False),
        sa.Column("verified_by", sa.String(length=128), nullable=True),
        sa.Column("overdue_alerted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("remediation_tasks", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_remediation_tasks_due_at"), ["due_at"], unique=False)
        batch_op.create_index("ux_remediation_source", ["workspace_id", "source_type", "source_key"], unique=True)
        batch_op.create_index("ix_remediation_status", ["workspace_id", "status"], unique=False)

    op.create_table(
        "remediation_events",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("task_id", sa.String(length=32), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("by", sa.String(length=128), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("text", sa.String(length=2000), nullable=False),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(["task_id"], ["remediation_tasks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("remediation_events", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_remediation_events_task_id"), ["task_id"], unique=False)

    op.create_table(
        "remediation_policies",
        sa.Column("workspace_id", sa.String(length=32), nullable=False),
        sa.Column("sla_days", sa.JSON(), nullable=False),
        sa.Column("auto_create", sa.String(length=16), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(length=128), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("workspace_id"),
    )


def downgrade() -> None:
    op.drop_table("remediation_policies")
    op.drop_table("remediation_events")
    op.drop_table("remediation_tasks")
