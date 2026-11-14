"""client reports

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-14

Per-workspace report branding, and a registry of issued reports (SHA-256 of each file)
so recipients can verify a report is genuine and unmodified.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "report_branding",
        sa.Column("workspace_id", sa.String(length=32), nullable=False),
        sa.Column("organisation", sa.String(length=128), nullable=False),
        sa.Column("accent", sa.String(length=7), nullable=False),
        sa.Column("footer_note", sa.String(length=200), nullable=False),
        sa.Column("logo_png", sa.LargeBinary(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(length=128), nullable=True),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("workspace_id"),
    )
    op.create_table(
        "reports",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("workspace_id", sa.String(length=32), nullable=False),
        sa.Column("investigation_id", sa.String(length=64), nullable=False),
        sa.Column("target", sa.String(length=512), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("tlp", sa.String(length=16), nullable=False),
        sa.Column("prepared_for", sa.String(length=200), nullable=True),
        sa.Column("issued_by_org", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("sha256"),
    )
    with op.batch_alter_table("reports", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_reports_created_at"), ["created_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_reports_investigation_id"), ["investigation_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_reports_workspace_id"), ["workspace_id"], unique=False)


def downgrade() -> None:
    op.drop_table("reports")
    op.drop_table("report_branding")
