"""cases and evidence

Revision ID: 0015
Revises: 0014
Create Date: 2026-11-15

Cases (notes, entities, links, scans, events) and preserved evidence with files and a hash-chained
chain of custody.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "cases",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("workspace_id", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("purpose", sa.String(length=500), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("restricted", sa.Boolean(), nullable=False),
        sa.Column("members", sa.JSON(), nullable=False),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("cases", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_cases_workspace_id"), ["workspace_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_cases_updated_at"), ["updated_at"], unique=False)

    op.create_table(
        "case_items",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("case_id", sa.String(length=32), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("case_items", schema=None) as batch_op:
        batch_op.create_index("ix_case_items_case_kind", ["case_id", "kind"], unique=False)

    op.create_table(
        "evidence_captures",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("case_id", sa.String(length=32), nullable=False),
        sa.Column("workspace_id", sa.String(length=32), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=True),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("note", sa.String(length=1000), nullable=False),
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column("manifest", sa.JSON(), nullable=False),
        sa.Column("timestamp_token", sa.LargeBinary(), nullable=True),
        sa.Column("warnings", sa.JSON(), nullable=False),
        sa.Column("captured_by", sa.String(length=128), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("evidence_captures", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_evidence_captures_case_id"), ["case_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_evidence_captures_digest"), ["digest"], unique=False)

    op.create_table(
        "evidence_files",
        sa.Column("capture_id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("media_type", sa.String(length=128), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("data", sa.LargeBinary(), nullable=False),
        sa.ForeignKeyConstraint(["capture_id"], ["evidence_captures.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("capture_id", "name"),
    )

    op.create_table(
        "evidence_custody",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("capture_id", sa.String(length=32), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("by", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("detail", sa.String(length=500), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("hash", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["capture_id"], ["evidence_captures.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("evidence_custody", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_evidence_custody_capture_id"), ["capture_id"], unique=False)


def downgrade() -> None:
    op.drop_table("evidence_custody")
    op.drop_table("evidence_files")
    op.drop_table("evidence_captures")
    op.drop_table("case_items")
    op.drop_table("cases")
