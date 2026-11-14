"""team workspaces

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-14

Multi-tenancy: every investigation, monitor, alert, API key, audit entry and
WebSocket ticket belongs to a workspace. Existing data moves into a "Default"
workspace so nothing is lost or exposed:

* existing non-admin API keys are bound to Default; admin keys stay platform-wide;
* existing single-sign-on users become members of Default with their current role.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DEFAULT = "ws_default"
SCOPED = ("investigations", "monitors", "alerts")


def upgrade() -> None:
    workspaces = op.create_table(
        "workspaces",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("workspaces", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_workspaces_slug"), ["slug"], unique=True)
    op.bulk_insert(
        workspaces,
        [
            {
                "id": DEFAULT,
                "name": "Default",
                "slug": "default",
                "created_at": datetime.now(timezone.utc),
                "created_by": "system",
            }
        ],
    )
    op.create_table(
        "workspace_members",
        sa.Column("workspace_id", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.String(length=32), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("added_by", sa.String(length=128), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("workspace_id", "user_id"),
    )

    for table in SCOPED:  # everything that exists today belongs to Default
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.add_column(sa.Column("workspace_id", sa.String(length=32), server_default=DEFAULT, nullable=False))
            batch_op.create_index(batch_op.f(f"ix_{table}_workspace_id"), ["workspace_id"], unique=False)
    with op.batch_alter_table("api_keys", schema=None) as batch_op:
        batch_op.add_column(sa.Column("workspace_id", sa.String(length=32), nullable=True))
        batch_op.create_index(batch_op.f("ix_api_keys_workspace_id"), ["workspace_id"], unique=False)
    with op.batch_alter_table("audit_events", schema=None) as batch_op:
        batch_op.add_column(sa.Column("workspace_id", sa.String(length=32), nullable=True))
        batch_op.create_index(batch_op.f("ix_audit_events_workspace_id"), ["workspace_id"], unique=False)
    with op.batch_alter_table("ws_tickets", schema=None) as batch_op:
        batch_op.add_column(sa.Column("workspace_id", sa.String(length=32), nullable=True))

    # Least privilege for existing credentials: only admin keys stay platform-wide.
    op.execute(sa.text("UPDATE api_keys SET workspace_id = :ws WHERE role <> 'admin'").bindparams(ws=DEFAULT))
    op.execute(
        sa.text(
            "INSERT INTO workspace_members (workspace_id, user_id, role, added_at, added_by) "
            "SELECT :ws, id, role, created_at, 'migration' FROM users"
        ).bindparams(ws=DEFAULT)
    )


def downgrade() -> None:
    with op.batch_alter_table("ws_tickets", schema=None) as batch_op:
        batch_op.drop_column("workspace_id")
    for table in ("audit_events", "api_keys", *SCOPED):
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.drop_index(batch_op.f(f"ix_{table}_workspace_id"))
            batch_op.drop_column("workspace_id")
    op.drop_table("workspace_members")
    with op.batch_alter_table("workspaces", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_workspaces_slug"))
    op.drop_table("workspaces")
