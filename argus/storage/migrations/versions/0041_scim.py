"""SCIM provisioning: provisioned users, groups, and group-to-workspace roles

Revision ID: 0041
Revises: 0040
Create Date: 2026-11-25
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0041"
down_revision: str | None = "0040"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Plain ADD COLUMN, not a batch rebuild: rebuilding "users" on SQLite would drop and recreate it, and the
    # ON DELETE CASCADE from workspace memberships and sessions would wipe them.
    op.add_column("users", sa.Column("scim_managed", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("users", sa.Column("external_id", sa.String(length=255), nullable=True))
    op.add_column("users", sa.Column("user_name", sa.String(length=320), nullable=True))
    op.create_index("ix_users_user_name", "users", ["user_name"])
    op.create_table(
        "scim_groups",
        sa.Column("id", sa.String(length=32), primary_key=True),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=True),
        sa.Column("members", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scim_groups_display_name", "scim_groups", ["display_name"])
    op.create_table(
        "scim_group_roles",
        sa.Column("group_name", sa.String(length=255), primary_key=True),
        sa.Column(
            "workspace_id", sa.String(length=32), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), primary_key=True
        ),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("updated_by", sa.String(length=128), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("scim_group_roles")
    op.drop_index("ix_scim_groups_display_name", table_name="scim_groups")
    op.drop_table("scim_groups")
    op.drop_index("ix_users_user_name", table_name="users")
    for column in ("user_name", "external_id", "scim_managed"):
        op.drop_column("users", column)
