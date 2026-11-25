"""Upgrading a SQLite database never deletes data through ON DELETE CASCADE.

SQLite batch migrations rebuild a table (copy, drop, rename). With foreign keys on, dropping the old
table cascades to its children: a migration that rebuilt ``cases`` deleted every case item. This
fills an old database with parents and children, upgrades it with the real migration runner, and
checks that every child row is still there.
"""

from __future__ import annotations

import pytest
from sqlalchemy import JSON, Boolean, DateTime, Integer, inspect, text

from argus.storage.db import Database
from argus.storage.migrate import alembic_config, upgrade_database


def _value(column):
    kind = column["type"]
    if isinstance(kind, Boolean):
        return 0
    if isinstance(kind, Integer):
        return 0
    if isinstance(kind, DateTime):
        return "2026-01-01 00:00:00"
    if isinstance(kind, JSON):
        return "[]"
    return "x"


def _insert(conn, table, **given):
    """Insert one row, filling every other required column with a plausible value."""
    columns = inspect(conn).get_columns(table)
    row = dict(given)
    for column in columns:
        if column["name"] in row or column["nullable"] or column.get("default") is not None:
            continue
        if column.get("autoincrement") is True or (column["name"] == "id" and isinstance(column["type"], Integer)):
            continue
        row[column["name"]] = _value(column)
    names = ", ".join(row)
    conn.execute(text(f"INSERT INTO {table} ({names}) VALUES ({', '.join(':' + n for n in row)})"), row)  # noqa: S608


def _count(conn, table):
    return conn.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar_one()  # noqa: S608  (fixed table names)


@pytest.fixture
async def old_db(tmp_path):
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'old.db'}")
    if db.dialect != "sqlite":
        pytest.skip("SQLite only")
    from alembic import command

    def build(conn):
        command.upgrade(alembic_config(conn), "0018")
        _insert(conn, "workspaces", id="ws_old", name="Old", slug="old")
        _insert(conn, "investigations", id="inv_old", target="example.com", status="completed", workspace_id="ws_old",
                data="{}")  # fmt: skip
        _insert(conn, "entities", investigation_id="inv_old", entity_id="ent_1", value="example.com", data="{}")
        _insert(conn, "cases", id="case_old", workspace_id="ws_old", members="[]", tags="[]")
        _insert(conn, "case_items", id="item_old", case_id="case_old", data="{}")
        _insert(conn, "evidence_captures", id="cap_old", case_id="case_old")
        _insert(conn, "subscriber_accounts", id="acct_old")
        _insert(conn, "subscriber_devices", id="dev_old", account_id="acct_old")

    async with db.engine.begin() as conn:
        await conn.run_sync(build)
    yield db
    await db.dispose()


async def test_upgrading_keeps_every_child_row(old_db):
    children = ("entities", "case_items", "evidence_captures", "subscriber_devices", "cases", "investigations")
    async with old_db.engine.connect() as conn:
        before = {t: await conn.run_sync(lambda c, t=t: _count(c, t)) for t in children}
    assert all(before.values()), before
    await upgrade_database(old_db)  # through every later migration that rebuilds a parent table
    async with old_db.engine.connect() as conn:
        after = {t: await conn.run_sync(lambda c, t=t: _count(c, t)) for t in children}
        enforced = (await conn.exec_driver_sql("PRAGMA foreign_keys")).scalar_one()
    assert after == before
    assert enforced == 1  # foreign keys are back on once the migration is done
