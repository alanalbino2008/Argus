"""Phase 95: SQLite upgrades take a checked snapshot first and refuse to lose rows."""

from __future__ import annotations

import sqlite3
import stat

import pytest

from argus.storage import migrate
from argus.storage.migrate import MigrationDataLoss, head_revision, upgrade_database
from tests.test_migration_cascades import old_db  # noqa: F401  (fixture used by name)


def _file(db):
    return migrate._sqlite_file(db)


def _query(path, sql):
    conn = sqlite3.connect(path)
    try:
        return conn.execute(sql).fetchall()
    finally:
        conn.close()


async def test_an_upgrade_keeps_a_checked_copy_of_the_database_before(old_db):  # noqa: F811
    path = _file(old_db)
    assert await upgrade_database(old_db) == head_revision()
    (snapshot,) = sorted((path.parent / "pre-upgrade").glob("*.db"))
    assert f"-0018-to-{head_revision()}-" in snapshot.name
    assert stat.S_IMODE(snapshot.stat().st_mode) == 0o600
    assert _query(snapshot, "SELECT version_num FROM alembic_version") == [("0018",)]
    assert _query(snapshot, "SELECT COUNT(*) FROM case_items") == [(1,)]
    # Already up to date: nothing to protect, no new copy.
    await upgrade_database(old_db)
    assert len(list((path.parent / "pre-upgrade").glob("*.db"))) == 1


async def test_an_upgrade_that_loses_rows_is_undone(old_db, monkeypatch):  # noqa: F811
    path = _file(old_db)
    real = migrate._migrate_sqlite

    async def faulty(db):  # a migration with the 1.91.0 bug: it drops children on the way
        revision = await real(db)
        async with db.engine.begin() as conn:
            await conn.exec_driver_sql("DELETE FROM case_items")
        return revision

    monkeypatch.setattr(migrate, "_migrate_sqlite", faulty)
    with pytest.raises(MigrationDataLoss, match=r"case_items: 0 of 1 rows") as refused:
        await upgrade_database(old_db)
    assert "put back as it was" in str(refused.value)
    assert _query(path, "SELECT COUNT(*) FROM case_items") == [(1,)]  # the row is back
    assert _query(path, "SELECT version_num FROM alembic_version") == [("0018",)]  # and so is the schema


async def test_an_upgrade_that_fails_is_undone(old_db, monkeypatch):  # noqa: F811
    path = _file(old_db)

    async def broken(db):
        async with db.engine.begin() as conn:
            await conn.exec_driver_sql("DROP TABLE case_items")
        raise RuntimeError("migration crashed half-way")

    monkeypatch.setattr(migrate, "_migrate_sqlite", broken)
    with pytest.raises(RuntimeError, match="half-way"):
        await upgrade_database(old_db)
    assert _query(path, "SELECT COUNT(*) FROM case_items") == [(1,)]


def test_only_the_newest_copies_are_kept(tmp_path):
    path = tmp_path / "argus.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE t (x)")
    conn.commit()
    conn.close()
    for i in range(5):
        migrate._snapshot(path, f"00{i}", "0099")
    assert len(list((tmp_path / "pre-upgrade").glob("argus-*.db"))) == migrate.SNAPSHOTS_KEPT
