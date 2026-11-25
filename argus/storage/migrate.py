"""Schema migrations (Alembic), applied automatically at startup.

Every schema change is a versioned, reviewable migration script in
``argus/storage/migrations/versions``. On startup Argus upgrades the database to
the latest revision, so deployments never need a manual SQL step.

Databases created before migrations existed (Argus 1.2-1.3 used ``create_all``)
already contain the baseline schema: they are *stamped* as the baseline revision
rather than re-created, then upgraded normally.
"""

from __future__ import annotations

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection

from argus.storage.db import Database

logger = logging.getLogger("argus.storage.migrate")

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"
BASELINE_REVISION = "0001"


def alembic_config(connection: Connection | None = None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    if connection is not None:
        cfg.attributes["connection"] = connection
    return cfg


def head_revision() -> str:
    head = ScriptDirectory.from_config(alembic_config()).get_current_head()
    if head is None:  # not an assert: asserts vanish under `python -O`
        raise RuntimeError(f"No Alembic migrations found in {MIGRATIONS_DIR}")
    return head


def _upgrade(connection: Connection) -> str | None:
    cfg = alembic_config(connection)
    current = MigrationContext.configure(connection).get_current_revision()
    tables = set(inspect(connection).get_table_names())
    if current is None and "investigations" in tables:
        logger.warning("Pre-migration database detected: stamping baseline revision %s", BASELINE_REVISION)
        command.stamp(cfg, BASELINE_REVISION)
    command.upgrade(cfg, "head")
    return MigrationContext.configure(connection).get_current_revision()


# PostgreSQL advisory-lock key: replicas starting together migrate one at a time.
MIGRATION_LOCK = 0x4152_4755_534D_4947  # "ARGUSMIG"


async def upgrade_database(db: Database) -> str | None:
    """Bring the database schema up to the latest revision; returns that revision.

    Safe to call from several replicas at once: on PostgreSQL the migration runs under a
    transaction-scoped advisory lock, so the others wait and then find nothing to do.
    """
    if db.dialect == "sqlite":
        return await _upgrade_sqlite(db)
    async with db.engine.begin() as conn:
        if db.dialect == "postgresql":
            await conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": MIGRATION_LOCK})
        revision = await conn.run_sync(_upgrade)
    logger.info("Database schema at revision %s", revision)
    return revision


class MigrationDataLoss(RuntimeError):
    """An upgrade removed rows it should not have; the database was put back as it was."""


# Tables whose rows may legitimately vanish during an upgrade (short-lived, recreated on demand).
EPHEMERAL = {"alembic_version", "ws_tickets", "oidc_logins", "rate_limit_counters", "sessions"}
SNAPSHOTS_KEPT = 3


def _sqlite_file(db: Database) -> Path | None:
    name = db.engine.url.database
    if not name or name == ":memory:" or name.startswith("file:"):
        return None
    return Path(name)


def _counts(path: Path) -> dict[str, int]:
    """Rows in every table of a SQLite file (read-only)."""
    import sqlite3

    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        tables = [
            r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        ]
        return {t: int(conn.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]) for t in tables}  # noqa: S608 - names from the schema
    finally:
        conn.close()


def _snapshot(path: Path, current: str | None, head: str) -> Path:
    """A consistent copy of the database before it is migrated, next to it, readable by its owner only."""
    import sqlite3
    from datetime import datetime, timezone

    folder = path.parent / "pre-upgrade"
    folder.mkdir(mode=0o700, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = folder / f"{path.stem}-{current or 'none'}-to-{head}-{stamp}.db"
    source = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        source.execute("VACUUM INTO ?", (str(out),))
    finally:
        source.close()
    out.chmod(0o600)
    check = sqlite3.connect(f"file:{out}?mode=ro", uri=True)
    try:
        if check.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError(f"The pre-upgrade snapshot {out} is damaged; not upgrading")
    finally:
        check.close()
    for old in sorted(folder.glob(f"{path.stem}-*.db"))[:-SNAPSHOTS_KEPT]:
        old.unlink(missing_ok=True)
    return out


def _put_back(path: Path, snapshot: Path) -> None:
    import shutil

    for suffix in ("-wal", "-shm"):
        Path(f"{path}{suffix}").unlink(missing_ok=True)
    shutil.copyfile(snapshot, path)


async def _pending(db: Database) -> tuple[str | None, str, bool]:
    """(current revision, head, whether the database holds anything worth protecting)."""
    head = head_revision()
    async with db.engine.connect() as conn:

        def read(c: Connection) -> tuple[str | None, bool]:
            tables = set(inspect(c).get_table_names())
            return MigrationContext.configure(c).get_current_revision(), bool(tables - {"alembic_version"})

        current, populated = await conn.run_sync(read)
    return current, head, populated


async def _upgrade_sqlite(db: Database) -> str | None:
    """Migrate SQLite safely: a checked snapshot first, foreign keys off, and no rows lost (Phase 95).

    Before a pending migration runs, the database is copied (``VACUUM INTO``) to ``pre-upgrade/`` next
    to it and the copy checked; the newest three are kept. After the migration, every table is counted
    again: if one has fewer rows than before (short-lived tables aside), the snapshot is put back and
    :class:`MigrationDataLoss` stops the start-up, so a faulty migration can never cost data silently.
    """
    path = _sqlite_file(db)
    current, head, populated = await _pending(db)
    if path is None or current == head or not populated or not path.exists():
        return await _migrate_sqlite(db)
    snapshot = _snapshot(path, current, head)
    before = _counts(snapshot)
    logger.warning("Upgrading the database from %s to %s; a copy was saved first: %s", current, head, snapshot)
    try:
        revision = await _migrate_sqlite(db)
    except Exception:
        await db.engine.dispose()
        _put_back(path, snapshot)
        logger.error("The upgrade failed; the database was put back as it was (%s)", snapshot)
        raise
    after = _counts(path)
    lost = {t: (n, after.get(t, 0)) for t, n in before.items()
            if t not in EPHEMERAL and t in after and after[t] < n}  # fmt: skip
    if lost:
        await db.engine.dispose()
        _put_back(path, snapshot)
        detail = ", ".join(f"{t}: {a} of {b} rows" for t, (b, a) in sorted(lost.items()))
        raise MigrationDataLoss(f"Upgrading from {current} to {head} would have lost rows ({detail}). The database "
                                f"was put back as it was; Argus did not start. Report this, with the log, before "
                                f"upgrading again. The copy taken before the upgrade is {snapshot}.")  # fmt: skip
    return revision


async def _migrate_sqlite(db: Database) -> str | None:
    """Migrate SQLite with foreign keys off, as Alembic's batch mode requires.

    SQLite cannot alter most of a table, so batch migrations copy it to a new table, drop the old one
    and rename. With foreign keys on, dropping the old table fires every ``ON DELETE CASCADE`` that
    points at it: rebuilding ``cases`` would delete every case item and piece of evidence. The pragma
    only takes effect outside a transaction, so it is set before the migration starts, the foreign keys
    are checked once it is done, and they are switched back on.
    """
    async with db.engine.connect() as conn:
        await conn.exec_driver_sql("PRAGMA foreign_keys=OFF")
        await conn.commit()
        try:
            async with conn.begin():
                revision = await conn.run_sync(_upgrade)
            problems = (await conn.exec_driver_sql("PRAGMA foreign_key_check")).fetchall()
            if problems:
                logger.warning("Rows referring to missing parents after migrating: %s", problems[:20])
        finally:
            await conn.exec_driver_sql("PRAGMA foreign_keys=ON")
            await conn.commit()
    logger.info("Database schema at revision %s", revision)
    return revision
