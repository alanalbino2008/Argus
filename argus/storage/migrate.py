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


async def _upgrade_sqlite(db: Database) -> str | None:
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
