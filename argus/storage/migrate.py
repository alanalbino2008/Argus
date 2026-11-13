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
from sqlalchemy import inspect
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


async def upgrade_database(db: Database) -> str | None:
    """Bring the database schema up to the latest revision; returns that revision."""
    async with db.engine.begin() as conn:
        revision = await conn.run_sync(_upgrade)
    logger.info("Database schema at revision %s", revision)
    return revision
