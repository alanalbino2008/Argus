"""Schema migrations: fresh upgrade, model/migration drift, legacy adoption, downgrade."""

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import inspect, text

from argus.storage.db import Base, Database
from argus.storage.migrate import alembic_config, head_revision, upgrade_database


@pytest.fixture
async def db(tmp_path):
    database = Database(f"sqlite+aiosqlite:///{tmp_path / 'm.db'}")
    yield database
    await database.dispose()


async def test_fresh_database_upgrades_to_head(db):
    assert await upgrade_database(db) == head_revision()
    async with db.engine.connect() as conn:
        tables = await conn.run_sync(lambda c: set(inspect(c).get_table_names()))
    assert {"investigations", "entities", "relations", "api_keys", "audit_events", "alembic_version"} <= tables


async def test_migrations_match_models_exactly(db):
    """Fails if someone edits an ORM model without writing a migration."""
    await upgrade_database(db)
    async with db.engine.connect() as conn:
        diff = await conn.run_sync(lambda c: compare_metadata(MigrationContext.configure(c), Base.metadata))
    assert diff == []


async def test_upgrade_is_idempotent(db):
    first = await upgrade_database(db)
    assert await upgrade_database(db) == first


async def test_pre_migration_database_is_adopted_without_data_loss(db):
    """Argus 1.2-1.3 created its (baseline) tables with create_all() and no alembic_version table."""
    baseline = [
        Base.metadata.tables[t] for t in ("investigations", "entities", "relations", "api_keys", "audit_events")
    ]
    async with db.engine.begin() as conn:
        await conn.run_sync(lambda c: Base.metadata.create_all(c, tables=baseline))
    async with db.engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO investigations (id, target, target_type, status, created_at, node_count, edge_count, data) "
                "VALUES ('inv_old', 'example.com', 'domain', 'completed', '2026-01-01', 1, 0, '{}')"
            )
        )
    assert await upgrade_database(db) == head_revision()
    async with db.engine.connect() as conn:
        count = (await conn.execute(text("SELECT COUNT(*) FROM investigations"))).scalar_one()
    assert count == 1
    async with db.engine.connect() as conn:  # later migrations were applied on top of the adopted baseline
        tables = await conn.run_sync(lambda c: set(inspect(c).get_table_names()))
    assert {"monitors", "alerts"} <= tables


async def test_downgrade_to_base_and_back(db):
    await upgrade_database(db)
    async with db.engine.begin() as conn:
        await conn.run_sync(lambda c: command.downgrade(alembic_config(c), "base"))
        tables = await conn.run_sync(lambda c: set(inspect(c).get_table_names()))
    assert tables <= {"alembic_version"}
    assert await upgrade_database(db) == head_revision()
