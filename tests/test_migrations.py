"""Schema migrations: fresh upgrade, model/migration drift, legacy adoption, downgrade."""

from datetime import datetime, timezone

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import inspect, text

from argus.storage.db import Base, Database
from argus.storage.migrate import alembic_config, head_revision, upgrade_database
from tests.conftest import database_url


@pytest.fixture
async def db(tmp_path):
    database = Database(database_url(tmp_path, "m.db"))
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
    from alembic import command

    def baseline_schema(c):
        # The real 1.2/1.3 schema is migration 0001's; then forget it was ever migrated.
        command.upgrade(alembic_config(c), "0001")
        c.execute(text("DROP TABLE alembic_version"))

    async with db.engine.begin() as conn:
        await conn.run_sync(baseline_schema)
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


async def test_upgrade_moves_existing_data_into_the_default_workspace(db):
    """A live 1.13 database: data stays visible (in Default), non-admin keys get least privilege."""
    from alembic import command

    from argus.storage.security_repo import AuditLog

    async with db.engine.begin() as conn:
        await conn.run_sync(lambda c: command.upgrade(alembic_config(c), "0005"))
        for sql in (
            "INSERT INTO investigations (id, target, target_type, status, created_at, node_count, edge_count, data) "
            "VALUES ('inv_old', 'example.com', 'domain', 'completed', '2026-01-01', 0, 0, '{}')",
            "INSERT INTO api_keys (id, name, prefix, key_hash, role, created_at) "
            "VALUES ('k_admin', 'root', 'argus_x', 'h1', 'admin', '2026-01-01'), "
            "('k_analyst', 'ci', 'argus_y', 'h2', 'analyst', '2026-01-01')",
            "INSERT INTO users (id, issuer, subject, email, role, created_at) "
            "VALUES ('usr_1', 'https://idp', 's1', 'dana@acme.example', 'analyst', '2026-01-01')",
        ):
            await conn.execute(text(sql))
    from argus.storage.security_repo import GENESIS_HASH

    # An entry written by the old version, hashed the old way (no workspace field).
    old = {"ts": "2026-01-01T00:00:00+00:00", "actor_id": "system", "actor_name": "system", "action": "before.upgrade",
           "resource": None, "outcome": "success", "ip": None, "details": {}}  # fmt: skip
    async with db.engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO audit_events (ts, actor_id, actor_name, action, resource, outcome, ip, details, prev_hash, hash) "
                "VALUES (:ts, 'system', 'system', 'before.upgrade', NULL, 'success', NULL, '{}', :prev, :hash)"
            ),
            {"ts": old["ts"], "prev": GENESIS_HASH, "hash": AuditLog._digest(GENESIS_HASH, old)},
        )
    await upgrade_database(db)
    from argus.security.auth import SYSTEM

    await AuditLog(db).record(SYSTEM, "after.upgrade", workspace_id="ws_default")  # new-style entry chains on
    async with db.engine.connect() as conn:
        assert (await conn.execute(text("SELECT workspace_id FROM investigations"))).scalar_one() == "ws_default"
        keys = dict((await conn.execute(text("SELECT id, workspace_id FROM api_keys"))).all())
        members = (await conn.execute(text("SELECT workspace_id, user_id, role FROM workspace_members"))).all()
    assert keys == {"k_admin": None, "k_analyst": "ws_default"}
    assert [tuple(m) for m in members] == [("ws_default", "usr_1", "analyst")]
    assert (await AuditLog(db).verify())["valid"] is True  # old entries still verify after the change


async def test_acknowledged_alerts_become_resolved(db):
    """Before 1.81, acknowledging an alert was how it was dealt with: those alerts become 'resolved'."""
    async with db.engine.begin() as conn:
        await conn.run_sync(lambda c: command.upgrade(alembic_config(c), "0032"))
        acknowledged_at = datetime(
            2026, 11, 1, tzinfo=timezone.utc
        )  # a datetime: PostgreSQL's driver will not take text
        for alert_id, acknowledged, by in (("alert_done", acknowledged_at, "dana"), ("alert_new", None, None)):
            await conn.execute(text(
                "INSERT INTO alerts (id, workspace_id, investigation_id, previous_investigation_id, target, severity, "
                "headline, summary, created_at, acknowledged_at, acknowledged_by) VALUES (:id, 'ws_default', '', '', "
                "'t', 'high', 'h', '{}', '2026-10-30', :acknowledged, :by)"
            ), {"id": alert_id, "acknowledged": acknowledged, "by": by})  # fmt: skip
    assert await upgrade_database(db) == head_revision()
    async with db.engine.connect() as conn:
        rows = dict((await conn.execute(text("SELECT id, status FROM alerts"))).all())
        resolved_by = (await conn.execute(text("SELECT resolved_by FROM alerts WHERE id = 'alert_done'"))).scalar_one()
    assert rows == {"alert_done": "resolved", "alert_new": "open"} and resolved_by == "dana"
