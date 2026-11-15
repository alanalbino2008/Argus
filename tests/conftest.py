"""Shared fixtures: an isolated database and an authenticated API client per test.

Set ``ARGUS_TEST_DATABASE_URL`` (e.g. ``postgresql+asyncpg://argus:argus@localhost/argus_test``)
to run the whole suite against PostgreSQL instead of SQLite; the schema is wiped before each test.
"""

import asyncio
import os

import pytest
from fastapi.testclient import TestClient

from argus.api import server
from argus.core.settings import get_settings

ADMIN_KEY = "argus_test-admin-key-0123456789abcdefghijklmnopqrstu"
PG_URL = os.environ.get("ARGUS_TEST_DATABASE_URL")


def database_url(tmp_path, name: str) -> str:
    return PG_URL or f"sqlite+aiosqlite:///{tmp_path / name}"


@pytest.fixture(autouse=True)
def _fresh_postgres_schema() -> None:
    """With a PostgreSQL test database, start every test from an empty schema."""
    if PG_URL:
        from sqlalchemy import text
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy.pool import NullPool

        async def wipe():
            engine = create_async_engine(PG_URL, poolclass=NullPool)
            async with engine.begin() as conn:
                await conn.execute(text("DROP SCHEMA public CASCADE"))
                await conn.execute(text("CREATE SCHEMA public"))
            await engine.dispose()

        asyncio.run(wipe())


@pytest.fixture
def make_client(tmp_path, monkeypatch):
    """Factory so tests can tweak settings (env vars) before the app starts."""
    clients = []

    def _make(**env):
        monkeypatch.setenv("ARGUS_DATABASE_URL", database_url(tmp_path, "api.db"))
        monkeypatch.setenv("ARGUS_BOOTSTRAP_ADMIN_KEY", ADMIN_KEY)
        # Tests never reach live breach sources unless they opt in.
        monkeypatch.setenv("ARGUS_EXPOSURE_MONITORING_ENABLED", "false")
        for k, v in env.items():
            monkeypatch.setenv(f"ARGUS_{k.upper()}", str(v))
        get_settings.cache_clear()
        cm = TestClient(server.app)
        c = cm.__enter__()
        c.headers["Authorization"] = f"Bearer {ADMIN_KEY}"
        clients.append(cm)
        return c

    yield _make
    for cm in clients:
        cm.__exit__(None, None, None)
    server.INVESTIGATIONS.clear()
    server.SCAN_TASKS.clear()
    get_settings.cache_clear()


@pytest.fixture
def client(make_client):
    return make_client()
