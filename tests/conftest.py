"""Shared fixtures: an isolated database and an authenticated API client per test."""

import pytest
from fastapi.testclient import TestClient

from argus.api import server
from argus.core.settings import get_settings

ADMIN_KEY = "argus_test-admin-key-0123456789abcdefghijklmnopqrstu"


@pytest.fixture
def make_client(tmp_path, monkeypatch):
    """Factory so tests can tweak settings (env vars) before the app starts."""
    clients = []

    def _make(**env):
        monkeypatch.setenv("ARGUS_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'api.db'}")
        monkeypatch.setenv("ARGUS_BOOTSTRAP_ADMIN_KEY", ADMIN_KEY)
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
