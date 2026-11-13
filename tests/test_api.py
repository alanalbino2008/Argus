"""REST API contract tests (no outbound network: scans use fake modules)."""

import asyncio

import pytest
from fastapi.testclient import TestClient

from argus.api import server
from argus.core.engine import ArgusEngine
from argus.core.events import EventBus
from argus.core.models import EntityType, ScanConfig
from tests.test_engine import FanOutModule


@pytest.fixture
def client():
    with TestClient(server.app) as c:
        yield c
    server.INVESTIGATIONS.clear()
    server.SCAN_TASKS.clear()


def test_list_modules(client):
    mods = client.get("/api/modules").json()
    assert {"dns_recon", "username_hunter"} <= {m["name"] for m in mods}


@pytest.mark.parametrize("payload", [
    {"target": "example.com", "max_depth": 9},
    {"target": "example.com", "concurrency_limit": 0},
    {"target": "   "},
    {"target": "example.com", "enabled_modules": ["does_not_exist"]},
])
def test_scan_rejects_invalid_input(client, payload):
    assert client.post("/api/scan", json=payload).status_code == 422


@pytest.mark.parametrize("path", [
    "/api/investigation/inv_missing",
    "/api/investigation/inv_missing/graph",
    "/api/investigation/inv_missing/export/json",
    "/api/investigation/inv_missing/export/csv",
])
def test_unknown_investigation_returns_404(client, path):
    assert client.get(path).status_code == 404


def test_cancel_lifecycle(client):
    config = ScanConfig(target="example.com", target_type=EntityType.DOMAIN, max_depth=4)
    engine = ArgusEngine(config, bus=EventBus(), modules={"fan_out": FanOutModule(fan=3, delay=0.5)})
    server.INVESTIGATIONS[engine.investigation_id] = engine
    engine._is_running = True  # simulate an in-flight scan

    url = f"/api/investigation/{engine.investigation_id}"
    assert client.post(f"{url}/cancel").json()["status"] == "cancelling"
    assert engine._cancel_event.is_set()

    engine._is_running = False
    assert client.post(f"{url}/cancel").status_code == 409

    body = client.get(url).json()
    assert {"module_stats", "http_stats", "truncated", "errors"} <= body.keys()
