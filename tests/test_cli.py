"""CLI: scan workflow, exports, scope refusal and out-of-band key creation."""

import json
import sys

import pytest

from argus.cli import console
from argus.core import engine as engine_module
from argus.core.settings import get_settings
from tests.test_engine import FanOutModule


@pytest.fixture
def fake_modules(monkeypatch):
    monkeypatch.setattr(engine_module, "get_default_modules", lambda: {"fan_out": FanOutModule(fan=2)})


async def test_cli_scan_exports_json_and_csv(tmp_path, fake_modules):
    out_json, out_csv = tmp_path / "g.json", tmp_path / "g.csv"
    await console.run_cli_scan("example.com", max_depth=1, export_json=str(out_json), export_csv=str(out_csv))
    graph = json.loads(out_json.read_text())
    assert len(graph["nodes"]) == 3 and len(graph["edges"]) == 2
    assert out_csv.read_text().count("SUBDOMAIN_OF") == 2


async def test_cli_refuses_internal_targets(fake_modules):
    with pytest.raises(SystemExit) as exc:
        await console.run_cli_scan("169.254.169.254")
    assert exc.value.code == 2


async def test_cli_allows_internal_targets_when_explicitly_authorised(fake_modules):
    await console.run_cli_scan("10.0.0.1", allow_private=True, max_depth=0)


def test_cli_create_api_key(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ARGUS_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'cli.db'}")
    get_settings.cache_clear()
    monkeypatch.setattr(sys, "argv", ["argus", "--create-api-key", "ci-bot", "--role", "viewer"])
    try:
        console.cli_entrypoint()
    finally:
        get_settings.cache_clear()
    out = capsys.readouterr().out
    assert "argus_" in out and "role viewer" in out


@pytest.mark.parametrize(
    "value,expected",
    [("+1 (555) 010-9999", "phone"), ("ünïcode_user", "username"), ("2001:db8::1", "ip_address")],
)
def test_detect_target_type_edge_cases(value, expected):
    assert console.detect_target_type(value).value == expected
