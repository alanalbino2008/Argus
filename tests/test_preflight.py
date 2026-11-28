"""Production preflight: an unsafe configuration stops a production start and names the fix."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.core import preflight
from argus.core.settings import Settings

ROOT = Path(__file__).resolve().parents[1]
PG = "postgresql+asyncpg://argus:pw@db:5432/argus"
KEY = "k" * 40


def settings(**kw) -> Settings:
    kw.setdefault("database_url", PG)
    kw.setdefault("encryption_key", KEY)
    kw.setdefault("public_url", "https://argus.example.com")
    kw.setdefault("log_format", "json")
    kw.setdefault("smtp_host", "smtp.example.com")
    kw.setdefault("metrics_token", "scrape-token-123")
    return Settings(_env_file=None, **kw)


def codes(found, level=None):
    return {f.code for f in found if level is None or f.level == level}


def test_a_well_configured_cluster_has_no_findings():
    assert preflight.check(settings(), env={"FORWARDED_ALLOW_IPS": "10.0.0.0/8"}) == []


@pytest.mark.parametrize(
    "overrides, env, code",
    [
        ({"auth_enabled": False}, {}, "auth_disabled"),
        ({}, {"FORWARDED_ALLOW_IPS": "*"}, "trust_all_proxies"),
        ({}, {"FORWARDED_ALLOW_IPS": "10.0.0.1, *"}, "trust_all_proxies"),
        ({"encryption_key": None}, {}, "no_encryption_key"),
        ({"encryption_key": None, "encryption_key_file": "/data/k"}, {}, "encryption_key_file_in_cluster"),
        ({"public_url": "http://argus.example.com"}, {}, "public_url_not_https"),
        ({"cors_origins": ["*"]}, {}, "cors_wildcard"),
    ],
)
def test_unsafe_settings_are_errors(overrides, env, code):
    assert code in codes(preflight.check(settings(**overrides), env=env), "error")


def test_local_development_urls_and_single_node_keys_are_not_errors():
    found = preflight.check(
        settings(
            database_url="sqlite+aiosqlite:///x.db",
            encryption_key=None,
            encryption_key_file="/d/k",
            public_url="http://localhost:8000",
        ),
        env={},
    )
    assert not codes(found, "error")
    assert "sqlite" in codes(found, "warning")


def test_advice_is_only_a_warning():
    found = preflight.check(settings(log_format="text", smtp_host=None, metrics_token=None, public_url=None), env={})
    assert codes(found, "warning") == {"text_logs", "no_email", "metrics_without_token", "no_public_url"}
    assert not codes(found, "error")


def test_errors_come_first_and_every_finding_names_a_fix():
    found = preflight.check(settings(auth_enabled=False, log_format="text"), env={})
    assert found[0].level == "error" and all(f.fix for f in found)


def test_production_refuses_and_development_only_logs(caplog):
    unsafe = {"auth_enabled": False}
    with pytest.raises(preflight.PreflightFailed, match="auth_disabled"):
        preflight.enforce(settings(environment="production", **unsafe), env={})
    caplog.clear()
    assert preflight.enforce(settings(environment="development", log_format="text", **unsafe), env={})
    logged = caplog.text
    assert "auth_disabled" in logged and "text_logs" not in logged  # development: errors only, no nagging


def test_a_production_server_will_not_start_unsafe(make_client):
    with pytest.raises(preflight.PreflightFailed):
        make_client(environment="production", auth_enabled="false")


def test_a_safe_production_server_starts(make_client, monkeypatch):
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "127.0.0.1")
    client = make_client(environment="production", encryption_key=KEY)
    assert client.get("/api/health").status_code == 200


def test_preflight_command(monkeypatch, capsys):
    from argus.cli import console
    from argus.core.settings import get_settings

    monkeypatch.setenv("ARGUS_AUTH_ENABLED", "false")
    get_settings.cache_clear()
    try:
        assert console.preflight_cli() == 1
    finally:
        get_settings.cache_clear()
    assert "auth_disabled" in capsys.readouterr().out


def test_deployments_run_in_production_mode():
    assert "ARGUS_ENVIRONMENT=production" in (ROOT / "Dockerfile").read_text()
    assert "environment: production" in (ROOT / "deploy/helm/argus/values.yaml").read_text()
    assert (
        "ARGUS_ENVIRONMENT: {{ .Values.config.environment"
        in (ROOT / "deploy/helm/argus/templates/configmap.yaml").read_text()
    )
    assert "ARGUS_ENVIRONMENT: production" in (ROOT / "deploy/compose/cluster.yml").read_text()


def test_image_installs_only_the_hash_locked_dependencies():
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "pip install --require-hashes --no-deps -r requirements.lock" in dockerfile
    assert dockerfile.count("FROM python:3.12-slim@sha256:") == 2  # both stages pinned by digest
    lock = (ROOT / "requirements.lock").read_text()
    for name in ("fastapi", "uvicorn", "sqlalchemy", "asyncpg", "cryptography", "pyjwt"):
        assert f"\n{name}==" in lock, name
    assert "--hash=sha256:" in lock
