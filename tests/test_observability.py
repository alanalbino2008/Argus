"""Metrics, request correlation and structured logs."""

from __future__ import annotations

import json
import logging

import pytest

from argus.observability import logs, metrics
from tests.test_engine import FailingModule, FanOutModule, make_engine


def value(name: str, **labels: str) -> float:
    return metrics.REGISTRY.get_sample_value(name, labels) or 0.0


# ------------------------------------------------------------------ /metrics and HTTP metrics
def test_metrics_endpoint_exposes_templated_routes_and_build_info(client):
    before = value("argus_http_requests_total", method="GET", route="/api/investigation/{inv_id}", status="404")
    client.get("/api/investigation/inv_missing_1")
    client.get("/api/investigation/inv_missing_2")
    client.get("/definitely/not/a/route")
    body = client.get("/metrics").text
    assert "argus_build_info{" in body and "argus_http_request_duration_seconds_bucket" in body
    assert "process_resident_memory_bytes" in body
    after = value("argus_http_requests_total", method="GET", route="/api/investigation/{inv_id}", status="404")
    assert after - before == 2  # one series for every investigation id: bounded cardinality
    assert "inv_missing_1" not in body and "/definitely/not" not in body
    assert value("argus_http_requests_total", method="GET", route="unmatched", status="404") >= 1


def test_request_ids_are_echoed_or_generated(client):
    assert client.get("/api/live", headers={"X-Request-ID": "lb-7f3a.42"}).headers["x-request-id"] == "lb-7f3a.42"
    generated = client.get("/api/live", headers={"X-Request-ID": "bad id\nwith newline"}).headers["x-request-id"]
    assert len(generated) == 32 and generated.isalnum()


def test_metrics_token_and_disable_switch(make_client):
    client = make_client(metrics_token="scrape-secret-123")
    anonymous = client.get("/metrics", headers={"Authorization": ""})
    assert anonymous.status_code == 401
    assert client.get("/metrics", headers={"Authorization": "Bearer scrape-secret-123"}).status_code == 200
    off = make_client(metrics_enabled="false")
    assert off.get("/metrics").status_code == 404


def test_auth_failures_and_rate_limits_are_counted(client):
    before = value("argus_auth_failures_total", reason="invalid_key")
    client.get("/api/investigations", headers={"Authorization": "Bearer argus_wrong-key-000000000000000000000000"})
    assert value("argus_auth_failures_total", reason="invalid_key") == before + 1
    assert value("argus_database_up") in (0.0, 1.0)
    client.get("/api/health")
    assert value("argus_database_up") == 1.0


# ------------------------------------------------------------------ scans and modules
async def test_scan_and_module_metrics():
    started = value("argus_scans_finished_total", status="completed")
    ok_before = value("argus_module_runs_total", module="fan_out", outcome="success")
    failed_before = value("argus_module_runs_total", module="failing", outcome="failed")
    found_before = value("argus_entities_discovered_total", type="subdomain")
    engine = make_engine([FanOutModule(fan=2), FailingModule()], max_depth=2)
    await engine.start()
    assert value("argus_scans_finished_total", status="completed") == started + 1
    assert value("argus_module_runs_total", module="fan_out", outcome="success") == ok_before + 3  # seed + 2 subs
    assert value("argus_module_runs_total", module="failing", outcome="failed") == failed_before + 2
    assert value("argus_entities_discovered_total", type="subdomain") == found_before + 6
    assert value("argus_scans_running") == 0  # balanced inc/dec
    assert value("argus_module_duration_seconds_count", module="fan_out") >= 1


async def test_blocked_egress_is_counted():
    from argus.core.http import HttpClient
    from argus.security.network import BlockedDestinationError

    before = value("argus_outbound_requests_total", outcome="blocked")
    client = HttpClient(session=None, max_retries=0)  # type: ignore[arg-type]
    with pytest.raises(BlockedDestinationError):
        await client._send("GET", "http://169.254.169.254/latest/meta-data/", {})
    assert value("argus_outbound_requests_total", outcome="blocked") == before + 1


# ------------------------------------------------------------------ logs
def test_json_logs_carry_request_and_investigation_ids(capsys):
    logs.configure("json", "INFO", instance="argus-pod-1")
    rid = logs.request_id.set("req-123")
    iid = logs.investigation_id.set("inv_abc")
    try:
        logging.getLogger("argus.test").info("checkpoint saved", extra={"entities": 4})
    finally:
        logs.request_id.reset(rid)
        logs.investigation_id.reset(iid)
        logs.configure("text", "INFO")
    line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert line["message"] == "checkpoint saved" and line["level"] == "info"
    assert line["request_id"] == "req-123" and line["investigation_id"] == "inv_abc"
    assert line["instance"] == "argus-pod-1" and line["entities"] == 4


def test_text_logs_append_correlation_tags(capsys):
    logs.configure("text", "INFO", instance="x")
    token = logs.request_id.set("req-9")
    try:
        logging.getLogger("argus.test").warning("slow source")
    finally:
        logs.request_id.reset(token)
    assert "slow source [request_id=req-9]" in capsys.readouterr().out


def test_engine_log_lines_carry_the_investigation_id(capsys):
    logs.configure("json", "INFO", instance="x")
    try:
        engine = make_engine([FanOutModule(fan=1), FailingModule()], max_depth=2)
        import asyncio

        asyncio.run(engine.start())
    finally:
        logs.configure("text", "INFO")
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    failures = [line for line in lines if "failed on" in line["message"]]
    assert failures and all(line["investigation_id"] == engine.investigation_id for line in failures)


# ------------------------------------------------------------------ dashboard & alerts consistency
def _referenced_metrics(text: str) -> set[str]:
    import re

    return set(re.findall(r"\b((?:argus|process)_[a-z_]+)\b", text))


def test_dashboard_is_generated_and_only_queries_real_metrics():
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location("build_dashboard", "deploy/observability/build_dashboard.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    committed = Path("deploy/helm/argus/files/argus-dashboard.json").read_text()
    assert committed == module.build(), "run: python deploy/observability/build_dashboard.py"
    dashboard = json.loads(committed)
    exprs = " ".join(t["expr"] for p in dashboard["panels"] for t in p.get("targets", []))
    missing = _referenced_metrics(exprs) - metrics.metric_names()
    assert not missing, missing
    ids = [p["id"] for p in dashboard["panels"]]
    assert len(ids) == len(set(ids))


def test_alert_rules_only_use_real_metrics_and_are_documented():
    from pathlib import Path

    import yaml

    rules = yaml.safe_load(Path("deploy/helm/argus/files/alerts.yaml").read_text())
    alerts = [r for g in rules["groups"] for r in g["rules"]]
    assert len(alerts) >= 10
    for alert in alerts:
        assert alert["labels"]["severity"] in {"critical", "warning", "info"}
        assert alert["annotations"]["summary"] and alert["annotations"]["description"]
        missing = _referenced_metrics(alert["expr"]) - metrics.metric_names()
        assert not missing, (alert["alert"], missing)


def test_uvicorn_access_log_never_contains_query_strings():
    logs.configure("text", "INFO")
    record = logging.LogRecord(
        "uvicorn.access", logging.INFO, "", 0, '%s - "%s %s HTTP/%s" %d', ("1.2.3.4:5", "GET",
        "/auth/oidc/callback?code=SECRET&state=abc", "1.1", 303), None,
    )  # fmt: skip
    for f in logging.getLogger("uvicorn.access").filters:
        f.filter(record)
    assert "SECRET" not in record.getMessage() and "/auth/oidc/callback HTTP/1.1" in record.getMessage()
