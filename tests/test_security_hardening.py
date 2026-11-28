"""Regression tests for the security audit (1.126.0): each test pins one weakness that was found and fixed."""

from __future__ import annotations

from pathlib import Path

import pytest
from starlette.testclient import TestClient

from argus.api import deps, server
from argus.security.oidc import safe_return_path
from tests.conftest import ADMIN_KEY

ROOT = Path(__file__).resolve().parents[1]
WRONG_KEY = "argus_wrong-key-0000000000000000000000000000"


def from_address(started: TestClient, ip: str, key: str | None = None) -> TestClient:
    """A client connecting from ``ip``, sharing the event loop of the ``started`` client (so it can use the
    app's database pool, e.g. asyncpg's, which is bound to that loop)."""
    c = TestClient(server.app, client=(ip, 40000))
    c.portal = started.portal
    if key:
        c.headers["Authorization"] = f"Bearer {key}"
    return c


# ------------------------------------------------------------------ open redirect after sign-in
@pytest.mark.parametrize(
    "payload",
    [
        "//evil.example",
        "/\\evil.example",
        "/\t/evil.example",  # browsers drop the tab: "//evil.example"
        "/\r/evil.example",
        "/\n/evil.example",
        "/\x0b/evil.example",
        "/\x00/evil.example",
        "/ /evil.example",
        "https://evil.example",
        "javascript:alert(1)",
        "evil.example",
        "",
        None,
    ],
)
def test_return_path_never_leaves_the_site(payload):
    assert safe_return_path(payload) == "/"


@pytest.mark.parametrize("path", ["/", "/cases/c_1", "/investigate?target=acme.example#graph", "/a/b:c"])
def test_ordinary_return_paths_are_kept(path):
    assert safe_return_path(path) == path


# ------------------------------------------------------------------ request body size
def test_oversized_json_body_is_refused_before_it_is_read(make_client):
    client = make_client(max_request_kb="64")
    r = client.post("/api/scan", content=b"{" + b" " * (80 * 1024) + b"}",
                    headers={"Content-Type": "application/json"})  # fmt: skip
    assert r.status_code == 413
    assert r.headers["x-content-type-options"] == "nosniff"  # still gets the security headers


def test_oversized_body_without_content_length_is_cut_off(make_client):
    client = make_client(max_request_kb="64")

    def chunks():
        for _ in range(200):
            yield b" " * 1024

    r = client.post("/api/scan", content=chunks(), headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_oversized_body_is_refused_even_without_credentials(make_client):
    client = make_client(max_request_kb="64")
    anonymous = from_address(client, "93.184.216.35")
    assert anonymous.post("/api/csp-report", content=b"x" * (100 * 1024)).status_code == 413


def test_uploads_get_the_evidence_limit_not_the_json_limit(make_client):
    client = make_client(max_request_kb="64", evidence_max_upload_mb="1")
    ok = client.post("/api/import", files={"file": ("a.csv", b"x" * (200 * 1024), "text/csv")})
    assert ok.status_code != 413  # 200 KB is over the JSON limit but within the upload limit
    big = client.post("/api/import", files={"file": ("a.csv", b"x" * (3 * 1024 * 1024), "text/csv")})
    assert big.status_code == 413


def test_negative_or_malformed_content_length_is_refused(client):
    r = client.post("/api/scan", content=b"{}", headers={"Content-Type": "application/json", "Content-Length": "-5"})
    assert r.status_code in (400, 413)


# ------------------------------------------------------------------ API key guessing
def test_repeated_wrong_keys_lock_out_the_address(client):
    guesser = from_address(client, "198.51.100.20", WRONG_KEY)
    codes = [guesser.get("/api/investigations").status_code for _ in range(deps.KEY_FAILURES_PER_IP + 2)]
    assert codes[0] == 401 and codes[-1] == 429
    assert codes.index(429) <= deps.KEY_FAILURES_PER_IP
    # Locked out: even the right key is refused from that address (the lock is no oracle) ...
    right = from_address(client, "198.51.100.20", ADMIN_KEY).get("/api/investigations")
    assert right.status_code == 429 and int(right.headers["retry-after"]) > 0
    # ... while everyone else carries on.
    assert from_address(client, "198.51.100.21", ADMIN_KEY).get("/api/investigations").status_code == 200


def test_a_few_typos_do_not_lock_anyone_out(client):
    for _ in range(3):
        assert from_address(client, "198.51.100.30", WRONG_KEY).get("/api/investigations").status_code == 401
    assert from_address(client, "198.51.100.30", ADMIN_KEY).get("/api/investigations").status_code == 200


# ------------------------------------------------------------------ information disclosure
def test_health_tells_the_internet_only_whether_it_is_up(client):
    body = from_address(client, "93.184.216.34").get("/api/health").json()
    assert body["status"] == "ok" and body["database"] == {"reachable": True}
    assert "version" not in body and "active_scans" not in body
    signed_in = client.get("/api/health").json()
    assert signed_in["version"] == server.app.version and "backend" in signed_in["database"]


def test_health_details_for_the_internal_network(client):
    body = from_address(client, "10.1.2.3").get("/api/health").json()
    assert "version" in body


def test_metrics_are_hidden_from_the_internet_without_a_token(client):
    assert from_address(client, "93.184.216.34").get("/metrics").status_code == 404
    assert from_address(client, "10.0.0.7").get("/metrics").status_code == 200  # Prometheus in the cluster
    assert from_address(client, "127.0.0.1").get("/metrics").status_code == 200
    assert from_address(client, "93.184.216.34", ADMIN_KEY).get("/metrics").status_code == 200


def test_server_banner_is_not_sent_by_the_container():
    assert '"--no-server-header"' in (ROOT / "Dockerfile").read_text()


# ------------------------------------------------------------------ forged X-Forwarded-For
def test_container_and_chart_never_trust_every_proxy():
    """``--forwarded-allow-ips "*"`` let any client forge X-Forwarded-For and so its IP: past network
    allow-lists on keys, per-IP rate limits and sign-in lockouts, and into the audit log."""
    dockerfile = (ROOT / "Dockerfile").read_text()
    chart = (ROOT / "deploy/helm/argus/templates/deployment.yaml").read_text()
    values = (ROOT / "deploy/helm/argus/values.yaml").read_text()
    cluster = (ROOT / "deploy/compose/cluster.yml").read_text()
    assert '"*"' not in dockerfile.split("CMD [", 1)[1]
    assert "FORWARDED_ALLOW_IPS=127.0.0.1" in dockerfile
    assert '"--forwarded-allow-ips", "*"' not in chart and ".Values.config.trustedProxies" in chart
    assert 'trustedProxies: "127.0.0.1,10.0.0.0/8' in values
    assert "FORWARDED_ALLOW_IPS:" in cluster


def test_uvicorn_ignores_forwarded_for_from_untrusted_peers():
    from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

    seen: list[str] = []

    async def app(scope, receive, send):
        seen.append(scope["client"][0])

    import asyncio

    mw = ProxyHeadersMiddleware(app, trusted_hosts="127.0.0.1,10.0.0.0/8")
    headers = [(b"x-forwarded-for", b"10.9.9.9")]

    async def run(peer: str) -> None:
        await mw({"type": "http", "client": (peer, 1), "headers": headers, "scheme": "http"}, None, None)

    asyncio.run(run("203.0.113.66"))  # an internet client forging its address
    asyncio.run(run("10.0.0.2"))  # the load balancer
    assert seen == ["203.0.113.66", "10.9.9.9"]


# ------------------------------------------------------------------ development mode
def test_auth_disabled_serves_only_local_networks(make_client):
    client = make_client(auth_enabled="false")
    assert from_address(client, "93.184.216.34").get("/api/me").status_code == 403
    assert from_address(client, "127.0.0.1").get("/api/me").json()["role"] == "admin"
    assert from_address(client, "192.168.1.10").get("/api/me").status_code == 200


def test_api_reference_can_be_switched_off(monkeypatch):
    """The setting is read when the app is built; check the wiring rather than rebuilding the app."""
    source = (ROOT / "argus/api/server.py").read_text()
    assert 'docs_url="/docs" if get_settings().api_docs_enabled else None' in source
    assert 'openapi_url="/openapi.json" if get_settings().api_docs_enabled else None' in source
