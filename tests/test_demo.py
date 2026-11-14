"""Built-in demo: safe identifiers only, exercises every attack-path rule, loads via API and CLI."""

import ipaddress
import sys
from urllib.parse import urlsplit

import stix2

from argus.cli import console
from argus.core.models import EntityType
from argus.core.settings import get_settings
from argus.demo import DEMO_ID, build_demo
from argus.intel.paths import RULES, find_attack_paths
from argus.intel.stix import build_bundle


def test_demo_uses_only_reserved_identifiers():
    """Fictional data must never point at a real organisation, person or network."""
    _, graph = build_demo()
    for e in graph.get_all_entities():
        if e.type == EntityType.IP_ADDRESS:
            assert ipaddress.ip_address(e.value) in ipaddress.ip_network("203.0.113.0/24")  # TEST-NET-3
        if e.type == EntityType.PHONE:
            assert e.value.startswith("+44113496"), e.value  # Ofcom range reserved for drama/fiction
        if e.type in (
            EntityType.DOMAIN,
            EntityType.SUBDOMAIN,
            EntityType.EMAIL,
            EntityType.SOCIAL_PROFILE,
            EntityType.URL,
        ):
            host = urlsplit(e.value).hostname if "://" in e.value else e.value.rsplit("@", 1)[-1]
            assert host.endswith(".example"), e.value  # RFC 2606


def test_demo_triggers_every_attack_path_rule():
    _, graph = build_demo()
    fired = {p["rule"] for p in find_attack_paths(graph)["paths"]}
    expected = {r.__name__.lstrip("_") for r in RULES}
    names = {
        "credential_exposure",
        "spoofable_email_domain",
        "exploitable_public_service",
        "exposed_sensitive_service",
        "identity_correlation",
        "tls_interception",
        "subdomain_takeover_candidate",
        "malicious_reputation",
        "web_information_leak",
        "end_of_life_software",
        "leaked_secret_in_code",
        "exposed_sensitive_file",
        "public_cloud_storage",
        "staff_enumeration",
    }
    assert fired == names and len(expected) == len(names)


def test_demo_exports_as_valid_stix():
    investigation, graph = build_demo()
    stix2.parse(build_bundle(investigation, graph).serialize(), allow_custom=False)


def test_paths_and_demo_api(client):
    assert client.post("/api/demo").json()["investigation_id"] == DEMO_ID
    data = client.get(f"/api/investigation/{DEMO_ID}/paths").json()
    assert data["summary"]["total"] >= 9 and data["paths"][0]["severity"] == "critical"
    assert all(set(p) >= {"steps", "edges", "techniques", "remediation"} for p in data["paths"])
    assert client.get("/api/audit", params={"action": "demo.load"}).json()
    client.post("/api/demo")  # reloading is idempotent
    assert len([i for i in client.get("/api/investigations").json() if i["id"] == DEMO_ID]) == 1


def test_demo_load_requires_admin(client):
    viewer = client.post("/api/keys", json={"name": "v", "role": "viewer"}).json()["key"]
    client.headers["Authorization"] = f"Bearer {viewer}"
    assert client.post("/api/demo").status_code == 403


def test_cli_load_demo(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ARGUS_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'demo.db'}")
    get_settings.cache_clear()
    monkeypatch.setattr(sys, "argv", ["argus", "--load-demo"])
    try:
        console.cli_entrypoint()
    finally:
        get_settings.cache_clear()
    assert DEMO_ID in capsys.readouterr().out
