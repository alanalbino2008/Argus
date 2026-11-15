"""Security rating: scoring rules, coverage honesty, what-if plans, benchmarks and the API."""

from __future__ import annotations

from typing import Any

import pytest

from argus.api.rating_routes import percentile
from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType
from argus.demo import DEMO_ID, build_demo
from argus.intel.paths import find_attack_paths
from argus.intel.rating import FACTORS, compute_rating, grade_for

E = EntityType


def rate_demo(previous: bool = False) -> dict[str, Any]:
    _, graph = build_demo(previous=previous)
    return compute_rating(graph, find_attack_paths(graph)["paths"])


def graph_of(seed_md: dict[str, Any], *extra: Entity) -> IntelligenceGraph:
    graph = IntelligenceGraph("inv")
    graph.add_entity(Entity.create(E.DOMAIN, "acme.com", metadata=seed_md, depth=0), is_seed=True)
    for entity in extra:
        graph.add_entity(entity)
    return graph


CLEAN = {
    "dns_checked": True, "dmarc_policy": "reject", "spf": "v=spf1 include:_spf.mail.com -all",
    "security_headers_grade": "A", "security_txt": {"present": True}, "lookalikes_checked": 300,
    "wayback": {"urls_archived": 10},
}  # fmt: skip


def path(rule: str, severity: str, pid: str = "p1") -> dict[str, Any]:
    return {"id": pid, "rule": rule, "severity": severity, "title": f"{rule} {pid}", "remediation": [f"fix {pid}"]}


# ---------------------------------------------------------------------------- the model
def test_weights_and_grade_bands():
    assert sum(w for _, w, _ in FACTORS.values()) == pytest.approx(1.0)
    assert [grade_for(s) for s in (100, 90, 89.9, 80, 70, 60, 59.9, 0)] == ["A", "A", "B", "B", "C", "D", "F", "F"]


def test_a_clean_organisation_rates_a_and_strengths_are_credited():
    r = compute_rating(graph_of(CLEAN, Entity.create(E.IP_ADDRESS, "203.0.113.5", depth=1)), [])
    assert (r["score"], r["grade"], r["critical_issues"], r["capped_at"]) == (100.0, "A", 0, None)
    email = next(f for f in r["factors"] if f["id"] == "email")
    assert set(email["strengths"]) == {"DMARC policy is p=reject: forged mail is refused",
                                       "SPF hard-fails unauthorised senders (-all)"}  # fmt: skip
    assert r["plan"] == {"issues": [], "reaches": "A"}


def test_the_demo_is_capped_by_its_critical_findings():
    r = rate_demo()
    assert r["grade"] == "F" and r["score"] == 59 and r["critical_issues"] == 5 and r["capped_at"] == 59
    assert r["uncapped_score"] > r["score"] and r["confidence"] == 1.0
    first = r["issues"][0]
    assert first["severity"] == "critical" and first["title"].startswith("Actively exploited vulnerabilities")
    assert first["impact"] == max(i["impact"] for i in r["issues"] if i["severity"] == "critical") > 0
    assert all(i["path_id"] for i in r["issues"] if i["source"] == "attack_path")
    assert r["plan"]["reaches"] == "D" and len(r["plan"]["issues"]) == 3  # lifting the cap needs 3 critical fixes
    earlier = rate_demo(previous=True)
    assert earlier["grade"] == "D" and earlier["score"] > r["score"]  # the surface got worse, and so did the grade


def test_caps():
    r1 = compute_rating(graph_of(CLEAN), [path("exploitable_public_service", "critical")])
    assert r1["score"] <= 69 and r1["capped_at"] == 69
    three = [path("exploitable_public_service", "critical", "a"), path("credential_exposure", "critical", "b"),
             path("public_cloud_storage", "critical", "c")]  # fmt: skip
    r3 = compute_rating(graph_of(CLEAN), three)
    assert r3["score"] <= 59 and r3["capped_at"] == 59 and r3["critical_issues"] == 3


def test_diminishing_returns_inside_a_factor():
    r = compute_rating(
        graph_of(CLEAN),
        [path("exposed_sensitive_service", "high", "a"), path("exposed_sensitive_service", "high", "b")],
    )
    network = next(f for f in r["factors"] if f["id"] == "network")
    assert network["score"] == 100 - 20 - 12  # the second exposure costs less than the first
    costs = sorted(i["points"] for i in r["issues"])
    assert costs == [12.0, 20.0]


def test_unassessed_factors_lower_confidence_instead_of_counting_as_perfect():
    r = compute_rating(graph_of({"dns_checked": True, "dmarc_policy": "reject", "spf": "-all"}), [])
    assessed = {f["id"] for f in r["factors"] if f["assessed"]}
    assert assessed == {"email", "dns", "social"}
    assert r["confidence"] == pytest.approx(0.25) and r["provisional"]
    web = next(f for f in r["factors"] if f["id"] == "web")
    assert web["grade"] is None


@pytest.mark.parametrize(
    "seed_md, title, severity",
    [
        ({"spf": "v=spf1 ~all"}, "SPF only soft-fails unauthorised senders (~all)", "low"),
        ({"spf": "v=spf1 +all"}, "SPF allows any sender (+all/?all)", "high"),
        ({"spf": "missing"}, "No SPF record", "medium"),
        ({"dmarc_policy": "quarantine"}, "DMARC quarantines rather than rejects forged mail", "low"),
        ({"security_headers_grade": "D", "missing_security_headers": ["content-security-policy"]},
         "Weak browser security headers on acme.com (grade D)", "medium"),
        ({"security_txt": {"present": False}}, "No security.txt", "low"),
    ],
)  # fmt: skip
def test_direct_measurements(seed_md, title, severity):
    r = compute_rating(graph_of({**CLEAN, **seed_md}), [])
    assert [(i["title"], i["severity"]) for i in r["issues"]] == [(title, severity)]
    assert r["issues"][0]["source"] == "measurement" and r["issues"][0]["fix"]


def test_certificate_measurements():
    expired = Entity.create(E.CERTIFICATE, "Cert: acme.com", metadata={"expired": True}, depth=1)
    soon = Entity.create(E.CERTIFICATE, "Cert: www.acme.com", metadata={"days_remaining": 5}, depth=1)
    r = compute_rating(graph_of(CLEAN, expired, soon), [])
    assert {(i["severity"], i["title"].split(":")[0]) for i in r["issues"]} == {
        ("high", "Expired certificate"), ("low", "Certificate expires in 5 day(s)")}  # fmt: skip


def test_third_party_assets_never_affect_the_rating():
    impostor = Entity.create(
        E.CERTIFICATE, "Cert: acme-login.com", metadata={"expired": True, "out_of_scope": True}, depth=1
    )
    assert compute_rating(graph_of(CLEAN, impostor), [])["score"] == 100


def test_benchmark_percentiles_are_honest():
    assert percentile(70, [50, 60]) == 100
    assert percentile(70, [50]) is None  # two organisations are not a benchmark
    assert percentile(70, [80, 70, 60, 50]) == 62  # ties count half
    assert percentile(40, [80, 70]) == 0


# ---------------------------------------------------------------------------- the API
@pytest.fixture
def client(make_client):
    c = make_client(monitors_enabled="false", notifications_enabled="false", report_schedules_enabled="false")
    c.post("/api/demo")
    return c


def test_rating_endpoint_with_trend_and_cache(client):
    r = client.get(f"/api/investigation/{DEMO_ID}/rating").json()
    assert r["grade"] == "F" and r["investigation_id"] == DEMO_ID and not r["live"]
    assert [h["grade"] for h in r["history"]] == ["D", "F"]  # the earlier demo scan was rated too
    assert r["benchmark"]["percentile"] is None and r["benchmark"]["basis"].startswith("organisations assessed")
    again = client.get(f"/api/investigation/{DEMO_ID}/rating").json()
    assert again["score"] == r["score"] and again["issues"] == r["issues"]  # served from the cache


def test_portfolio(client):
    p = client.get("/api/ratings").json()
    [org] = p["organisations"]
    assert org["target"] == "acme-corp.example" and org["grade"] == "F" and org["trend"] == [69.0, 59.0]
    assert org["change"] == -10.0 and org["weakest"]["name"] == "Leaks & data exposure" and org["percentile"] is None
    assert p["distribution"] == {"A": 0, "B": 0, "C": 0, "D": 0, "F": 1}


def test_ratings_are_workspace_scoped(client):
    client.get(f"/api/investigation/{DEMO_ID}/rating")
    client.post("/api/workspaces", json={"name": "Red Team"})
    red = {"X-Argus-Workspace": "red-team"}
    assert client.get(f"/api/investigation/{DEMO_ID}/rating", headers=red).status_code == 404
    assert client.get("/api/ratings", headers=red).json()["organisations"] == []


def test_the_report_carries_the_rating():
    from argus.reports.data import Branding, ReportOptions, build_report_data

    inv, graph = build_demo()
    data = build_report_data(inv, graph, ReportOptions(), Branding())
    assert data.security_rating["grade"] == "F" and data.security_rating["plan_reaches"] == "D"
    assert all("Dana Whitfield" not in p["title"] for p in data.security_rating["plan"])  # pseudonymised
