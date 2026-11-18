"""Playbooks: the catalogue, what stands out, the pages preserved, and runs in a case end to end.

Scans are replaced by a stand-in that returns a prepared graph, so the tests check what a
playbook does with results, not the modules themselves (those have their own tests).
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from functools import partial
from typing import Any

import pytest

from argus.api import playbook_routes
from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType, Relation, RelationType
from argus.evidence.capture import Capture, CaptureError
from argus.intel import playbooks
from argus.modules import get_module_catalog
from tests.test_analyst import claude  # noqa: F401 - the Claude stand-in fixture
from tests.test_cases import new_case


# ---------------------------------------------------------------------------- the catalogue
def test_every_playbook_names_real_modules_that_suit_its_starting_point():
    catalog = get_module_catalog()
    for book in playbooks.CATALOGUE.values():
        assert book.steps[-1].kind == "brief" and any(s.kind == "findings" for s in book.steps)
        for step in (s for s in book.steps if s.kind == "scan"):
            assert set(step.modules) <= set(catalog), (book.id, set(step.modules) - set(catalog))
            assert any(set(book.seed_types) & set(catalog[m].supported_entity_types) for m in step.modules), book.id
    covered = {t for b in playbooks.CATALOGUE.values() for t in b.seed_types}
    assert covered >= {EntityType.ORGANIZATION, EntityType.PERSON, EntityType.USERNAME, EntityType.EMAIL,
                       EntityType.CRYPTO_WALLET, EntityType.DOMAIN, EntityType.PHONE}  # fmt: skip


# ---------------------------------------------------------------------------- what stands out
def company_graph() -> IntelligenceGraph:
    g = IntelligenceGraph("t")
    company = Entity.create(EntityType.ORGANIZATION, "Acme Holdings Ltd", metadata={
        "register_url": "https://find-and-update.company-information.service.gov.uk/company/01234567",
        "offshore_leaks": [{"name": "ACME HOLDINGS LTD", "score": 0.97, "url": "https://offshoreleaks.icij.org/nodes/1"}]})  # fmt: skip
    director = Entity.create(EntityType.PERSON, "Ivan Petrov", depth=1, metadata={"born": "1975-03", "sanction_matches": [
        {"name": "PETROV, Ivan", "list": "UK Sanctions List", "score": 0.98}]})  # fmt: skip
    namesake = Entity.create(EntityType.PERSON, "John Smith", depth=1, metadata={"sanction_matches": [
        {"name": "SMITH, John", "list": "OFAC SDN", "score": 0.95, "conflicts": ["Born 1980, but the listed person was born 1950"]}]})  # fmt: skip
    profile = Entity.create(EntityType.SOCIAL_PROFILE, "https://github.com/acme", label="GitHub: acme", depth=1,
                            confidence=0.85, metadata={"platform": "GitHub"})  # fmt: skip
    weak = Entity.create(EntityType.SOCIAL_PROFILE, "https://example.social/acme", depth=1, confidence=0.4)
    for e in (company, director, namesake, profile, weak):
        g.add_entity(e, is_seed=e.depth == 0)
    g.add_relation(Relation.create(director.id, company.id, RelationType.OFFICER_OF, label="director"))
    g.add_relation(Relation.create(namesake.id, company.id, RelationType.CONTROLS, label="Significant control",
                                   metadata={"nature": ["ownership of shares 75 to 100 percent"]}))  # fmt: skip
    return g


def test_what_stands_out_comes_first_and_namesakes_are_downgraded():
    found = playbooks.highlights(company_graph())
    titles = [h.title for h in found]
    assert titles[0] == "Possible sanctions match: Ivan Petrov" and found[0].level == "high"
    namesake = next(h for h in found if "John Smith" in h.title and "sanctions" in h.title)
    assert namesake.level == "medium" and "Probably a different person" in namesake.detail
    assert namesake.as_dict()["tick"] is False and found[0].as_dict()["tick"] is True
    leak = next(h for h in found if "Offshore Leaks" in h.title)
    assert leak.level == "medium" and leak.url == "https://offshoreleaks.icij.org/nodes/1"
    director = next(h for h in found if h.title == "Ivan Petrov: director of Acme Holdings Ltd")
    assert director.entity == {"type": "person", "value": "Ivan Petrov",
                               "attributes": {"role": "director of Acme Holdings Ltd", "born": "1975-03"}}  # fmt: skip
    owner = next(h for h in found if h.title.startswith("John Smith: Significant control"))
    assert "75 to 100" in owner.detail
    levels = [h.level for h in found]
    assert levels == sorted(levels, key=playbooks.LEVEL_ORDER.get)
    note = playbooks.findings_note("Company due diligence", "Acme Holdings Ltd", found, {"entities": 5, "relations": 2})
    assert (
        "Needs attention:\n- Possible sanctions match: Ivan Petrov" in note
        and "possibilities, not identifications" in note
    )
    assert "not proof of absence" in playbooks.findings_note("x", "y", [], {})


def test_crypto_trails_flag_sanctions_and_same_owner_wallets():
    g = IntelligenceGraph("w")
    wallet = Entity.create(EntityType.CRYPTO_WALLET, "bc1qorigin", metadata={
        "sanctioned_counterparties": [{"address": "bc1qbad", "name": "LAZARUS GROUP"}]})  # fmt: skip
    sibling = Entity.create(EntityType.CRYPTO_WALLET, "bc1qsibling", depth=1, metadata={"sanctions": ["OFAC SDN"]})
    g.add_entity(wallet, is_seed=True)
    g.add_entity(sibling)
    g.add_relation(Relation.create(wallet.id, sibling.id, RelationType.SAME_WALLET, label="Spent together"))
    found = {h.title: h for h in playbooks.highlights(g)}
    assert found["Dealt with a sanctioned wallet: bc1qbad (LAZARUS GROUP)"].level == "high"
    assert found["Sanctioned wallet: bc1qsibling"].level == "high"
    assert found["Probably the same owner: bc1qsibling"].entity["type"] == "wallet"


def test_the_pages_worth_preserving():
    g = company_graph()
    assert playbooks.capture_urls(g, ("register",), "Acme", 5) == [
        "https://find-and-update.company-information.service.gov.uk/company/01234567"
    ]
    assert playbooks.capture_urls(g, ("profiles",), "acme", 10) == ["https://github.com/acme"]  # weak matches skipped
    assert playbooks.capture_urls(g, ("website",), "https://Example.org/", 1) == ["https://example.org/"]


# ---------------------------------------------------------------------------- runs in a case
class FakeScans:
    """Stands in for the engine: records each scan's settings and returns a prepared graph."""

    def __init__(self, graph: IntelligenceGraph, *, hold: bool = False):
        self.graph, self.hold, self.configs = graph, hold, []
        self.release = threading.Event()  # set from the test's thread; the scan runs on the app's

    async def __call__(self, app, config, *, by, purpose, workspace_id, egress):
        self.configs.append({"config": config, "purpose": purpose, "egress": egress})
        if self.hold:
            await asyncio.to_thread(self.release.wait, 10)
        return f"inv-{len(self.configs)}", self.graph


def fake_capture(url: str, settings: Any, route: Any = None) -> Capture:
    if "github" in url:
        raise CaptureError("The capture browser is not installed")
    files = {"text.txt": ("text/plain", f"Preserved {url}".encode())}
    return Capture({"kind": "web_capture", "url": url, "title": url, "files": ["text.txt"]}, "d" * 64, files, None, [])


async def _capture(url, settings, route=None):
    return fake_capture(url, settings, route)


@pytest.fixture
def pb(make_client, monkeypatch):
    monkeypatch.setattr(playbook_routes, "capture_url", _capture)
    c = make_client(monitors_enabled="false")
    scans = FakeScans(company_graph())
    c.app.state.playbook_scan = scans
    return c, scans


def wait(c, case_id, run_id, until=("completed", "failed", "cancelled", "interrupted"), seconds=10.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        run = c.get(f"/api/cases/{case_id}/playbooks/{run_id}").json()
        if run["status"] in until:
            return run
        time.sleep(0.05)
    raise AssertionError(f"run stayed {run['status']}: {json.dumps(run['steps'])[:500]}")


def start(c, case_id, playbook="company_due_diligence", seed="Acme Holdings Ltd", **extra):
    return c.post(
        f"/api/cases/{case_id}/playbooks", json={"playbook": playbook, "seed": seed, "confirmed": True, **extra}
    )


def test_a_company_playbook_runs_end_to_end(pb):
    c, scans = pb
    books = {b["id"]: b for b in c.get("/api/playbooks").json()}
    assert "companies_house" in books["company_due_diligence"]["steps"][0]["unavailable"]  # no key in tests
    case = new_case(c).json()
    r = start(c, case["id"])
    assert r.status_code == 202 and r.json()["status"] == "running"
    run = wait(c, case["id"], r.json()["id"])
    assert run["status"] == "completed", run
    assert [s["status"] for s in run["steps"]] == ["done", "done", "done", "skipped"]
    assert run["steps"][0]["investigation_id"] == "inv-1" and "companies_house" not in run["steps"][0]["modules"]
    assert run["steps"][1]["detail"] == "Preserved 1 of 1 page(s)" and run["steps"][3]["detail"] == "Not requested"
    assert run["highlights"][0]["title"] == "Possible sanctions match: Ivan Petrov"
    config = scans.configs[0]["config"]
    assert config.target_type == EntityType.ORGANIZATION and config.max_depth == 2 and not config.passive_only
    assert "(playbook: Company due diligence)" in scans.configs[0]["purpose"]

    full = c.get(f"/api/cases/{case['id']}").json()
    kinds = [(i["kind"], i["title"]) for i in full["items"]]
    assert ("scan", "Acme Holdings Ltd") in kinds and ("entity", "Acme Holdings Ltd") in kinds
    note = next(i for i in full["items"] if i["title"].startswith("Playbook findings"))
    assert "Possible sanctions match: Ivan Petrov" in note["body"]
    assert full["captures"][0]["note"] == "Preserved by the Company due diligence playbook"
    actions = [e["action"] for e in _audit(c)]
    assert {"playbook.start", "scan.start", "evidence.capture"} <= set(actions)
    assert c.get(f"/api/cases/{case['id']}/playbooks").json()[0]["id"] == run["id"]


def _audit(c) -> list[dict[str, Any]]:
    data = c.get("/api/audit?limit=200").json()
    return data if isinstance(data, list) else data.get("entries", data.get("items", []))


def test_a_failed_capture_does_not_stop_the_run(pb):
    c, scans = pb
    scans.graph = company_graph()
    case = new_case(c).json()
    run = wait(c, case["id"], start(c, case["id"], "online_identity", "acmeofficial").json()["id"])
    capture = run["steps"][1]
    assert capture["status"] == "failed" and "capture browser is not installed" in capture["detail"]
    assert run["steps"][2]["status"] == "done" and run["status"] == "completed"
    assert scans.configs[0]["config"].handle_variants is True


@pytest.mark.parametrize("body, status, words", [
    ({"playbook": "nope", "seed": "x"}, 404, "Unknown playbook"),
    ({"playbook": "crypto_trail", "seed": "jane@example.org"}, 422, "looks like a email"),
    ({"playbook": "crypto_trail", "seed": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdx"}, 422, "checksum"),
    ({"playbook": "person_background", "seed": "Jane Roe", "confirmed": False}, 422, "legitimate purpose"),
    ({"playbook": "person_background", "seed": "Jane Roe", "ai_brief": True}, 428, "Anthropic"),
])  # fmt: skip
def test_starting_a_playbook_is_checked(pb, body, status, words):
    c, _ = pb
    case = new_case(c).json()
    r = c.post(f"/api/cases/{case['id']}/playbooks", json={"confirmed": True, **body})
    assert r.status_code == status and words in r.json()["detail"], r.json()


def test_a_name_becomes_a_company_or_a_person_as_the_playbook_says(pb):
    c, scans = pb
    case = new_case(c).json()
    wait(c, case["id"], start(c, case["id"], "company_due_diligence", "Hope Relief").json()["id"])
    assert scans.configs[-1]["config"].target_type == EntityType.ORGANIZATION


def test_one_run_at_a_time_and_stopping_it(pb):
    c, scans = pb
    scans.hold = True
    case = new_case(c).json()
    run_id = start(c, case["id"]).json()["id"]
    assert start(c, case["id"]).status_code == 409
    stopped = c.post(f"/api/cases/{case['id']}/playbooks/{run_id}/cancel")
    assert stopped.status_code == 200 and stopped.json()["status"] == "cancelled"
    scans.release.set()
    time.sleep(0.5)
    run = c.get(f"/api/cases/{case['id']}/playbooks/{run_id}").json()
    assert run["status"] == "cancelled"
    assert [s["status"] for s in run["steps"][1:]] == ["skipped"] * 3
    assert c.post(f"/api/cases/{case['id']}/playbooks/{run_id}/cancel").status_code == 409
    c.patch(f"/api/cases/{case['id']}", json={"status": "closed"})
    assert start(c, case["id"]).status_code == 409  # closed cases take no new runs


def test_the_ai_briefing_step_runs_only_when_asked(make_client, claude, monkeypatch):  # noqa: F811
    from argus.api import analyst_routes
    from argus.security.ratelimit import SlidingWindowLimiter

    monkeypatch.setattr(playbook_routes, "capture_url", _capture)
    monkeypatch.setattr(analyst_routes, "_limiter", SlidingWindowLimiter(limit=100, window=60))
    c = make_client(anthropic_api_key="own-test-key", analyst_model="claude-chosen-test", monitors_enabled="false")
    c.app.state.playbook_scan = FakeScans(company_graph())
    case = new_case(c).json()
    run = wait(c, case["id"], start(c, case["id"], ai_brief=True, ai_acknowledged=True).json()["id"])
    brief = run["steps"][-1]
    assert brief["status"] == "done" and brief["brief"]["result"]["summary"].startswith("Jane Doe")
    sent = claude.requests[0]["messages"][0]["content"][0]["text"]
    assert "Playbook findings" in sent  # the briefing reads what the playbook found
    capture_id = c.get(f"/api/cases/{case['id']}").json()["captures"][0]["id"]
    custody = c.get(f"/api/evidence/{capture_id}").json()["custody"]
    assert "sent for AI analysis" in [e["action"] for e in custody]
    assert "case.analyst" in [e["action"] for e in _audit(c)]


def test_runs_left_by_a_stopped_server_are_marked_interrupted(pb):
    c, _ = pb
    case = new_case(c).json()
    repo = c.app.state.playbooks
    mine = c.portal.call(partial(repo.create, workspace_id="w", case_id=case["id"], playbook="phone_lookup", seed="+44",
                                 seed_type="phone", by="x", steps=[], options={}, owner="this-server"))  # fmt: skip
    other = c.portal.call(partial(repo.create, workspace_id="w", case_id=case["id"], playbook="phone_lookup", seed="+44",
                                  seed_type="phone", by="x", steps=[], options={}, owner="another-server"))  # fmt: skip
    assert c.portal.call(partial(repo.interrupt_running, "this-server")) == 1
    assert c.portal.call(partial(repo.status, mine["id"])) == "interrupted"
    assert c.portal.call(partial(repo.status, other["id"])) == "running"  # another server's run is left alone
