"""Phase 66: the dated facts inside a case's scans, and what changed between them, on its timeline."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType, Investigation, InvestigationStatus, Relation, RelationType, ScanConfig
from argus.demo import DEMO_ID, DEMO_PREVIOUS_ID, build_demo
from argus.intel.fact_timeline import RULES, case_facts, dated_facts, parse_date


@pytest.mark.parametrize(
    "value, precision, iso",
    [
        ("2009", "year", "2009-01-01T00:00:00+00:00"),
        ("2009-03", "month", "2009-03-01T00:00:00+00:00"),
        ("2009-03-14", "day", "2009-03-14T00:00:00+00:00"),
        ("2014-09-02T10:21:00Z", "time", "2014-09-02T10:21:00+00:00"),
        ("2014-09-02T10:21:00+02:00", "time", "2014-09-02T10:21:00+02:00"),
    ],
)
def test_dates_keep_their_precision(value, precision, iso):
    moment, got = parse_date(value)
    assert got == precision and moment.isoformat() == iso


@pytest.mark.parametrize("value", [None, 1700000000, "", "yesterday", "2009-13-01", "0001-01-01T00:00:00", "9999"])
def test_unusable_dates_are_ignored(value):
    assert parse_date(value) is None


def test_every_rule_names_its_source():
    assert all(rule.via for rule in RULES)


def _inv(inv_id: str, target: str, minutes: int) -> Investigation:
    created = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=minutes)
    return Investigation(id=inv_id, name=inv_id, config=ScanConfig(target=target, target_type=EntityType.DOMAIN),
                         status=InvestigationStatus.COMPLETED, created_at=created, completed_at=created)  # fmt: skip


def test_facts_from_one_scan():
    inv, graph = build_demo()
    facts = {e["fact"]: e for e in dated_facts(inv, graph)}
    assert {"domain_registered", "account_created", "breach", "pgp_key_created", "archived", "document_created",
            "end_of_life", "kev_added", "certificate_expires"} <= set(facts)  # fmt: skip
    registered = facts["domain_registered"]
    assert registered["title"] == "Domain registered: acme-corp.example" and registered["precision"] == "day"
    assert registered["detail"] == "Source: the RDAP registration record"  # "seed" is not a module
    assert registered["ref"] == {
        "type": "entity",
        "investigation_id": inv.id,
        "entity_id": registered["ref"]["entity_id"],
    }
    assert graph.get_entity(registered["ref"]["entity_id"]).value == "acme-corp.example"
    assert "found by hibp" in facts["breach"]["detail"]


def test_officer_appointments_come_from_relations():
    graph = IntelligenceGraph("inv_c")
    person = Entity.create(EntityType.PERSON, "Jane Roe")
    company = Entity.create(EntityType.ORGANIZATION, "Roe Holdings Ltd", metadata={"incorporated": "2012-06-01"})
    graph.add_entity(person)
    graph.add_entity(company)
    graph.add_relation(Relation.create(person.id, company.id, RelationType.OFFICER_OF,
                                       metadata={"role": "director", "appointed": "2015-02-03", "resigned": "2019"}))  # fmt: skip
    titles = {e["title"]: e["precision"] for e in dated_facts(_inv("inv_c", "roe.example", 0), graph)}
    assert titles == {
        "Company incorporated: Roe Holdings Ltd": "day",
        "Jane Roe appointed director of Roe Holdings Ltd": "day",
        "Jane Roe resigned as director of Roe Holdings Ltd": "year",
    }


def test_a_fact_seen_by_several_scans_appears_once():
    first, second = _inv("inv_1", "acme-corp.example", 0), _inv("inv_2", "acme-corp.example", 60)
    _, graph = build_demo()
    entries = case_facts([(second, graph), (first, graph)])
    registered = [e for e in entries if e.get("fact") == "domain_registered"]
    assert len(registered) == 1
    assert [s["id"] for s in registered[0]["seen_in"]] == ["inv_1", "inv_2"]
    assert registered[0]["ref"]["investigation_id"] == "inv_2"  # the latest scan that saw it
    assert registered[0]["detail"].endswith("seen in 2 scans")
    assert [datetime.fromisoformat(e["at"]) for e in entries] == sorted(
        datetime.fromisoformat(e["at"]) for e in entries
    )


def test_what_changed_between_scans():
    prev_inv, prev = build_demo(previous=True)
    inv, cur = build_demo()
    changes = [e for e in case_facts([(inv, cur), (prev_inv, prev)]) if e["kind"] == "change"]
    added = next(c for c in changes if c["fact"] == "entities_added")
    removed = next(c for c in changes if c["fact"] == "entities_removed")
    assert added["title"] == "9 new on acme-corp.example" and "3 domain" in added["detail"]
    assert removed["title"] == "1 gone from acme-corp.example" and "Port 21 (FTP)" in removed["detail"]
    assert added["ref"] == {"type": "investigation", "id": inv.id, "compared_with": prev_inv.id}


def test_changes_only_compare_scans_of_the_same_target():
    _, graph = build_demo()
    a, b = _inv("inv_a", "one.example", 0), _inv("inv_b", "two.example", 10)
    assert [e for e in case_facts([(a, graph), (b, IntelligenceGraph("inv_b"))]) if e["kind"] == "change"] == []


def test_case_timeline_api(make_client):
    client = make_client(monitors_enabled="false")
    client.post("/api/demo")
    case = client.post("/api/cases", json={"title": "Acme", "confirmed": True,
                                           "purpose": "Reviewing Acme's exposure for the client"}).json()  # fmt: skip
    for inv_id in (DEMO_PREVIOUS_ID, DEMO_ID):
        client.post(f"/api/cases/{case['id']}/items", json={"kind": "scan", "data": {"investigation_id": inv_id}})
    timeline = client.get(f"/api/cases/{case['id']}/timeline").json()
    kinds = {e["kind"] for e in timeline}
    assert {"scan", "fact", "change"} <= kinds
    facts = [e for e in timeline if e["kind"] == "fact"]
    assert any(e["title"] == "Domain registered: acme-corp.example" for e in facts)
    moments = [datetime.fromisoformat(e["at"]) for e in timeline]
    assert moments == sorted(moments)
    without = client.get(f"/api/cases/{case['id']}/timeline", params={"facts": "false"}).json()
    assert not {"fact", "change"} & {e["kind"] for e in without}
    csv_export = client.get(f"/api/cases/{case['id']}/timeline.csv").content.decode("utf-8-sig")
    assert "Domain registered: acme-corp.example" in csv_export and "9 new on acme-corp.example" in csv_export
