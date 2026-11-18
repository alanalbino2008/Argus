"""People in a case: brought in from scans (automatically and by hand), and their profiles."""

from __future__ import annotations

from functools import partial

from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType, Investigation, Relation, RelationType, ScanConfig
from argus.intel.people_import import automatic, proposals
from tests.test_cases import new_case


def company_scan(inv_id: str = "inv_people") -> IntelligenceGraph:
    g = IntelligenceGraph(inv_id)
    company = Entity.create(EntityType.ORGANIZATION, "Hope Relief Ltd", metadata={"company_number": "01234567"})
    jane = Entity.create(EntityType.PERSON, "Jane Roe", depth=1, confidence=0.95,
                         metadata={"born": "1980-04", "nationality": "British", "role": "director"})  # fmt: skip
    ivan = Entity.create(EntityType.PERSON, "Ivan Petrov", depth=1, confidence=0.95, metadata={"sanction_matches": [
        {"list": "UK Sanctions List", "name": "PETROV, Ivan", "score": 0.97, "conflicts": ["Born 1980, but the listed person was born 1950"]}]})  # fmt: skip
    old = Entity.create(EntityType.PERSON, "Old Director", depth=1, confidence=0.95)
    maybe = Entity.create(EntityType.PERSON, "Possibly Someone", depth=2, confidence=0.5)
    noise = Entity.create(EntityType.PERSON, "Very Unsure", depth=2, confidence=0.2)
    other = Entity.create(EntityType.ORGANIZATION, "Impostor Ltd", depth=1, metadata={"out_of_scope": True})
    telecom = Entity.create(EntityType.ORGANIZATION, "Telecom Region: United Kingdom", depth=1)
    account = Entity.create(EntityType.SOCIAL_PROFILE, "https://github.com/janeroe", label="GitHub: janeroe", depth=2,
                            confidence=0.85, metadata={"platform": "GitHub", "profile": {"bio": "Charity treasurer"}})  # fmt: skip
    for e in (company, jane, ivan, old, maybe, noise, other, telecom, account):
        g.add_entity(e, is_seed=e.depth == 0)
    g.add_relation(Relation.create(jane.id, company.id, RelationType.OFFICER_OF, label="director",
                                   metadata={"from": "2018-01-02"}))  # fmt: skip
    g.add_relation(Relation.create(ivan.id, company.id, RelationType.CONTROLS, label="Significant control"))
    g.add_relation(Relation.create(old.id, company.id, RelationType.OFFICER_OF, label="director (resigned)",
                                   metadata={"from": "2010-01-01", "to": "2015-06-30"}))  # fmt: skip
    g.add_relation(Relation.create(jane.id, account.id, RelationType.HAS_ACCOUNT, label="Registered on GitHub"))
    return g


def test_a_scan_proposes_people_and_relationships():
    items = [{"id": "co", "kind": "entity", "title": "Hope Relief Ltd", "body": "",
              "data": {"type": "organisation", "value": "HOPE RELIEF LTD", "attributes": {}}}]  # fmt: skip
    found = proposals(company_scan(), items, scan_label="Hope Relief Ltd")
    by_value = {p["value"]: p for p in found["entities"]}
    assert by_value["Hope Relief Ltd"]["existing"] == "co"  # already in the case: never added twice
    assert by_value["Jane Roe"]["automatic"] and by_value["Jane Roe"]["attributes"]["born"] == "1980-04"
    assert "possible match on UK Sanctions List" in by_value["Ivan Petrov"]["attributes"]["sanctions"]
    assert not by_value["Possibly Someone"]["automatic"]  # found, but not sure enough to add unasked
    assert {"Very Unsure", "Impostor Ltd", "Telecom Region: United Kingdom"}.isdisjoint(by_value)
    assert (
        by_value["https://github.com/janeroe"]["type"] == "account"
        and not by_value["https://github.com/janeroe"]["automatic"]
    )
    kinds = {(r["relation"], r["until"]) for r in found["relationships"]}
    assert {("director", None), ("owner", None), ("director", "2015-06-30"), ("uses", None)} <= kinds
    auto = automatic(found)
    assert {p["value"] for p in auto["entities"]} == {"Jane Roe", "Ivan Petrov", "Old Director"}
    assert (
        all(r["relation"] in ("director", "owner") for r in auto["relationships"]) and len(auto["relationships"]) == 3
    )


def link_scan(c, case_id: str, graph: IntelligenceGraph) -> str:
    repo = c.app.state.repo
    inv = Investigation(id=graph.investigation_id, name="scan", config=ScanConfig(target="Hope Relief Ltd",
                        target_type=EntityType.ORGANIZATION))  # fmt: skip
    inv.workspace_id = "ws_default"
    c.portal.call(partial(repo.save_investigation, inv))
    c.portal.call(partial(repo.save_graph, graph))
    c.post(f"/api/cases/{case_id}/items", json={"kind": "scan", "data": {"investigation_id": inv.id}})
    return inv.id


def test_people_are_brought_in_automatically_and_by_hand(client):
    from argus.api.people_routes import auto_import
    from argus.security.auth import Principal, Role

    case = new_case(client).json()
    inv_id = link_scan(client, case["id"], company_scan())
    who = Principal(key_id="k", name="analyst", role=Role.ANALYST)
    client.portal.call(partial(auto_import, client.app, case["id"], inv_id, who, "ws_default"))
    items = client.get(f"/api/cases/{case['id']}").json()["items"]
    people = {i["data"]["value"]: i for i in items if i["kind"] == "entity"}
    assert set(people) == {"Hope Relief Ltd", "Jane Roe", "Ivan Petrov", "Old Director"}
    assert (
        people["Jane Roe"]["data"]["source_investigation_id"] == inv_id
        and "Added from the scan" in people["Jane Roe"]["body"]
    )
    links = [i["data"] for i in items if i["kind"] == "link"]
    old = next(link for link in links if link["from"] == people["Old Director"]["id"])
    assert old["relation"] == "director" and old["until"] == "2015-06-30" and old["since"] == "2010-01-01"
    assert old["label"] == "director (resigned) of"
    profile = client.get(f"/api/cases/{case['id']}/entities/{people['Jane Roe']['id']}/profile").json()
    jane_dates = [t for t in profile["timeline"] if t["date"].startswith("2018-01-02")]
    assert len(jane_dates) == 1 and jane_dates[0]["source"] == "register"  # one entry, not two
    client.portal.call(partial(auto_import, client.app, case["id"], inv_id, who, "ws_default"))
    again = client.get(f"/api/cases/{case['id']}").json()["items"]
    assert len(again) == len(items)  # running it again adds nothing

    offer = client.get(f"/api/cases/{case['id']}/scan-people?investigation_id={inv_id}").json()
    account = next(p for p in offer["entities"] if p["type"] == "account")
    assert next(p for p in offer["entities"] if p["value"] == "Jane Roe")["existing"] == people["Jane Roe"]["id"]
    added = client.post(f"/api/cases/{case['id']}/scan-people",
                        json={"investigation_id": inv_id, "keys": [account["key"]]}).json()  # fmt: skip
    assert added == {"entities": 1, "relationships": 1}  # the account, and that Jane uses it
    assert client.get(f"/api/cases/{case['id']}/scan-people").json()["scans"][0]["investigation_id"] == inv_id
    assert client.get(f"/api/cases/{case['id']}/scan-people?investigation_id=inv_other").status_code == 404


def test_a_person_profile_brings_everything_together(client):
    case = new_case(client).json()
    add = lambda kind, **kw: client.post(f"/api/cases/{case['id']}/items", json={"kind": kind, **kw}).json()  # noqa: E731
    jane = add(
        "entity", data={"type": "person", "value": "Jane Roe", "attributes": {"Home address": "12 Example Street"}}
    )
    tom = add("entity", data={"type": "person", "value": "Tom Roe"})
    kid = add("entity", data={"type": "person", "value": "Lily Roe", "protected": True})
    handle = add("entity", data={"type": "username", "value": "janeroe80"})
    add(
        "link",
        data={"from": jane["id"], "to": tom["id"], "relation": "spouse", "confidence": "confirmed", "since": "2015-06"},
    )
    add("link", data={"from": jane["id"], "to": handle["id"], "relation": "uses"})
    add("link", data={"from": jane["id"], "to": kid["id"], "relation": "parent", "confidence": "confirmed"})
    add(
        "note",
        title="Call",
        body="Source says Jane Roe moved the money; janeroe80 posted about it. Lily Roe was there.",
    )
    add("event", title="Jane Roe resigned as treasurer", occurred_at="2023-02-01T00:00:00Z")
    client.post(
        f"/api/cases/{case['id']}/uploads", files={"file": ("m.txt", b"Minutes: JANE ROE chaired.", "text/plain")}
    )
    link_scan(client, case["id"], company_scan("inv_profile"))

    p = client.get(f"/api/cases/{case['id']}/entities/{jane['id']}/profile").json()
    assert p["name"] == "Jane Roe" and p["attributes"]["Home address"] == "12 Example Street"
    rel = {r["other"]: r for r in p["relationships"]}
    assert rel["Tom Roe"]["kind"] == "spouse" and rel["Protected person"]["kind"] == "parent"
    assert [i["other"] for i in p["identifiers"]] == ["janeroe80"]
    assert p["places"][0]["other"] == "12 Example Street"
    kinds = {m["kind"] for m in p["mentions"]}
    assert kinds == {"note", "event", "evidence"}
    note = next(m for m in p["mentions"] if m["kind"] == "note")
    assert "Lily" not in str(p) and "[protected person] was there" in note["passages"][0]  # the child is blanked
    dates = [t["date"] for t in p["timeline"]]
    assert dates == sorted(dates) and "2015-06" in dates and "2018-01-02" in dates and "2023-02-01" in dates
    scan = p["scans"][0]
    assert scan["facts"]["born"] == "1980-04" and scan["appointments"][0]["company"] == "Hope Relief Ltd"
    assert p["network"]["connections"] == 3 and p["network"]["key_person"] is True

    assert client.get(f"/api/cases/{case['id']}/entities/{kid['id']}/profile").json() == {
        "id": kid["id"], "type": "person", "name": "Protected person", "protected": True,
        "message": "This person is protected (for example, a child): Argus builds no profile of them."}  # fmt: skip
    assert client.get(f"/api/cases/{case['id']}/entities/nope/profile").status_code == 404
