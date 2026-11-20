"""Phase 68: the team's tags and notes on entities, in every investigation, and in AQL."""

from __future__ import annotations

import pytest

from argus.api import server
from argus.core.models import EntityType, generate_entity_id
from argus.demo import DEMO_ID, DEMO_PREVIOUS_ID, build_demo
from argus.intel.query import run_query
from argus.storage.annotation_repo import MAX_TAGS, clean_tags
from tests.test_saved_queries import _alerts, _rescan

VPN = generate_entity_id(EntityType.SUBDOMAIN, "vpn.acme-corp.example")
RED = {"X-Argus-Workspace": "red-team"}


@pytest.fixture
def demo_client(make_client):
    client = make_client(monitors_enabled="false")
    client.post("/api/demo")
    return client


def _tag(client, entity_id=VPN, tags=("client-owned", "VPN"), note="Fortinet box", headers=None):
    body = {"entity_type": "subdomain", "value": "vpn.acme-corp.example", "tags": list(tags), "note": note}
    return client.put(f"/api/annotations/{entity_id}", json=body, headers=headers or {})


def test_tags_are_cleaned():
    assert clean_tags(["  c2 ", "C2", "phish<script>", "", "x" * 60]) == ["c2", "phishscript", "x" * 40]
    assert len(clean_tags([f"t{i}" for i in range(50)])) == MAX_TAGS


def test_annotate_list_count_and_remove(demo_client):
    c = demo_client
    saved = _tag(c).json()
    assert saved["tags"] == ["client-owned", "VPN"] and saved["note"] == "Fortinet box"
    assert saved["updated_by"] and saved["entity_type"] == "subdomain"
    assert [a["entity_id"] for a in c.get("/api/annotations").json()] == [VPN]
    assert c.get("/api/annotations/tags").json() == [{"tag": "client-owned", "count": 1}, {"tag": "VPN", "count": 1}]
    assert _tag(c, tags=["VPN"], note="").json()["tags"] == ["VPN"]  # replaced, not merged
    removed = _tag(c, tags=[], note="  ").json()
    assert removed == {"entity_id": VPN, "tags": [], "note": "", "removed": True}
    assert c.get("/api/annotations").json() == []
    assert "entity.annotate" in {e["action"] for e in c.get("/api/audit").json()}


def test_validation(demo_client):
    c = demo_client
    assert _tag(c, entity_id="not-an-id").status_code == 422
    assert _tag(c, entity_id=generate_entity_id(EntityType.EMAIL, "x@y.example")).status_code == 422  # wrong type
    too_many = {"entity_type": "subdomain", "value": "v", "tags": [f"t{i}" for i in range(MAX_TAGS + 1)]}
    assert c.put(f"/api/annotations/{VPN}", json=too_many).status_code == 422


def test_roles_and_teams(demo_client):
    c = demo_client
    viewer = c.post("/api/keys", json={"name": "reader", "role": "viewer"}).json()["key"]
    as_viewer = {"Authorization": f"Bearer {viewer}"}
    assert _tag(c, headers=as_viewer).status_code == 403
    _tag(c)
    assert len(c.get("/api/annotations", headers=as_viewer).json()) == 1  # viewers can read
    c.post("/api/workspaces", json={"name": "Red Team"})
    assert c.get("/api/annotations", headers=RED).json() == []  # another team never sees them
    assert _tag(c, tags=["theirs"], headers=RED).status_code == 200
    assert [a["tags"] for a in c.get("/api/annotations").json()] == [["client-owned", "VPN"]]  # ours unchanged


def test_tags_apply_in_every_investigation_and_in_hunts(demo_client):
    c = demo_client
    _tag(c, tags=["vpn"])
    for inv in (DEMO_ID, DEMO_PREVIOUS_ID):  # tagged once, found in both scans
        rows = c.post(f"/api/investigation/{inv}/query", json={"query": "tag:vpn"}).json()["rows"]
        assert [(r["label"], r["tags"]) for r in rows] == [("vpn.acme-corp.example", ["vpn"])]
    pattern = c.post(f"/api/investigation/{DEMO_ID}/query", json={"query": "tag:vpn -[RESOLVES_TO]-> ip"}).json()
    assert pattern["count"] == 1 and pattern["edge_ids"]
    hunt = c.post("/api/hunt", json={"query": 'tag:vpn note~"fortinet"'}).json()
    assert hunt["investigations_matched"] == 2


def test_an_alert_when_a_tagged_entity_turns_up_in_a_new_scan(demo_client):
    from argus.core.models import Entity, Relation, RelationType

    c = demo_client
    c.post(
        "/api/saved-queries",
        json={"name": "Known C2 seen again", "query": "tag:c2", "alert": True, "severity": "critical"},
    )
    # The team tagged a known C2 domain earlier (say, from another case): it is in no scan yet.
    evil = generate_entity_id(EntityType.DOMAIN, "evil-c2.example")
    c.put(f"/api/annotations/{evil}", json={"entity_type": "domain", "value": "evil-c2.example", "tags": ["c2"]})
    graph = c.portal.call(c.app.state.repo.load_graph, DEMO_ID)
    c.portal.call(server._evaluate_saved_queries, c.app, _rescan(c, graph))
    assert _alerts(c) == []  # the domain is not in this scan
    seed = next(e for e in graph.get_all_entities() if e.depth == 0)
    found = Entity.create(EntityType.DOMAIN, "evil-c2.example", depth=1)
    graph.add_entity(found)
    graph.add_relation(Relation.create(seed.id, found.id, RelationType.ASSOCIATED_WITH))
    c.portal.call(server._evaluate_saved_queries, c.app, _rescan(c, graph))
    (alert,) = _alerts(c)
    assert alert["severity"] == "critical"
    assert alert["summary"]["saved_query"]["new_matches"] == ["evil-c2.example"]


def test_without_an_annotation_tag_and_note_fall_back_to_metadata():
    _, graph = build_demo()
    entity = next(e for e in graph.get_all_entities() if e.value == "vpn.acme-corp.example")
    entity.metadata["note"] = "from a module"
    assert run_query(graph, 'note~"module"')["count"] == 1
    annotations = {entity.id: {"tags": ["x"], "note": "the team's"}}
    assert run_query(graph, 'note~"team"', annotations=annotations)["count"] == 1  # the team's note wins
    assert run_query(graph, 'note~"module"', annotations=annotations)["count"] == 0
