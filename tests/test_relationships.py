"""Human relationships in a case: kinds, the network's shape, paths, suggestions, protected people."""

from __future__ import annotations

from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType, Relation, RelationType
from argus.intel.relationships import analyse, discover, entity_nodes, link_edges, path, redact_protected
from tests.test_cases import new_case


def ent(i, value, etype="person", **extra):
    return {"id": i, "kind": "entity", "title": value, "body": "", "data": {"type": etype, "value": value, **extra}}


def link(i, a, b, relation="associate", confidence="likely", **extra):
    return {"id": i, "kind": "link", "title": "", "body": "", "data": {"from": a, "to": b, "relation": relation,
                                                                       "confidence": confidence, **extra}}  # fmt: skip


def note(i, title, body):
    return {"id": i, "kind": "note", "title": title, "body": body, "data": {}}


# ---------------------------------------------------------------------------- the network
def two_groups():
    items = [ent(x, name) for x, name in [("a", "Ann Able"), ("b", "Ben Bold"), ("c", "Cat Cole"), ("d", "Dan Dale"),
                                          ("e", "Eve East"), ("f", "Fay Fern"), ("g", "Gus Gale")]]  # fmt: skip
    items += [link("ab", "a", "b", "colleague", "confirmed"), link("bc", "b", "c"), link("ac", "a", "c"),
              link("cd", "c", "d", "business_partner", "likely"),
              link("de", "d", "e", "friend", "possible"), link("ef", "e", "f"), link("df", "d", "f")]  # fmt: skip
    return items


def test_the_network_shows_groups_bridges_and_loose_ends():
    items = two_groups()
    nodes = entity_nodes(items)
    result = analyse(nodes, link_edges(items, nodes))
    assert len(result["clusters"]) == 2
    assert {b["label"] for b in result["bridges"]} >= {"Cat Cole", "Dan Dale"}  # they join the two groups
    assert result["isolated"] == [{"id": "g", "label": "Gus Gale"}]
    assert nodes["c"]["cluster"] != nodes["e"]["cluster"] and nodes["c"]["degree"] == 3


def test_the_best_supported_path_between_two_people():
    items = two_groups()
    nodes = entity_nodes(items)
    edges = link_edges(items, nodes)
    route = path(nodes, edges, "a", "e")
    assert route["found"] and [s["to_label"] for s in route["steps"]] == ["Cat Cole", "Dan Dale", "Eve East"]
    assert route["strength"] == "possible"  # as strong as its weakest link
    assert route["steps"][1]["relationship"] == "business partner of"
    assert path(nodes, edges, "a", "g")["found"] is False
    assert [c["label"] for c in path(nodes, edges, "a", "c")["common"]] == ["Ben Bold"]


# ---------------------------------------------------------------------------- suggestions
def test_relationships_are_suggested_from_the_material():
    items = [
        ent("p1", "Ann Able", attributes={"Employer": "Acme Ltd", "Work email": "ann@acme.example"}),
        ent("p2", "Ben Bold", attributes={"works at": "ACME LTD"}),
        ent("p3", "Cat Cole", attributes={"email": "Ann@Acme.example"}),
        ent("p4", "Dan Dale"),
        ent("ph", "+44 20 7946 0000", "phone"),
        ent("co", "Acme Holdings Ltd", "organisation"),
        link("l1", "p1", "ph", "uses"),
        link("l2", "p4", "ph", "uses"),
        note("n1", "Interview", "Ben Bold said Dan Dale handled the money."),
    ]
    g = IntelligenceGraph("s")
    company = Entity.create(EntityType.ORGANIZATION, "Acme Holdings Ltd")
    ann = Entity.create(EntityType.PERSON, "ANN ABLE", depth=1)
    cat = Entity.create(EntityType.PERSON, "Cat Cole", depth=1)
    for e in (company, ann, cat):
        g.add_entity(e)
    g.add_relation(Relation.create(ann.id, company.id, RelationType.OFFICER_OF, label="director"))
    g.add_relation(Relation.create(cat.id, company.id, RelationType.OFFICER_OF, label="secretary (resigned)",
                                   metadata={"to": "2021-04-01"}))  # fmt: skip
    found = {(frozenset((s["from"], s["to"])), s["kind"]): s for s in discover(items, [g], [{"title": "Interview",
             "text": items[-1]["body"]}])}  # fmt: skip
    assert found[(frozenset(("p1", "p4")), "shares_phone")]["why"] == "Both are linked to +44 20 7946 0000"
    assert found[(frozenset(("p1", "p3")), "shares_email")]["confidence"] == "likely"
    colleague = found[(frozenset(("p1", "p2")), "colleague")]
    assert colleague["confidence"] == "possible" and colleague["why"] == "Both have Acme Ltd recorded as their employer"
    assert found[(frozenset(("p1", "co")), "director")]["confidence"] == "confirmed"
    co_dir = found[(frozenset(("p1", "p3")), "co_director")]
    assert co_dir["confidence"] == "likely" and "not at the same time" in co_dir["why"]  # one resigned
    assert found[(frozenset(("p2", "p4")), "mentioned_with")]["why"] == "Both named in “Interview”"
    assert (frozenset(("p1", "ph")), "uses") not in found  # already linked: not suggested again


# ---------------------------------------------------------------------------- protected people
def test_protected_people_are_never_named_or_profiled():
    items = [ent("kid", "Tommy Roe", protected=True, attributes={"school": "Hill Primary"}),
             ent("mum", "Jane Roe", attributes={"phone": "+44 7700 900123"}),
             ent("x", "Max Roe", attributes={"phone": "+44 7700 900123"}),
             link("l", "mum", "kid", "parent", "confirmed"),
             note("n", "Family", "Jane Roe collects Tommy Roe from school; Tommy roe likes football.")]  # fmt: skip
    nodes = entity_nodes(items)
    assert nodes["kid"]["label"] == "Protected person" and nodes["kid"]["attributes"] == {}
    found = discover(items, [], [{"title": "Family", "text": items[-1]["body"]}])
    assert all("kid" not in (s["from"], s["to"]) for s in found)
    assert any(s["kind"] == "shares_phone" for s in found)
    analysis = analyse(nodes, link_edges(items, nodes))
    assert all(p["id"] != "kid" for p in analysis["key_people"] + analysis["isolated"])
    clean, docs = redact_protected(items, [{"title": "Notes on Tommy Roe", "text": "TOMMY ROE was there"}])
    assert "Tommy" not in str(clean) and "Hill Primary" not in str(clean)
    assert docs[0]["title"] == "Notes on [protected person]" and docs[0]["text"] == "[protected person] was there"
    assert "Jane Roe collects [protected person]" in clean[-1]["body"]


# ---------------------------------------------------------------------------- the API
def test_the_network_api(client):
    case = new_case(client).json()
    add = lambda kind, **kw: client.post(f"/api/cases/{case['id']}/items", json={"kind": kind, **kw})  # noqa: E731
    jane = add("entity", data={"type": "person", "value": "Jane Roe"}).json()
    tom = add("entity", data={"type": "person", "value": "Tom Roe"}).json()
    kid = add("entity", data={"type": "person", "value": "Little Roe", "protected": True}).json()
    ok = add("link", data={"from": jane["id"], "to": tom["id"], "relation": "spouse", "confidence": "confirmed",
                           "since": "2015-06", "evidence": ["n1"], "label": "married"})  # fmt: skip
    assert ok.status_code == 201 and ok.json()["data"]["since"] == "2015-06"
    assert add("link", data={"from": jane["id"], "to": tom["id"], "relation": "nemesis"}).status_code == 422
    assert add("link", data={"from": jane["id"], "to": tom["id"], "since": "June 2015"}).status_code == 422
    add("link", data={"from": jane["id"], "to": kid["id"], "relation": "parent", "confidence": "confirmed"})
    net = client.get(f"/api/cases/{case['id']}/network").json()
    labels = {n["label"] for n in net["nodes"]}
    assert "Little Roe" not in labels and "Protected person" in labels
    spouse = next(e for e in net["edges"] if e["kind"] == "spouse")
    assert spouse["group"] == "family" and spouse["text"] == "married" and spouse["symmetric"] is True
    route = client.get(f"/api/cases/{case['id']}/network/path?source={tom['id']}&target={kid['id']}").json()
    assert route["hops"] == 2 and route["steps"][-1]["to_label"] == "Protected person"
    assert client.get(f"/api/cases/{case['id']}/network/path?source={tom['id']}&target=nope").status_code == 404
    sugg = client.get(f"/api/cases/{case['id']}/network/suggestions").json()
    assert sugg["suggestions"] == [] and sugg["documents_read"] == 0
    kinds = client.get("/api/relationship-kinds").json()
    assert "family" in kinds["groups"] and any(k["kind"] == "co_director" for k in kinds["kinds"])
