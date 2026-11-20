"""Phase 59: the Argus Query Language and link analysis."""

import json

import pytest

from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType, Relation, RelationType
from argus.demo import DEMO_ID, build_demo
from argus.intel.link_analysis import analyze_links, pagerank, summary
from argus.intel.query import MAX_TERMS, QueryError, run_query, tokenize


@pytest.fixture(scope="module")
def demo():
    return build_demo()[1]


def _small_graph() -> IntelligenceGraph:
    """example.com -> a, b (two subdomains) -> one IP; plus an email and an isolated wallet."""
    g = IntelligenceGraph("inv_small")
    root = Entity.create(EntityType.DOMAIN, "example.com", source_module="seed", depth=0)
    a = Entity.create(
        EntityType.SUBDOMAIN, "vpn.example.com", metadata={"http_status": 200, "tags": ["remote"]}, depth=1
    )
    b = Entity.create(EntityType.SUBDOMAIN, "www.example.com", metadata={"http_status": 404}, depth=1, confidence=0.6)
    ip = Entity.create(EntityType.IP_ADDRESS, "198.51.100.7", metadata={"geo": {"country": "NL"}}, depth=2)
    mail = Entity.create(EntityType.EMAIL, "ops@example.com", depth=1)
    wallet = Entity.create(EntityType.CRYPTO_WALLET, "bc1qexample", depth=1)
    g.add_entity(root, is_seed=True)
    for e in (a, b, ip, mail, wallet):
        g.add_entity(e)
    g.add_relation(Relation.create(a.id, root.id, RelationType.SUBDOMAIN_OF))
    g.add_relation(Relation.create(b.id, root.id, RelationType.SUBDOMAIN_OF))
    g.add_relation(Relation.create(a.id, ip.id, RelationType.RESOLVES_TO))
    g.add_relation(Relation.create(b.id, ip.id, RelationType.RESOLVES_TO))
    g.add_relation(Relation.create(mail.id, root.id, RelationType.ASSOCIATED_WITH))
    return g


def labels(result):
    return sorted(r["label"] for r in result["rows"])


# ----------------------------------------------------------------------------- filters
@pytest.mark.parametrize(
    "query, expected",
    [
        ("type:subdomain", ["vpn.example.com", "www.example.com"]),
        ("sub", ["vpn.example.com", "www.example.com"]),  # bare type alias
        ("type:subdomain http_status:200", ["vpn.example.com"]),
        ("type:subdomain AND NOT http_status:200", ["www.example.com"]),
        ("type:subdomain -http_status:200", ["www.example.com"]),
        ("type:email OR type:crypto_wallet", ["bc1qexample", "ops@example.com"]),
        ('value~"^vpn"', ["vpn.example.com"]),
        ("label:*.example.com", ["vpn.example.com", "www.example.com"]),
        ("tags:remote", ["vpn.example.com"]),  # any element of a list
        ("geo.country:nl", ["198.51.100.7"]),  # dotted path, case-insensitive
        ("geo:*", ["198.51.100.7"]),
        ("confidence<0.9", ["www.example.com"]),
        ("http_status>=300", ["www.example.com"]),
        ("degree>=3", ["example.com"]),
        ("seed:true", ["example.com"]),
        ('"ops@"', ["ops@example.com"]),
    ],
)
def test_filters(query, expected):
    assert labels(run_query(_small_graph(), query)) == expected


def test_pattern_keeps_only_complete_chains():
    g = _small_graph()
    result = run_query(g, "type:subdomain http_status:200 -[RESOLVES_TO]-> ip")
    assert labels(result) == ["198.51.100.7"]
    assert len(result["edge_ids"]) == 1  # only the edge from vpn, not from www
    assert len(result["node_ids"]) == 2
    assert result["paths"] == [{"nodes": result["paths"][0]["nodes"], "edges": result["edge_ids"]}]


def test_pattern_directions():
    g = _small_graph()
    assert labels(run_query(g, "ip <-[RESOLVES_TO]- *")) == ["vpn.example.com", "www.example.com"]
    assert labels(run_query(g, "ip -[RESOLVES_TO]-> *")) == []  # wrong way round
    assert labels(run_query(g, "ip -[RESOLVES_TO]- *")) == ["vpn.example.com", "www.example.com"]
    assert labels(run_query(g, "type:email -> domain <- sub -> ip")) == ["198.51.100.7"]
    assert labels(run_query(g, "domain -- *")) == ["ops@example.com", "vpn.example.com", "www.example.com"]
    assert labels(run_query(g, "sub -[RESOLVES_TO|SUBDOMAIN_OF]-> *")) == ["198.51.100.7", "example.com"]


def test_shortest_paths():
    result = run_query(_small_graph(), "path from type:email to ip")
    assert result["kind"] == "paths"
    assert [p["hops"] for p in result["paths"]] == [3]  # email -> domain -> subdomain -> ip
    assert run_query(_small_graph(), "path from type:email to ip max 2")["paths"] == []
    assert run_query(_small_graph(), "path from type:email to type:crypto_wallet")["paths"] == []  # not connected


def test_commands():
    g = _small_graph()
    assert run_query(g, "* | count")["kind"] == "count"
    assert run_query(g, "* | count")["count"] == 6
    groups = run_query(g, "* | group type")["groups"]
    assert groups[0] == {"key": "subdomain", "count": 2}
    rows = run_query(g, "* | sort degree desc | limit 2")["rows"]
    assert [r["label"] for r in rows] == ["example.com", "198.51.100.7"]  # ties keep label order
    asc = run_query(g, "type:subdomain | sort confidence asc")["rows"]
    assert [r["label"] for r in asc] == ["www.example.com", "vpn.example.com"]
    ranked = run_query(g, "* | sort key_score | limit 1")["rows"][0]
    assert ranked["key_score"] == 1.0  # analytics columns appear when analytics are used


@pytest.mark.parametrize(
    "query, fragment",
    [
        ("", "empty"),
        ("type:dom", "unknown entity type"),
        ("x -[NOPE]-> y", "unknown relation"),
        ("path from x", "needs 'to'"),
        ("x | limit 0", "positive number"),
        ("x | frobnicate", "unknown command"),
        ("x | sort", "needs a field"),
        ('value~"(a+)+"', "nested repetition"),
        ('value~"["', "invalid regular expression"),
        ("(type:domain", "expected ')'"),
        ("confidence>high", "needs a number"),
        ("path from x to y max 99", "max hops"),
        ("x" + " -> x" * 9, "at most"),
    ],
)
def test_errors_are_explained(query, fragment):
    with pytest.raises(QueryError) as info:
        run_query(_small_graph(), query)
    assert fragment in str(info.value)


def test_limits():
    with pytest.raises(QueryError, match="at most"):
        run_query(_small_graph(), " ".join(["x"] * (MAX_TERMS + 1)))
    with pytest.raises(QueryError, match="limited"):
        run_query(_small_graph(), "x" * 3000)


def test_tokenizer_keeps_hyphenated_values_and_arrows_apart():
    kinds = [(t.kind, t.text) for t in tokenize("my-host.example->ip -tag")]
    assert kinds[:3] == [("WORD", "my-host.example"), ("ARROW_OUT", "->"), ("WORD", "ip")]
    assert kinds[3:5] == [("WORD", "NOT"), ("WORD", "tag")]


def test_demo_queries(demo):
    kev = run_query(demo, "type:vulnerability intel.kev:*")
    assert {r["label"] for r in kev["rows"]} == {"CVE-2023-27997", "CVE-2024-21762"}
    routes = run_query(demo, "path from type:email to type:ip_address")
    assert routes["paths"] and all(p["nodes"][-1] in routes["node_ids"] for p in routes["paths"])


# ----------------------------------------------------------------------------- link analysis
def test_pagerank_is_a_distribution():
    g = _small_graph()
    ranks = pagerank(g._graph)
    assert sum(ranks.values()) == pytest.approx(1.0)
    ip = next(e.id for e in g.get_all_entities() if e.type == EntityType.IP_ADDRESS)
    wallet = next(e.id for e in g.get_all_entities() if e.type == EntityType.CRYPTO_WALLET)
    assert ranks[ip] > ranks[wallet]  # pointed at twice vs. not at all


def test_link_analysis_structure(demo):
    data = analyze_links(demo)
    assert data["components"] == 1
    assert data["key_entities"][0]["label"] == "acme-corp.example"
    assert data["communities"] and data["communities"][0]["size"] >= data["communities"][-1]["size"]
    assert all(e["articulation"] for e in data["single_points_of_failure"])
    assert analyze_links(demo) is data  # cached per graph version
    assert "scores" not in summary(demo)


def test_isolated_entities_get_their_own_cluster():
    data = analyze_links(_small_graph())
    scores = data["scores"]
    wallet = next(nid for nid in scores if nid.startswith("crypto_wallet_"))
    others = {s["community"] for nid, s in scores.items() if nid != wallet}
    assert scores[wallet]["community"] not in others
    assert data["components"] == 2


def test_graph_round_trips_through_json(demo):
    copy = IntelligenceGraph.from_dict(json.loads(json.dumps(demo.to_dict(), default=str)))
    assert (copy.node_count, copy.edge_count) == (demo.node_count, demo.edge_count)
    assert run_query(copy, "seed:true")["count"] == 1


# ----------------------------------------------------------------------------- API
def test_query_api(client):
    client.post("/api/demo")
    ok = client.post(f"/api/investigation/{DEMO_ID}/query", json={"query": "type:domain -[RESOLVES_TO]-> ip"})
    assert ok.status_code == 200
    body = ok.json()
    assert body["count"] >= 1 and body["edge_ids"] and body["kind"] == "nodes"
    bad = client.post(f"/api/investigation/{DEMO_ID}/query", json={"query": "type:dom"})
    assert bad.status_code == 400
    assert bad.json()["detail"]["position"] == 5
    assert client.post("/api/investigation/inv_missing/query", json={"query": "*"}).status_code == 404
    assert client.post(f"/api/investigation/{DEMO_ID}/query", json={"query": ""}).status_code == 422
    help_ = client.get("/api/query/help").json()
    assert help_["examples"] and help_["syntax"]
    for example in help_["examples"]:  # every documented example runs
        assert client.post(f"/api/investigation/{DEMO_ID}/query", json={"query": example["query"]}).status_code == 200


def test_links_api(client):
    client.post("/api/demo")
    data = client.get(f"/api/investigation/{DEMO_ID}/links").json()
    assert data["key_entities"] and data["communities"]
    assert len(data["community_of"]) == data["node_count"]
    assert "scores" not in data


def test_query_cli(tmp_path, capsys, demo):
    import asyncio

    from argus.cli.console import query_cli

    path = tmp_path / "graph.json"
    path.write_text(json.dumps(demo.to_dict(), default=str), encoding="utf-8")
    assert asyncio.run(query_cli("* | count", str(path), as_json=True)) == 0
    assert json.loads(capsys.readouterr().out)["count"] == demo.node_count
    assert asyncio.run(query_cli("type:dom", str(path), as_json=False)) == 1


def test_snapshot_is_independent_of_the_live_graph():
    live = _small_graph()
    copy = live.snapshot()
    extra = Entity.create(EntityType.DOMAIN, "later.example", depth=1)
    live.add_entity(extra)
    root = next(e for e in live.get_all_entities() if e.value == "example.com")
    live.add_entity(Entity.create(EntityType.DOMAIN, "example.com", metadata={"new": 1}, source_module="other"))
    assert copy.node_count == live.node_count - 1
    assert "new" in root.metadata
    assert "new" not in copy.get_entity(root.id).metadata
    assert run_query(copy, "seed:true")["count"] == 1


def test_queries_on_a_running_scan_use_a_snapshot(client, monkeypatch):
    from argus.api import server

    class FakeEngine:
        def __init__(self, graph):
            self.graph = graph
            self.investigation = type("I", (), {"workspace_id": "ws_default"})()

        def cancel(self):  # the server cancels running scans when it shuts down
            pass

    live = _small_graph()
    seen = []
    monkeypatch.setitem(server.INVESTIGATIONS, "inv_live", FakeEngine(live))
    real = server.run_query
    monkeypatch.setattr(server, "run_query", lambda g, q, **kw: seen.append(g) or real(g, q, **kw))
    resp = client.post("/api/investigation/inv_live/query", json={"query": "* | count"})
    assert resp.status_code == 200 and resp.json()["count"] == 6
    assert seen and seen[0] is not live
