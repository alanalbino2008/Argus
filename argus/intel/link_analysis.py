"""Link analysis: who matters in an investigation graph, and how it falls into clusters.

Degree alone says how *connected* an entity is. Investigators also need to know:

* **PageRank** — influence: an entity pointed at by important entities is important
  (an IP that hosts the organisation's key domains outranks one hosting a stray subdomain).
* **Betweenness** — brokerage: how often an entity sits on the shortest route between
  others. High betweenness marks the pivot that ties two otherwise separate clusters
  together, such as one email shared by a company's domain and a person's accounts.
* **Communities** (Louvain) — the clusters themselves: one per infrastructure estate,
  persona or shell-company network.
* **Articulation points** — single points of failure: removing one disconnects the graph.

Everything is pure Python (no SciPy): betweenness is sampled on large graphs, and the
result is cached per graph version, so repeated queries cost nothing.
"""

from __future__ import annotations

import logging
import time
from collections import OrderedDict
from typing import Any

import networkx as nx

from argus.core.graph import IntelligenceGraph

logger = logging.getLogger("argus.link_analysis")

BETWEENNESS_EXACT_LIMIT = 600  # above this many nodes, betweenness is estimated from a sample
BETWEENNESS_SAMPLES = 256  # at most; fewer on big graphs, see BETWEENNESS_BUDGET
# Sampled betweenness costs about samples x (nodes + edges): the budget keeps it to a few seconds
# on the largest graphs (12 samples at 50,000 entities) instead of minutes.
BETWEENNESS_BUDGET = 1_500_000
BETWEENNESS_MIN_SAMPLES = 8
PAGERANK_DAMPING = 0.85
PAGERANK_TOLERANCE = 1e-8
PAGERANK_MAX_ITERATIONS = 200
CACHE_SIZE = 32

_cache: OrderedDict[tuple[str, int, int, int], dict[str, Any]] = OrderedDict()


def _version(graph: IntelligenceGraph) -> tuple[str, int, int, int]:
    # Graphs only grow during a scan, so node and edge counts identify a version; id() separates
    # two graph objects that happen to share an investigation id (a stored copy and a live one).
    return (graph.investigation_id, id(graph), graph.node_count, graph.edge_count)


def pagerank(g: nx.MultiDiGraph) -> dict[str, float]:
    """PageRank by power iteration over the collapsed directed graph (parallel edges count once)."""
    nodes = list(g.nodes)
    n = len(nodes)
    if n == 0:
        return {}
    successors = {u: set(g.successors(u)) - {u} for u in nodes}
    predecessors: dict[str, list[str]] = {u: [] for u in nodes}
    for u, outs in successors.items():
        for v in outs:
            predecessors[v].append(u)
    out_degree = {u: len(outs) for u, outs in successors.items()}
    rank = dict.fromkeys(nodes, 1.0 / n)
    teleport = (1.0 - PAGERANK_DAMPING) / n
    for _ in range(PAGERANK_MAX_ITERATIONS):
        dangling = PAGERANK_DAMPING * sum(rank[u] for u in nodes if out_degree[u] == 0) / n
        new = {
            v: teleport + dangling + PAGERANK_DAMPING * sum(rank[u] / out_degree[u] for u in predecessors[v])
            for v in nodes
        }
        delta = sum(abs(new[u] - rank[u]) for u in nodes)
        rank = new
        if delta < n * PAGERANK_TOLERANCE:
            break
    return rank


def analyze_links(graph: IntelligenceGraph) -> dict[str, Any]:
    """Per-entity scores and graph-level structure (cached per graph version)."""
    key = _version(graph)
    cached = _cache.get(key)
    if cached is not None:
        _cache.move_to_end(key)
        return cached

    started = time.perf_counter()
    g = graph._graph
    simple = nx.Graph(g.to_undirected(as_view=True))
    simple.remove_edges_from(nx.selfloop_edges(simple))
    n = simple.number_of_nodes()

    ranks = pagerank(g)
    sampled = n > BETWEENNESS_EXACT_LIMIT
    samples = (
        max(BETWEENNESS_MIN_SAMPLES, min(BETWEENNESS_SAMPLES, BETWEENNESS_BUDGET // (n + simple.number_of_edges())))
        if sampled
        else n
    )
    if n <= 2:
        between = dict.fromkeys(simple.nodes, 0.0)
    elif sampled:
        between = nx.betweenness_centrality(simple, k=min(samples, n), seed=7, normalized=True)
    else:
        between = nx.betweenness_centrality(simple, normalized=True)

    communities: list[set[str]] = (
        [set(c) for c in nx.community.louvain_communities(simple, seed=7)] if simple.number_of_edges() else []
    )
    communities.sort(key=len, reverse=True)
    community_of: dict[str, int] = {}
    for index, members in enumerate(communities):
        for node in members:
            community_of[node] = index
    next_id = len(communities)
    for node in simple.nodes:  # isolated entities form their own one-member communities
        if node not in community_of:
            community_of[node] = next_id
            next_id += 1

    articulation = set(nx.articulation_points(simple)) if n > 2 else set()
    degree = dict(g.degree())

    max_rank = max(ranks.values(), default=0.0) or 1.0
    max_between = max(between.values(), default=0.0) or 1.0
    max_degree = max(degree.values(), default=0) or 1
    scores: dict[str, dict[str, Any]] = {}
    for node in g.nodes:
        pr = ranks.get(node, 0.0)
        bc = between.get(node, 0.0)
        # One "key entity" score: influence, brokerage and connectivity, each scaled to this graph.
        key_score = 0.4 * pr / max_rank + 0.4 * bc / max_between + 0.2 * degree.get(node, 0) / max_degree
        scores[node] = {
            "pagerank": round(pr, 6),
            "betweenness": round(bc, 6),
            "degree": degree.get(node, 0),
            "community": community_of.get(node, -1),
            "articulation": node in articulation,
            "key_score": round(key_score, 4),
        }

    def describe(node_id: str) -> dict[str, Any]:
        entity = graph.get_entity(node_id)
        return {
            "id": node_id,
            "label": entity.label if entity else node_id,
            "type": entity.type.value if entity else "generic",
            **scores[node_id],
        }

    ranked = sorted(scores, key=lambda nid: scores[nid]["key_score"], reverse=True)
    community_summaries = []
    for index, members in enumerate(communities[:50]):
        types: dict[str, int] = {}
        for nid in members:
            entity = graph.get_entity(nid)
            if entity:
                types[entity.type.value] = types.get(entity.type.value, 0) + 1
        anchor = max(members, key=lambda nid: scores[nid]["key_score"])
        community_summaries.append(
            {
                "id": index,
                "size": len(members),
                "anchor": describe(anchor),
                "types": dict(sorted(types.items(), key=lambda kv: kv[1], reverse=True)),
            }
        )

    result = {
        "node_count": g.number_of_nodes(),
        "edge_count": g.number_of_edges(),
        "components": nx.number_connected_components(simple) if n else 0,
        "modularity": round(nx.community.modularity(simple, communities), 4) if communities else 0.0,
        "betweenness_sampled": sampled,
        "betweenness_samples": samples if sampled else None,
        "key_entities": [describe(nid) for nid in ranked[:15]],
        "brokers": [
            describe(nid) for nid in sorted(between, key=between.__getitem__, reverse=True)[:10] if between[nid] > 0
        ],
        "single_points_of_failure": [describe(nid) for nid in ranked if nid in articulation][:15],
        "communities": community_summaries,
        "scores": scores,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
    }
    _cache[key] = result
    if len(_cache) > CACHE_SIZE:
        _cache.popitem(last=False)
    return result


def summary(graph: IntelligenceGraph) -> dict[str, Any]:
    """Everything but the per-entity score table (for API responses)."""
    return {k: v for k, v in analyze_links(graph).items() if k != "scores"}
