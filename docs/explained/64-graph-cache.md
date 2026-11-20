# 64 — A graph cache, and graph loading off the event loop

## What was slow

Every view of a stored investigation rebuilt its graph from the database: the graph itself,
attack paths, the ATT&CK mapping, people, exports, reports, ratings, queries, link analysis and
hunts, 15 endpoints in all. Opening one investigation triggers several of them.

Measured on a 5,000-entity, 6,400-relation investigation (SQLite):

| | Before | After |
|---|---|---|
| Graph load, first time | 200–360 ms, blocking the server | the same, but in a worker thread |
| Graph load, again | 200–360 ms | **1–3 ms** |
| Longest event-loop stall while loading | the whole load | **≈ 26 ms** |

## How it works

`InvestigationRepository.load_graph(id, shared=True)`:

1. Reads the investigation's row (one primary-key lookup). If it's gone, any cached graph is
   dropped and the answer is "not found".
2. If the investigation has **finished** (completed, cancelled or failed) and the cache holds a
   graph with the same **version** (status, node count, edge count, completion time), it returns
   that graph.
3. Otherwise it rebuilds the graph: in a worker thread when there are more than 1,500 rows, so
   the server keeps answering other requests. A finished investigation's graph is then cached.

Finished scans don't change, and the version check catches anything that does (a demo reload,
another replica re-recording an investigation, a deletion), so the cache can't serve a stale graph.

## Read-only, enforced by tests

A cached graph is shared by every request that asks for it, so **callers must not modify it**:

- Only read-only paths pass `shared=True`: the workspace-checked loader behind the investigation
  endpoints, and hunts.
- Everything else (drift comparison, saved-query alerts, the live WebSocket view, the CLI) calls
  `load_graph(id)` and gets its own graph.
- `tests/test_graph_cache.py` loads the shared graph, calls **every** `GET` endpoint of an
  investigation plus queries and a hunt, and checks the graph is byte-for-byte unchanged and
  still the cached object.

## Settings and monitoring

| Setting | Default | |
|---|---|---|
| `ARGUS_GRAPH_CACHE_SIZE` | 16 | Graphs kept (least recently used dropped first); 0 turns it off |

`argus_graph_cache_total{result="hit"|"miss"}` shows how often the cache helps. The memory cost
is roughly the size of the graphs themselves. Lower the setting on small machines that open
very large investigations.

Link analysis is cached per graph object, so a cached graph also keeps its PageRank, clusters
and betweenness between requests.
