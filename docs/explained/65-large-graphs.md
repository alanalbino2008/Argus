# 65 — Very large graphs stay fast

## The problem, measured

Real investigations explode in predictable ways: one domain with thousands of sub-domains, which
resolve to thousands of IPs, which expose thousands of ports. Until this phase the browser drew
every entity and ran a force-directed layout over all of them, which costs roughly n² per
iteration. On a 5,000-entity investigation **the tab froze for more than three minutes**; 20,000
and 50,000 never finished.

## Bundling (`argus/web/js/bundles.js`)

Above 1,500 entities the graph draws a *view* of the model rather than the model itself:

1. **Hub bundling.** A node with 40 or more neighbours of one type shows them as one bundle:
   "25,000 subdomains".
2. **Repeat on the bundled graph.** Those sub-domains' 8,000 IPs now share one neighbour, the
   bundle, so they bundle too, and then their ports. Four passes at most.
3. **Islands.** If more than 400 nodes would still be drawn, same-type *leaves* across the whole
   graph are bundled (an IP with two ports that nothing points to, times a few hundred), and hub
   bundling runs again.
4. **Edges** between bundles are merged into one edge, labelled with how many relations it stands for.

On the 50,000-entity benchmark this draws **37 elements**: the target, 30 shared technologies and
6 bundles.

### Nothing is hidden

- **Expand**: click a bundle to show its next 300 members, most connected first, laid out in a
  ring around it. **Regroup** folds expansions back. A bar shows "37 of 50,000 shown · 6 bundles".
- **Pinned entities are never bundled**: the target, the selected entity, every entity on a
  highlighted attack path, and query results (up to 300; beyond that, their bundles light up).
- **Search, details, neighbours, the legend and counts** all work on the full model. Searching for
  an entity inside a bundle reveals and selects it.
- **Live scans**: discoveries go into the model, and the view is recomputed at most every 1.5 s.

### Cost

The bundling pass works on integer indices and flat arrays (a compressed adjacency list), never
on string-keyed sets. The adjacency is cached per model version, so expanding or pinning only pays
for the pass itself: about 45 ms at 20,000 entities and 60–110 ms at 50,000.

## The server side

- The live view of a stored investigation loads the **shared graph cache** (Phase 64).
- Its **snapshot**, 28 MB of JSON at 50,000 entities, is serialised in a worker thread and **cached
  for finished investigations**: 4.7 s cold, 0.35 s warm.
- **Link analysis**: sampled betweenness cost about samples × (entities + relations) and took 88 s
  at 50,000 entities with 256 samples. Samples are now scaled to a fixed budget (12 at 50,000, 31 at
  20,000, never fewer than 8), so the whole analysis takes 10 s and is cached. It's requested only
  when the Intelligence tab opens, never on every investigation open. Results report
  `betweenness_samples`.

## Results

Chromium, the synthetic investigations from `tools/bench/` ("cold" right after a server start):

| Entities | Before | Cold open | Warm open | Longest freeze | Zoom/pan |
|---|---|---|---|---|---|
| 5,000 | frozen > 3 min | 1.1 s | 0.6 s | 0.3 s | 30 fps |
| 20,000 | frozen | 2.0 s | 0.5 s | 0.25 s | 59 fps |
| 50,000 | frozen | 6.4 s | 0.95 s | 0.45 s | 60 fps |

Reproduce with:

```bash
python tools/bench/make_large_investigations.py ./bench.db 5000 20000 50000
ARGUS_DATABASE_URL=sqlite+aiosqlite:///./bench.db ARGUS_BOOTSTRAP_ADMIN_KEY=<key> argus --serve --port 8811
ARGUS_BENCH_KEY=<key> node tools/bench/large_graph_benchmark.js inv_big5k inv_big20k inv_big50k
```

## Tests

- `tests/js/bundles.test.mjs` (Node's test runner, run from pytest when Node is installed):
  - small graphs unchanged;
  - recursive and island bundling;
  - every relation accounted for;
  - pinned entities;
  - paging most connected first;
  - stable bundle IDs;
  - 50,000 entities bundled in time.
- The browser walkthroughs used during development cover expanding, revealing a searched entity,
  highlighting bundled query results and regrouping.
