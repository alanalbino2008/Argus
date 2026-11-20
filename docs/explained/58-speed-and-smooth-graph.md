# 58 — Speed and a smoother live graph

## The problem

A busy scan finds hundreds of entities a second. Before this phase, each discovery reached the
browser as its own WebSocket message, and each message:

1. added one node to the graph (one Cytoscape redraw),
2. refreshed every panel listening for graph changes, and
3. added one line to the activity feed.

On top of that, every module run sent a *started* and a *finished* message that no view used.
On a large scan the stream was mostly that chatter. Big JSON responses (graphs, exports) were
also sent uncompressed.

## What changed

### Discoveries are applied once per frame
`live.js` now buffers incoming messages and applies them on the next animation frame (or after
250 ms in a background tab, where browsers pause animation frames):

- consecutive discoveries are added inside one `cy.batch()`: one redraw, however many nodes;
- panels are told about graph changes once per frame;
- more than four discoveries in a frame become one summary feed line;
- only the newest `scan_progress` in a frame is used;
- order is preserved: a `scan_completed` after discoveries is handled after they are drawn.

### Module chatter stays on the server
`MODULE_STARTED` and `MODULE_FINISHED` still go on the event bus (Prometheus metrics, plugins),
but `ws_dispatcher` never forwards them to browsers (`WS_SILENT_EVENTS`).

### Gzip
`GZipMiddleware` compresses responses over 1 KB at level 5, a good balance of speed and size.
It sits *inside* the security-headers and observability middleware, so they see the final
response. Turn it off with `ARGUS_COMPRESS_RESPONSES=false` if a reverse proxy already compresses.

**Why this is safe from BREACH-style attacks:** those need a victim's browser to send
*credentialed* cross-site requests, which works only with cookie authentication. Argus
authenticates with a header (`Authorization: Bearer`), which a cross-site page cannot attach.

## Measured

| | Before | After |
|---|---|---|
| Demo graph over the wire | 36.8 KB | 6.9 KB (5.3×) |
| Redraws per frame on a busy scan | one per discovery | one |
| Messages per module run | 2 + findings | findings only |

Tests: `tests/test_performance.py`.
