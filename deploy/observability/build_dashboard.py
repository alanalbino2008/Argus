"""Generate the Argus Grafana dashboard (deploy/helm/argus/files/argus-dashboard.json).

Written as code so panels stay consistent and every query is checked against the
metrics Argus really exports (tests/test_observability.py). Regenerate with:

    python deploy/observability/build_dashboard.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

OUT = Path(__file__).resolve().parents[1] / "helm" / "argus" / "files" / "argus-dashboard.json"
DS = {"type": "prometheus", "uid": "${datasource}"}
WIDTH = 24

_panels: list[dict[str, Any]] = []
_y = 0
_next_id = 1


def _id() -> int:
    global _next_id
    _next_id += 1
    return _next_id


def row(title: str) -> None:
    global _y
    _panels.append({"type": "row", "title": title, "id": _id(), "collapsed": False,
                    "gridPos": {"h": 1, "w": WIDTH, "x": 0, "y": _y}})  # fmt: skip
    _y += 1


def _targets(queries: list[tuple[str, str]]) -> list[dict[str, Any]]:
    return [
        {"datasource": DS, "expr": expr, "legendFormat": legend, "refId": chr(65 + i)}
        for i, (expr, legend) in enumerate(queries)
    ]


def stats(items: list[dict[str, Any]], h: int = 4) -> None:
    global _y
    w = WIDTH // len(items)
    for i, item in enumerate(items):
        _panels.append(
            {
                "type": "stat",
                "id": _id(),
                "title": item["title"],
                "description": item.get("description", ""),
                "datasource": DS,
                "gridPos": {"h": h, "w": w, "x": i * w, "y": _y},
                "targets": _targets([(item["expr"], "")]),
                "options": {"colorMode": "background", "graphMode": "area", "reduceOptions": {"calcs": ["lastNotNull"]}},
                "fieldConfig": {
                    "defaults": {
                        "unit": item.get("unit", "short"),
                        "decimals": item.get("decimals"),
                        "thresholds": {"mode": "absolute", "steps": item.get("thresholds", [{"color": "green", "value": None}])},
                    },
                    "overrides": [],
                },
            }
        )
    _y += h


def series(panels: list[dict[str, Any]], h: int = 8) -> None:
    global _y
    w = WIDTH // len(panels)
    for i, p in enumerate(panels):
        _panels.append(
            {
                "type": "timeseries",
                "id": _id(),
                "title": p["title"],
                "description": p.get("description", ""),
                "datasource": DS,
                "gridPos": {"h": h, "w": w, "x": i * w, "y": _y},
                "targets": _targets(p["queries"]),
                "options": {"legend": {"displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "multi"}},
                "fieldConfig": {
                    "defaults": {
                        "noValue": "None yet",  # nothing happened: not a broken panel
                        "unit": p.get("unit", "short"),
                        "custom": {"drawStyle": "line", "lineWidth": 2, "fillOpacity": p.get("fill", 12),
                                   "stacking": {"mode": "normal" if p.get("stack") else "none"}},
                    },
                    "overrides": [],
                },
            }
        )
    _y += h


RED = [{"color": "green", "value": None}, {"color": "red", "value": 1}]

# ------------------------------------------------------------------------------ overview
row("Overview")
stats([
    {"title": "Replicas up", "expr": "count(argus_build_info)",
     "thresholds": [{"color": "red", "value": None}, {"color": "orange", "value": 1}, {"color": "green", "value": 2}]},
    {"title": "Database", "expr": "min(argus_database_up)", "description": "1 = every replica reaches PostgreSQL",
     "thresholds": [{"color": "red", "value": None}, {"color": "green", "value": 1}]},
    {"title": "Scans running (cluster)", "expr": "max(argus_cluster_scans_running)"},
    {"title": "API requests / s", "expr": "sum(rate(argus_http_requests_total[5m]))", "unit": "reqps", "decimals": 2},
    {"title": "API errors (5xx)", "expr": '(sum(rate(argus_http_requests_total{status=~"5..",route!~"/api/health|/api/live|/metrics"}[5m])) or vector(0)) / clamp_min(sum(rate(argus_http_requests_total{route!~"/api/health|/api/live|/metrics"}[5m])), 1e-9)',
     "unit": "percentunit", "thresholds": [{"color": "green", "value": None}, {"color": "orange", "value": 0.01}, {"color": "red", "value": 0.05}]},
    {"title": "API p95 latency", "expr": 'histogram_quantile(0.95, sum by (le) (rate(argus_http_request_duration_seconds_bucket{route!~"/ws/.*|/metrics"}[5m])))',
     "unit": "s", "thresholds": [{"color": "green", "value": None}, {"color": "orange", "value": 0.5}, {"color": "red", "value": 1}]},
])  # fmt: skip

# ------------------------------------------------------------------------------ API
row("API")
series([
    {"title": "Requests by status", "stack": True, "unit": "reqps",
     "queries": [("sum by (status) (rate(argus_http_requests_total[5m]))", "{{status}}")]},
    {"title": "Latency", "unit": "s", "fill": 0, "queries": [
        (f'histogram_quantile({q}, sum by (le) (rate(argus_http_request_duration_seconds_bucket{{route!~"/ws/.*|/metrics"}}[5m])))', f"p{int(q * 100)}")
        for q in (0.5, 0.95, 0.99)]},
    {"title": "Busiest routes", "unit": "reqps",
     "queries": [('topk(8, sum by (route) (rate(argus_http_requests_total{route!~"/api/health|/api/live|/metrics"}[5m])))', "{{route}}")]},
])  # fmt: skip

# ------------------------------------------------------------------------------ scans
row("Scans")
series([
    {"title": "Scans finished by status (per hour)", "stack": True,
     "queries": [("sum by (status) (increase(argus_scans_finished_total[1h]))", "{{status}}")]},
    {"title": "Scan duration", "unit": "s", "fill": 0,
     "queries": [(f"histogram_quantile({q}, sum by (le) (rate(argus_scan_duration_seconds_bucket[30m])))", f"p{int(q * 100)}") for q in (0.5, 0.95)]},
    {"title": "Findings per minute by type", "stack": True,
     "queries": [("sum by (type) (rate(argus_entities_discovered_total[5m])) * 60", "{{type}}")]},
])  # fmt: skip
series([
    {"title": "Running scans per replica",
     "queries": [("sum by (instance) (argus_scans_running)", "{{instance}}"), ("max(argus_scan_capacity)", "cluster limit")]},
    {"title": "Scans started (per hour)", "stack": True,
     "queries": [("sum by (trigger) (increase(argus_scans_started_total[1h]))", "{{trigger}}")]},
    {"title": "Scans lost to unresponsive replicas", "stack": True,
     "queries": [("sum by (reason) (increase(argus_scans_interrupted_total[1h]))", "{{reason}}")]},
])  # fmt: skip

# ------------------------------------------------------------------------------ collectors
row("Collectors & OSINT sources")
series([
    {"title": "Module runs by outcome", "stack": True, "unit": "ops",
     "queries": [("sum by (outcome) (rate(argus_module_runs_total[5m]))", "{{outcome}}")]},
    {"title": "Slowest modules (p95)", "unit": "s", "fill": 0,
     "queries": [("topk(8, histogram_quantile(0.95, sum by (le, module) (rate(argus_module_duration_seconds_bucket[15m]))))", "{{module}}")]},
    {"title": "Failing modules", "stack": True, "unit": "ops",
     "queries": [('topk(8, sum by (module) (rate(argus_module_runs_total{outcome=~"failed|timeout"}[15m])))', "{{module}}")]},
])  # fmt: skip
series([
    {"title": "Outbound requests by outcome", "stack": True, "unit": "reqps",
     "queries": [("sum by (outcome) (rate(argus_outbound_requests_total[5m]))", "{{outcome}}")]},
    {"title": "Circuit breaker trips (per hour)", "stack": True,
     "queries": [("sum by (module) (increase(argus_module_circuit_breaker_trips_total[1h]))", "{{module}}")]},
    {"title": "Blocked egress (SSRF guard)", "description": "Requests refused because they targeted private or metadata addresses",
     "queries": [('sum(increase(argus_outbound_requests_total{outcome="blocked"}[15m])) or vector(0)', "blocked")]},
])  # fmt: skip

# ------------------------------------------------------------------------------ notifications
row("Notifications")
series([
    {"title": "Deliveries by outcome (per hour)", "stack": True,
     "description": "delivered, retry (will be tried again), failed (gave up), cancelled (channel paused)",
     "queries": [("sum by (outcome) (increase(argus_notifications_total[1h]))", "{{outcome}}")]},
    {"title": "Waiting to be sent", "description": "Cluster-wide outbox backlog; grows while a destination is down",
     "queries": [("max(argus_notifications_pending)", "pending")]},
    {"title": "Time to deliver (p95)", "unit": "s", "fill": 0,
     "description": "From the event to a successful delivery, retries included",
     "queries": [("histogram_quantile(0.95, sum by (le, channel_type) (rate(argus_notification_delivery_seconds_bucket[1h])))",
                  "{{channel_type}}")]},
])  # fmt: skip

# ------------------------------------------------------------------------------ brand protection & watches
row("Brand protection & watches")
series([
    {"title": "Watch runs by outcome (per hour)", "stack": True,
     "description": "Brand (Certificate Transparency) and fingerprint (Shodan/Censys) watch runs: ok, partial (one source failed), error",
     "queries": [("sum by (kind, status) (increase(argus_watch_runs_total[1h]))", "{{kind}} {{status}}")]},
    {"title": "Hours since a watch last succeeded", "unit": "h", "fill": 0,
     "description": "Over 48 h raises ArgusWatchesStalled",
     "queries": [("(time() - max by (kind) (argus_watch_last_success_timestamp_seconds)) / 3600", "{{kind}}")]},
    {"title": "Watch run time (p95)", "unit": "s", "fill": 0,
     "queries": [("histogram_quantile(0.95, sum by (le, kind) (rate(argus_watch_run_duration_seconds_bucket[1h])))", "{{kind}}")]},
])  # fmt: skip
series([
    {"title": "Source failures (per hour)", "stack": True,
     "queries": [("sum by (source) (increase(argus_watch_source_errors_total[1h]))", "{{source}}")]},
    {"title": "New lookalike domains (per day)", "stack": True,
     "queries": [("sum by (severity) (increase(argus_lookalikes_found_total[1d]))", "{{severity}}")]},
    {"title": "Takedowns (per day)", "stack": True,
     "description": "drafted, reported to registrar or host, seen down, closed",
     "queries": [("sum by (event) (increase(argus_takedown_events_total[1d]))", "{{event}}")]},
])  # fmt: skip

# ------------------------------------------------------------------------------ platform & security
row("Platform & security")
series([
    {"title": "Live WebSockets", "stack": True, "queries": [("sum by (mode) (argus_websocket_connections)", "{{mode}}")]},
    {"title": "Checkpoint latency (p95)", "unit": "s", "fill": 0,
     "queries": [("histogram_quantile(0.95, sum by (le) (rate(argus_checkpoint_duration_seconds_bucket[5m])))", "p95"),
                 ("sum(increase(argus_checkpoint_failures_total[5m]))", "failures (5m)")]},
    {"title": "Monitoring", "queries": [("sum(increase(argus_monitor_runs_total[1h]))", "re-scans / h"),
                                        ("sum by (severity) (increase(argus_drift_alerts_total[1h]))", "alerts: {{severity}}")]},
])  # fmt: skip
series([
    {"title": "Rejected credentials", "stack": True,
     "queries": [("sum by (reason) (rate(argus_auth_failures_total[5m])) * 60", "{{reason}} / min")]},
    {"title": "Refused by limits", "stack": True,
     "queries": [("sum by (limit) (increase(argus_rate_limited_total[15m]))", "{{limit}}")]},
    {"title": "Memory per replica", "unit": "bytes", "fill": 0,
     "queries": [("process_resident_memory_bytes", "{{instance}}")]},
    {"title": "CPU per replica", "unit": "percentunit", "fill": 0,
     "queries": [("rate(process_cpu_seconds_total[5m])", "{{instance}}")]},
])  # fmt: skip

DASHBOARD = {
    "uid": "argus-overview",
    "title": "Argus OSINT",
    "description": "Service health, scans, collectors, OSINT sources and security signals for Argus",
    "tags": ["argus", "osint"],
    "timezone": "browser",
    "schemaVersion": 39,
    "version": 1,
    "refresh": "30s",
    "time": {"from": "now-6h", "to": "now"},
    "editable": True,
    "templating": {
        "list": [
            {"name": "datasource", "label": "Data source", "type": "datasource", "query": "prometheus",
             "current": {}, "hide": 0, "refresh": 1}
        ]
    },
    "annotations": {"list": []},
    "links": [],
    "panels": _panels,
}


def build() -> str:
    return json.dumps(DASHBOARD, indent=2, sort_keys=True) + "\n"


if __name__ == "__main__":
    OUT.write_text(build(), encoding="utf-8")
    print(f"wrote {OUT} ({len(_panels)} panels)")
