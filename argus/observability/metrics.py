"""Prometheus metrics - the single catalogue of everything Argus measures.

Every replica exposes its own ``/metrics``; Prometheus scrapes each pod and sums
across them. Label values are always *bounded* (route templates, module names,
entity types, outcomes) - never raw URLs, targets or user input - so the number of
time series cannot explode.

Naming follows Prometheus conventions: ``argus_`` prefix, base units (seconds),
``_total`` for counters.
"""

from __future__ import annotations

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    PlatformCollector,
    ProcessCollector,
    generate_latest,
)
from prometheus_client.exposition import CONTENT_TYPE_LATEST

from argus import __version__

REGISTRY = CollectorRegistry(auto_describe=True)
ProcessCollector(registry=REGISTRY)  # CPU, memory, open file descriptors
PlatformCollector(registry=REGISTRY)  # Python version

BUILD_INFO = Gauge(
    "argus_build_info", "Argus version running on this replica", ["version", "replica"], registry=REGISTRY
)

# ------------------------------------------------------------------ API
HTTP_REQUESTS = Counter(
    "argus_http_requests_total", "API requests handled", ["method", "route", "status"], registry=REGISTRY
)
HTTP_DURATION = Histogram(
    "argus_http_request_duration_seconds",
    "API request latency",
    ["method", "route"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
    registry=REGISTRY,
)
HTTP_IN_FLIGHT = Gauge("argus_http_requests_in_flight", "API requests being processed", registry=REGISTRY)
WS_CONNECTIONS = Gauge(
    "argus_websocket_connections", "Open live-view WebSockets (live = local scan, tail = scan on another replica)",
    ["mode"], registry=REGISTRY,
)  # fmt: skip
WS_SLOW_CLIENTS = Counter(
    "argus_websocket_slow_client_disconnects_total", "WebSockets closed because the browser fell too far behind",
    registry=REGISTRY,
)  # fmt: skip
AUTH_FAILURES = Counter(
    "argus_auth_failures_total", "Rejected API calls (missing/invalid key, insufficient role, bad ticket)",
    ["reason"], registry=REGISTRY,
)  # fmt: skip
SSO_LOGINS = Counter(
    "argus_sso_logins_total", "Single sign-on attempts by result (success or the refusal reason)", ["result"],
    registry=REGISTRY,
)  # fmt: skip
RATE_LIMITED = Counter("argus_rate_limited_total", "Requests refused by a limit", ["limit"], registry=REGISTRY)

# ------------------------------------------------------------------ scans
SCANS_STARTED = Counter("argus_scans_started_total", "Scans launched", ["trigger"], registry=REGISTRY)
SCANS_FINISHED = Counter(
    "argus_scans_finished_total", "Scans that ended, by final status", ["status"], registry=REGISTRY
)
SCANS_RUNNING = Gauge("argus_scans_running", "Scans running on this replica", registry=REGISTRY)
CLUSTER_SCANS_RUNNING = Gauge(
    "argus_cluster_scans_running", "Scans running anywhere in the cluster (live heartbeats)", registry=REGISTRY
)
SCAN_CAPACITY = Gauge("argus_scan_capacity", "Configured cluster-wide concurrent-scan limit", registry=REGISTRY)
SCAN_DURATION = Histogram(
    "argus_scan_duration_seconds",
    "Wall-clock time of finished scans",
    buckets=(5, 15, 30, 60, 120, 300, 600, 1200, 1800, 3600),
    registry=REGISTRY,
)
SCANS_INTERRUPTED = Counter(
    "argus_scans_interrupted_total", "Scans failed because their replica stopped or restarted", ["reason"],
    registry=REGISTRY,
)  # fmt: skip
ENTITIES_DISCOVERED = Counter(
    "argus_entities_discovered_total", "New findings added to investigation graphs", ["type"], registry=REGISTRY
)

# ------------------------------------------------------------------ modules & data sources
MODULE_RUNS = Counter(
    "argus_module_runs_total", "Collector runs by outcome (success, degraded, failed, timeout)", ["module", "outcome"],
    registry=REGISTRY,
)  # fmt: skip
MODULE_DURATION = Histogram(
    "argus_module_duration_seconds",
    "Time a collector spends on one entity",
    ["module"],
    buckets=(0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 40, 80),
    registry=REGISTRY,
)
CIRCUIT_BREAKER_TRIPS = Counter(
    "argus_module_circuit_breaker_trips_total", "Collectors disabled mid-scan after repeated failures", ["module"],
    registry=REGISTRY,
)  # fmt: skip
OUTBOUND_REQUESTS = Counter(
    "argus_outbound_requests_total",
    "Requests to OSINT sources (ok, http_error, network_error, retried, throttled, blocked)",
    ["outcome"],
    registry=REGISTRY,
)

# ------------------------------------------------------------------ storage, monitors, cluster
DATABASE_UP = Gauge("argus_database_up", "1 if the last database check succeeded", registry=REGISTRY)
CHECKPOINT_DURATION = Histogram(
    "argus_checkpoint_duration_seconds",
    "Time to persist a running scan's new findings",
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5),
    registry=REGISTRY,
)
CHECKPOINT_FAILURES = Counter(
    "argus_checkpoint_failures_total", "Failed checkpoints/heartbeats (retried automatically)", registry=REGISTRY
)
MONITOR_RUNS = Counter("argus_monitor_runs_total", "Scheduled re-scans started by this replica", registry=REGISTRY)
MONITOR_CLAIMS_LOST = Counter(
    "argus_monitor_claims_lost_total", "Due monitors another replica claimed first (expected in a cluster)",
    registry=REGISTRY,
)  # fmt: skip
ALERTS_RAISED = Counter(
    "argus_drift_alerts_total", "Attack-surface drift alerts raised", ["severity"], registry=REGISTRY
)
AUDIT_EVENTS = Counter("argus_audit_events_total", "Audit-log entries written", ["outcome"], registry=REGISTRY)

REPORTS_GENERATED = Counter("argus_reports_generated_total", "PDF reports issued", registry=REGISTRY)

# ------------------------------------------------------------------ outbound notifications
NOTIFICATIONS = Counter(
    "argus_notifications_total",
    "Notification delivery attempts by channel type and outcome (delivered, retry, failed, cancelled)",
    ["channel_type", "outcome"],
    registry=REGISTRY,
)
NOTIFICATION_LATENCY = Histogram(
    "argus_notification_delivery_seconds",
    "Time from the event to its successful delivery (includes retries)",
    ["channel_type"],
    buckets=(1, 5, 15, 60, 300, 900, 3600, 14400),
    registry=REGISTRY,
)
NOTIFICATIONS_PENDING = Gauge(
    "argus_notifications_pending", "Deliveries waiting to be sent, cluster-wide", registry=REGISTRY
)


def init(instance: str, scan_capacity: int = 0) -> None:
    BUILD_INFO.labels(version=__version__, replica=instance).set(1)
    SCAN_CAPACITY.set(scan_capacity)


def render() -> tuple[bytes, str]:
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST


def metric_names() -> set[str]:
    """Every exposed series name (counters include their ``_total``), for dashboard/alert consistency tests."""
    suffixes = {"counter": ("_total",), "histogram": ("_bucket", "_count", "_sum"), "summary": ("_count", "_sum")}
    names: set[str] = set()
    for family in REGISTRY.collect():  # include series that have not been observed yet
        names.add(family.name)
        names.update(family.name + suffix for suffix in suffixes.get(family.type, ()))
        names.update(sample.name for sample in family.samples)
    return names
