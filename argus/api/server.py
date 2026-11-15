"""FastAPI backend: REST API, persistent investigation history and live WebSocket telemetry.

State model
-----------
* The **database** is the source of truth for every investigation, past or present.
* **Running** scans also live in ``INVESTIGATIONS`` (in memory) so their graphs can
  be served live; they are dropped once their final state is persisted.
* Each WebSocket client gets its **own bounded send queue** drained by a dedicated
  task, so a slow browser can never slow the engine down. A client that falls too
  far behind is disconnected rather than allowed to exhaust memory.
* On connect, a client receives a **snapshot** of everything found so far, then live
  events - so opening the page mid-scan (or after a restart) loses nothing.

Running as several replicas (Kubernetes) behind a load balancer
----------------------------------------------------------------
Replicas coordinate through the shared database - no sticky sessions, no extra broker:

* each scan records its **owner** replica, which refreshes a **heartbeat**; a replica that
  crashes is detected by the others (its scans are marked failed), instead of every
  restart failing every running scan;
* **cancel** works from any replica: it sets a flag the owner sees on its next heartbeat;
* a WebSocket opened on a replica that is *not* running the scan **tails the database**,
  streaming new findings as the owner checkpoints them (about once a second);
* WebSocket **tickets**, the scheduler's monitor **claims** and the **audit chain** are all
  database-backed and safe under concurrency; migrations take an advisory lock.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any, Literal

import anyio
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import text

from argus import __version__
from argus.api.auth_routes import router as auth_router
from argus.api.deps import WorkspaceContext, audit, in_workspace, public_base_url, require_platform_admin
from argus.api.monitor_routes import router as monitor_router
from argus.api.notification_routes import router as notification_router
from argus.api.onboarding_routes import router as onboarding_router
from argus.api.onboarding_routes import scope_warnings
from argus.api.rating_routes import benchmark, ensure_history, rate
from argus.api.rating_routes import router as rating_router
from argus.api.report_routes import router as report_router
from argus.api.scheduler import SCHEDULER, MonitorScheduler
from argus.api.security_routes import router as security_router
from argus.api.workspace_routes import router as workspace_router
from argus.core.engine import ArgusEngine
from argus.core.events import Event, event_bus
from argus.core.graph import IntelligenceGraph
from argus.core.models import EntityType, Investigation, InvestigationStatus, ScanConfig
from argus.core.settings import Settings, get_settings
from argus.demo import load_demo
from argus.intel.attack import map_investigation, to_navigator_layer
from argus.intel.diff import compare, headline
from argus.intel.identity import resolve_people
from argus.intel.paths import find_attack_paths
from argus.intel.stix import build_bundle
from argus.modules import get_default_modules, get_module_catalog, plugin_report
from argus.modules.analytics.graph_analyzer import GraphIntelligenceAnalyzer
from argus.notify.dispatcher import NotificationDispatcher
from argus.observability import logs, metrics
from argus.observability.middleware import ObservabilityMiddleware
from argus.reports.data import ReportOptions
from argus.reports.scheduler import ReportScheduler
from argus.reports.service import issue_report
from argus.security.auth import SYSTEM, Principal, Role
from argus.security.crypto import secret_box_from_settings
from argus.security.headers import SecurityHeadersMiddleware
from argus.security.network import validate_scan_target
from argus.security.oidc import OidcProvider
from argus.security.ratelimit import SlidingWindowLimiter
from argus.storage import Database, InvestigationRecorder, InvestigationRepository
from argus.storage.migrate import upgrade_database
from argus.storage.monitor_repo import MonitorRepository
from argus.storage.notification_repo import NotificationRepository
from argus.storage.rating_repo import RatingRepository
from argus.storage.report_repo import ReportRepository
from argus.storage.repository import ACTIVE_STATUSES
from argus.storage.schedule_repo import ScheduleRepository
from argus.storage.security_repo import ApiKeyRepository, AuditLog, TicketStore
from argus.storage.user_repo import UserRepository
from argus.storage.workspace_repo import WorkspaceRepository

logger = logging.getLogger("argus.api")

BASE_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = BASE_DIR / "web"

# Live (running) scans only. Finished investigations are read from the database.
INVESTIGATIONS: dict[str, ArgusEngine] = {}
SCAN_TASKS: dict[str, asyncio.Task[None]] = {}


# --------------------------------------------------------------------------- WebSockets
class ClientConnection:
    """One WebSocket client with its own bounded outbound queue."""

    def __init__(self, ws: WebSocket, maxsize: int):
        self.ws = ws
        self.queue: asyncio.Queue[str] = asyncio.Queue(maxsize=maxsize)
        self.dead = asyncio.Event()

    def offer(self, message: str) -> None:
        if self.dead.is_set():
            return
        try:
            self.queue.put_nowait(message)
        except asyncio.QueueFull:
            logger.warning("WebSocket client too slow; disconnecting")
            self.dead.set()

    async def pump(self) -> None:
        try:
            while True:
                await self.ws.send_text(await self.queue.get())
        finally:
            self.dead.set()


CONNECTIONS: dict[str, set[ClientConnection]] = {}


async def ws_dispatcher(event: Event) -> None:
    """Fan an engine event out to every client watching that investigation (non-blocking)."""
    conns = CONNECTIONS.get(event.investigation_id)
    if not conns:
        return
    payload = json.dumps(event.model_dump(mode="json"))
    for conn in list(conns):
        conn.offer(payload)


# --------------------------------------------------------------------------- lifecycle
@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logs.configure(settings.log_format, settings.log_level, settings.instance_id)
    metrics.init(settings.instance_id, settings.max_concurrent_scans)
    db = Database(settings.database_url, echo=settings.db_echo)
    if settings.auto_migrate:
        await upgrade_database(db)
    repo = InvestigationRepository(db)
    # Scans this instance was running before it restarted, legacy rows without an owner, and
    # scans whose owner stopped sending heartbeats can never finish. Other replicas' live
    # scans are left alone.
    interrupted = await repo.mark_interrupted(owned_by=settings.instance_id, stale_seconds=settings.scan_stale_seconds)
    if interrupted:
        metrics.SCANS_INTERRUPTED.labels("restart").inc(interrupted)
        logger.warning("Marked %d interrupted investigation(s) as failed", interrupted)

    app.state.settings, app.state.db, app.state.repo = settings, db, repo
    app.state.keys = ApiKeyRepository(db)
    app.state.users = UserRepository(db)
    app.state.workspaces = WorkspaceRepository(db)
    app.state.oidc = OidcProvider(settings) if settings.oidc_issuer and settings.oidc_client_id else None
    app.state.audit = AuditLog(db)
    app.state.ws_tickets = TicketStore(db, settings.ws_ticket_ttl_seconds)
    app.state.scan_limiter = SlidingWindowLimiter(settings.scans_per_minute, 60)
    await _bootstrap_admin_key(app)
    await _audit_plugins(app)
    app.state.monitors = MonitorRepository(db)
    app.state.reports = ReportRepository(db)
    app.state.ratings = RatingRepository(db)
    app.state.schedules = ScheduleRepository(db)
    app.state.secret_box = secret_box_from_settings(settings)
    app.state.notifications = NotificationRepository(db, app.state.secret_box)
    app.state.notifier = NotificationDispatcher(
        app.state.notifications,
        settings,
        files=lambda report_id, workspace_id: app.state.reports.file(report_id, workspace_id=workspace_id),
    )
    app.state.report_scheduler = ReportScheduler(
        app.state.schedules, repo, app.state.reports, app.state.workspaces, app.state.audit, settings
    )
    report_task = (
        asyncio.create_task(app.state.report_scheduler.run_forever(), name="report-scheduler")
        if settings.report_schedules_enabled
        else None
    )
    notifier_task = (
        asyncio.create_task(app.state.notifier.run_forever(), name="notification-dispatcher")
        if settings.notifications_enabled
        else None
    )
    app.state.scheduler = MonitorScheduler(
        app.state.monitors,
        app.state.audit,
        settings,
        launch=lambda config, by, purpose, monitor_id, workspace_id: _launch_for_scheduler(
            app, config, by, purpose, monitor_id, workspace_id
        ),
        running_scans=lambda: cluster_running_scans(app),
    )
    janitor_task = asyncio.create_task(_janitor(app), name="crashed-scan-janitor")
    scheduler_task = (
        asyncio.create_task(app.state.scheduler.run_forever(), name="monitor-scheduler")
        if settings.monitors_enabled
        else None
    )
    event_bus.subscribe_all(ws_dispatcher)
    try:
        yield
    finally:
        background = [t for t in (scheduler_task, janitor_task, notifier_task, report_task) if t]
        for task in background:
            task.cancel()
        await asyncio.gather(*background, return_exceptions=True)
        event_bus.unsubscribe_all(ws_dispatcher)
        for engine in INVESTIGATIONS.values():
            engine.cancel()
        pending = [t for t in SCAN_TASKS.values() if not t.done()]
        if pending:
            await asyncio.wait(pending, timeout=15)  # let recorders persist final state
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        await db.dispose()


MIN_BOOTSTRAP_KEY_LENGTH = 32


async def _audit_plugins(app: FastAPI) -> None:
    """Third-party code runs with server privileges: record exactly what was loaded."""
    report = plugin_report()
    for name, source in report.loaded.items():
        await app.state.audit.record(SYSTEM, "plugin.loaded", name, details={"source": source})
    for name, reason in report.errors.items():
        await app.state.audit.record(SYSTEM, "plugin.rejected", name, outcome="failure", details={"reason": reason})


BOOTSTRAP_LOCK = 0x4152_4755_5342_4F4F  # "ARGUSBOO": replicas starting together bootstrap once


async def _bootstrap_admin_key(app: FastAPI) -> None:
    """Guarantee an administrator can always get in - without shipping a default password."""
    settings = app.state.settings
    if not settings.auth_enabled:
        logger.warning("AUTHENTICATION IS DISABLED (ARGUS_AUTH_ENABLED=false). Never expose this instance.")
        return
    # Several replicas start at once: without the lock each sees "no admin yet" and creates one.
    async with app.state.db.cluster_lock(BOOTSTRAP_LOCK):
        await _install_bootstrap_key(app, settings)


async def _install_bootstrap_key(app: FastAPI, settings: Settings) -> None:
    keys: ApiKeyRepository = app.state.keys
    if await keys.count_active(Role.ADMIN) > 0:
        return
    supplied = (settings.bootstrap_admin_key.get_secret_value() if settings.bootstrap_admin_key else "").strip() or None
    if supplied is not None and len(supplied) < MIN_BOOTSTRAP_KEY_LENGTH:
        # Fail closed: never install a guessable admin credential.
        raise RuntimeError(
            f"ARGUS_BOOTSTRAP_ADMIN_KEY must be at least {MIN_BOOTSTRAP_KEY_LENGTH} characters "
            "(generate one with: python -c \"import secrets; print('argus_' + secrets.token_urlsafe(32))\")"
        )
    record, key = await keys.create("bootstrap-admin", Role.ADMIN, created_by="system", plaintext=supplied)
    await app.state.audit.record(
        SYSTEM, "key.bootstrap", record["id"], details={"source": "env" if supplied else "generated"}
    )
    if not supplied:
        banner = "=" * 72
        logger.warning(
            "\n%s\n No admin API key existed, so one was generated. It will NOT be shown again:\n\n"
            "   %s\n\n Use it to sign in to the web UI, then create personal keys and revoke this one.\n%s",
            banner,
            key,
            banner,
        )


app = FastAPI(
    title="Argus OSINT Platform API",
    description="REST & WebSocket API for Argus Reconnaissance & Relationship Graphing",
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(ObservabilityMiddleware)  # outermost: times and labels everything, incl. errors
# Same-origin by default. The UI is served by this app, so CORS is only needed for
# separate front-ends, which must be listed explicitly (never "*").
_cors_origins = get_settings().cors_origins
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=False,  # auth is via header, not cookies
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Authorization", "X-API-Key", "Content-Type"],
    )
app.include_router(security_router)
app.include_router(auth_router)
app.include_router(workspace_router)
app.include_router(monitor_router)
app.include_router(notification_router)
app.include_router(report_router)
app.include_router(onboarding_router)
app.include_router(rating_router)

# Tenant-scoped endpoints receive a WorkspaceContext: the caller, the workspace and their role there.
VIEWER = Depends(in_workspace(Role.VIEWER))
ANALYST = Depends(in_workspace(Role.ANALYST))
ADMIN = Depends(in_workspace(Role.ADMIN))
PLATFORM_ADMIN = Depends(require_platform_admin)


def get_repo(request: Request) -> InvestigationRepository:
    return request.app.state.repo


# --------------------------------------------------------------------------- helpers
class StartScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    target_type: EntityType | None = None
    max_depth: int = Field(default=2, ge=0, le=4)
    passive_only: bool = Field(default=False, description="Skip modules that contact the target's own systems")
    enabled_modules: list[str] | None = None
    concurrency_limit: int = Field(default=15, ge=1, le=50)
    purpose: str = Field(
        min_length=5,
        max_length=500,
        description="Why this target is being investigated, e.g. 'HackerOne program X, ticket #123' or 'CTF'",
    )
    authorized: bool = Field(description="Confirms you are authorised to investigate this target")


def _live_investigation(engine: ArgusEngine) -> Investigation:
    """The engine's Investigation with live counters/stats filled in."""
    inv = engine.investigation
    if engine.is_running:
        inv = inv.model_copy(
            update={
                "node_count": engine.graph.node_count,
                "edge_count": engine.graph.edge_count,
                "truncated": engine.truncated,
                "module_stats": {n: s.as_dict() for n, s in engine.module_stats.items()},
                "http_stats": engine.http.stats.as_dict() if engine.http else {},
            }
        )
    return inv


def _investigation_payload(inv: Investigation) -> dict[str, Any]:
    return {
        "id": inv.id,
        "name": inv.name,
        "status": inv.status.value,
        "target": inv.config.target,
        "target_type": inv.config.target_type.value,
        "max_depth": inv.config.max_depth,
        "node_count": inv.node_count,
        "edge_count": inv.edge_count,
        "truncated": inv.truncated,
        "errors": inv.errors,
        "warnings": inv.warnings,
        "module_stats": inv.module_stats,
        "http_stats": inv.http_stats,
        "created_at": inv.created_at.isoformat(),
        "completed_at": inv.completed_at.isoformat() if inv.completed_at else None,
        "created_by": inv.created_by,
        "purpose": inv.purpose,
    }


def _not_found() -> HTTPException:
    return HTTPException(status_code=404, detail="Investigation not found")


async def _resolve(inv_id: str, repo: InvestigationRepository, workspace_id: str) -> Investigation:
    """THE tenant boundary for investigations: anything outside ``workspace_id`` is "not found"."""
    engine = INVESTIGATIONS.get(inv_id)
    if engine:
        if engine.investigation.workspace_id != workspace_id:
            raise _not_found()
        return _live_investigation(engine)
    inv = await repo.get_investigation(inv_id)
    if inv is None or inv.workspace_id != workspace_id:
        raise _not_found()
    return inv


async def _resolve_graph(inv_id: str, repo: InvestigationRepository, workspace_id: str) -> IntelligenceGraph:
    engine = INVESTIGATIONS.get(inv_id)
    if engine:
        if engine.investigation.workspace_id != workspace_id:
            raise _not_found()
        return engine.graph
    await _resolve(inv_id, repo, workspace_id)  # ownership first, then the (larger) graph
    graph = await repo.load_graph(inv_id)
    if graph is None:
        raise _not_found()
    return graph


async def _run_scan(engine: ArgusEngine, recorder: InvestigationRecorder) -> None:
    inv_id = engine.investigation_id
    try:
        await recorder.start()
        await engine.start()
    finally:
        try:
            await asyncio.shield(recorder.finish())
        except Exception:
            logger.exception("Failed to persist final state of %s", inv_id)
        INVESTIGATIONS.pop(inv_id, None)
        SCAN_TASKS.pop(inv_id, None)


BACKGROUND_TASKS: set[asyncio.Task[Any]] = set()


def _spawn(coro: Any, name: str) -> None:
    task = asyncio.create_task(coro, name=name)
    BACKGROUND_TASKS.add(task)  # strong reference until done
    task.add_done_callback(BACKGROUND_TASKS.discard)


def _running_scans() -> int:
    """Scans running in this process."""
    return sum(1 for e in INVESTIGATIONS.values() if e.is_running or e.investigation.status.value == "initializing")


async def cluster_running_scans(app: FastAPI) -> int:
    """Scans running on any replica (live heartbeat), so the concurrency cap is cluster-wide."""
    try:
        remote = len(await app.state.repo.active_scans(app.state.settings.scan_stale_seconds))
        metrics.CLUSTER_SCANS_RUNNING.set(remote)
    except Exception:
        logger.warning("Could not count cluster-wide scans; using this replica's count", exc_info=True)
        remote = 0
    return max(_running_scans(), remote)


async def _janitor(app: FastAPI) -> None:
    """Periodically fail scans whose owning replica died (no heartbeat), so they don't stay 'running'."""
    settings: Settings = app.state.settings
    while True:
        await asyncio.sleep(max(15.0, settings.scan_stale_seconds / 4))
        try:
            count = await app.state.repo.mark_interrupted(
                stale_seconds=settings.scan_stale_seconds,
                exclude=list(INVESTIGATIONS),
                reason="Interrupted: the replica running this scan stopped responding.",
            )
            if count:
                metrics.SCANS_INTERRUPTED.labels("replica_unresponsive").inc(count)
                logger.warning("Marked %d scan(s) of unresponsive replicas as failed", count)
            await cluster_running_scans(app)  # refreshes argus_cluster_scans_running
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Janitor pass failed")


async def launch_scan(
    app: FastAPI,
    config: ScanConfig,
    *,
    created_by: str,
    purpose: str,
    workspace_id: str,
    monitor_id: str | None = None,
) -> ArgusEngine:
    """Single code path for every scan (manual or scheduled): record, register, run in background."""
    repo: InvestigationRepository = app.state.repo
    engine = ArgusEngine(config)
    engine.investigation.workspace_id = workspace_id
    engine.investigation.created_by = created_by
    engine.investigation.purpose = purpose
    engine.investigation.monitor_id = monitor_id
    await repo.save_investigation(engine.investigation)  # fail before running if it cannot be recorded

    recorder = InvestigationRecorder(
        repo, engine, flush_interval=app.state.settings.persist_flush_interval, owner=app.state.settings.instance_id
    )
    INVESTIGATIONS[engine.investigation_id] = engine
    # Keep a strong reference to the task (asyncio only holds weak refs) and log failures.
    task = asyncio.create_task(_run_scan(engine, recorder), name=f"scan-{engine.investigation_id}")
    task.add_done_callback(_on_scan_done)
    if monitor_id:
        task.add_done_callback(lambda _t: _spawn(_evaluate_drift(app, engine), f"drift-{engine.investigation_id}"))
    SCAN_TASKS[engine.investigation_id] = task
    metrics.SCANS_STARTED.labels("monitor" if monitor_id else "manual").inc()
    return engine


async def _launch_for_scheduler(
    app: FastAPI, config: ScanConfig, by: str, purpose: str, monitor_id: str, workspace_id: str
) -> str:
    engine = await launch_scan(
        app, config, created_by=by, purpose=purpose, monitor_id=monitor_id, workspace_id=workspace_id
    )
    return engine.investigation_id


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


async def _evaluate_drift(app: FastAPI, engine: ArgusEngine) -> None:
    """After a monitored scan: compare with the previous scan and raise an alert if anything material changed."""
    inv = engine.investigation
    if inv.status != InvestigationStatus.COMPLETED:
        return
    repo: InvestigationRepository = app.state.repo
    previous = await repo.find_previous(inv)
    if previous is None:
        return  # first scan is the baseline
    old_graph = await repo.load_graph(previous.id)
    if old_graph is None:
        return
    diff = compare(old_graph, engine.graph)
    if not diff["summary"]["material"]:
        return
    worst = max(
        (p["severity"] for p in diff["new_paths"] + diff["escalated_paths"]),
        key=lambda s: SEVERITY_RANK.get(s, 0),
        default="low",
    )
    alert = await app.state.monitors.create_alert(
        monitor_id=inv.monitor_id,
        investigation_id=inv.id,
        previous_investigation_id=previous.id,
        target=inv.config.target,
        severity=worst,
        headline=headline(diff, inv.config.target),
        summary={k: diff[k] for k in ("summary", "new_paths", "escalated_paths", "resolved_paths")},
        workspace_id=inv.workspace_id,
        public_url=app.state.settings.public_url,
    )
    metrics.ALERTS_RAISED.labels(worst).inc()
    await app.state.audit.record(
        SCHEDULER,
        "alert.raised",
        alert["id"],
        details={"severity": worst, "target": inv.config.target, "notifications": alert.get("notifications_queued", 0)},
        workspace_id=inv.workspace_id,
    )


def _on_scan_done(task: asyncio.Task[None]) -> None:
    """Consume the task result so failures are logged instead of silently lost."""
    if not task.cancelled() and task.exception() is not None:
        logger.error("Scan task %s failed: %r", task.get_name(), task.exception())


# --------------------------------------------------------------------------- REST
@app.get("/metrics", include_in_schema=False)
async def prometheus_metrics(request: Request):
    """Prometheus scrape endpoint (one per replica). Optionally protected by ARGUS_METRICS_TOKEN."""
    settings: Settings = request.app.state.settings
    if not settings.metrics_enabled:
        raise HTTPException(status_code=404, detail="Not found")
    if settings.metrics_token is not None:
        expected = f"Bearer {settings.metrics_token.get_secret_value()}"
        if not hmac.compare_digest(request.headers.get("authorization", ""), expected):
            metrics.AUTH_FAILURES.labels("metrics_token").inc()
            raise HTTPException(
                status_code=401, detail="Metrics token required", headers={"WWW-Authenticate": "Bearer"}
            )
    body, content_type = metrics.render()
    return Response(body, media_type=content_type)


@app.get("/api/live")
async def live():
    """Liveness probe: the process is up and serving. Deliberately ignores the database, so a
    database outage makes pods *unready* (taken out of the load balancer) rather than restarted."""
    return {"status": "alive"}


@app.get("/api/health")
async def health(request: Request):
    """Liveness/readiness probe for Docker, Kubernetes and load balancers."""
    db: Database = request.app.state.db
    try:
        async with db.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        db_ok = True
        metrics.DATABASE_UP.set(1)
    except Exception:
        logger.warning("Health check: database unreachable", exc_info=True)
        db_ok = False
        metrics.DATABASE_UP.set(0)
    body = {
        "status": "ok" if db_ok else "degraded",
        "database": {"backend": db.dialect, "reachable": db_ok},
        "active_scans": len(INVESTIGATIONS),
        "instance": request.app.state.settings.instance_id,
        "version": app.version,
    }
    if not db_ok:
        return Response(json.dumps(body), status_code=503, media_type="application/json")
    return body


@app.get("/api/modules")
async def list_modules(ws: WorkspaceContext = VIEWER):
    """Return list of available OSINT reconnaissance modules."""
    return [
        {
            "name": m.name,
            "description": m.description,
            "supported_types": [t.value for t in m.supported_entity_types],
            "attack_techniques": list(m.attack_techniques),
            "active": m.active,
            "requires": list(m.requires_settings),
            "configured": m.is_configured(),
            "origin": m.origin,
        }
        for m in get_module_catalog().values()
    ]


@app.get("/api/plugins")
async def list_plugins(_: Principal = PLATFORM_ADMIN):
    """Plugin status: allowlisted, loaded, rejected (with reasons) and installed-but-inactive."""
    return asdict(plugin_report())


@app.post("/api/demo")
async def load_demo_investigation(request: Request, ws: WorkspaceContext = ADMIN):
    """Load the built-in fictional demo investigation (reserved .example domains, TEST-NET IPs)."""
    principal = ws.principal
    inv_id = await load_demo(get_repo(request), ws.id)
    await audit(request, principal, "demo.load", inv_id)
    return {"investigation_id": inv_id}


@app.get("/api/investigations")
async def list_investigations(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    status: InvestigationStatus | None = None,
    target: str | None = Query(None, max_length=253),
    ws: WorkspaceContext = VIEWER,
):
    """Investigation history (newest first), with live counters for running scans."""
    rows = await get_repo(request).list_investigations(
        workspace_id=ws.id, limit=limit, offset=offset, status=status.value if status else None, target=target
    )
    for row in rows:
        engine = INVESTIGATIONS.get(row["id"])
        if engine:
            row["status"] = engine.investigation.status.value
            row["nodes_count"] = engine.graph.node_count
            row["edges_count"] = engine.graph.edge_count
    return rows


@app.post("/api/scan")
async def start_scan(req: StartScanRequest, request: Request, ws: WorkspaceContext = ANALYST):
    """Initiate a new reconnaissance scan in the background."""
    principal = ws.principal
    from argus.cli.console import detect_target_type

    settings = request.app.state.settings
    target = req.target.strip()
    if not target:
        raise HTTPException(status_code=422, detail="Target must not be blank")
    if not req.authorized:
        await audit(request, principal, "scan.start", target, "denied", {"reason": "authorisation not confirmed"})
        raise HTTPException(status_code=422, detail="You must confirm you are authorised to investigate this target")
    if req.enabled_modules:
        catalog = get_module_catalog()
        unknown = set(req.enabled_modules) - set(catalog)
        if unknown:
            raise HTTPException(status_code=422, detail=f"Unknown modules: {sorted(unknown)}")
        unconfigured = sorted(n for n in req.enabled_modules if not catalog[n].is_configured())
        if unconfigured:
            raise HTTPException(status_code=422, detail=f"Modules need an API key first: {unconfigured}")

    ttype = req.target_type or detect_target_type(target)
    if not settings.allow_private_targets:
        try:
            validate_scan_target(target, ttype)
        except ValueError as exc:
            await audit(request, principal, "scan.start", target, "denied", {"reason": str(exc)})
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    if await cluster_running_scans(request.app) >= settings.max_concurrent_scans:
        metrics.RATE_LIMITED.labels("concurrent_scans").inc()
        raise HTTPException(
            status_code=429, detail=f"Server is at its limit of {settings.max_concurrent_scans} concurrent scans"
        )
    limiter: SlidingWindowLimiter = request.app.state.scan_limiter
    if not limiter.hit(principal.key_id):
        metrics.RATE_LIMITED.labels("scans_per_minute").inc()
        raise HTTPException(
            status_code=429,
            detail="Scan rate limit exceeded",
            headers={"Retry-After": str(limiter.retry_after(principal.key_id))},
        )

    try:
        config = ScanConfig(
            target=target,
            target_type=ttype,
            max_depth=req.max_depth,
            passive_only=req.passive_only,
            enabled_modules=req.enabled_modules,
            concurrency_limit=req.concurrency_limit,
            allow_private_targets=settings.allow_private_targets,
        )
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors(include_url=False)) from exc

    try:  # fail fast (503) if we cannot record the scan, rather than run it unsaved
        engine = await launch_scan(
            request.app, config, created_by=principal.name, purpose=req.purpose, workspace_id=ws.id
        )
    except Exception as exc:
        logger.exception("Database unavailable")
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    await audit(
        request,
        principal,
        "scan.start",
        engine.investigation_id,
        details={
            "target": target,
            "target_type": ttype.value,
            "max_depth": req.max_depth,
            "passive_only": req.passive_only,
            "purpose": req.purpose,
            "authorized_confirmed": True,
            # What the person was warned about (computed here, not trusted from the client).
            "scope_warnings": [w["code"] for w in scope_warnings(target, ttype, req.passive_only)],
        },
    )

    return {
        "status": "launched",
        "investigation_id": engine.investigation_id,
        "target": target,
        "target_type": ttype.value,
    }


@app.get("/api/investigation/{inv_id}")
async def get_investigation(inv_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Status, summary metrics and execution telemetry of an investigation."""
    return _investigation_payload(await _resolve(inv_id, get_repo(request), ws.id))


@app.post("/api/investigation/{inv_id}/cancel")
async def cancel_investigation(inv_id: str, request: Request, ws: WorkspaceContext = ANALYST):
    """Request cooperative cancellation of a running investigation."""
    principal = ws.principal
    inv = await _resolve(inv_id, get_repo(request), ws.id)  # tenant check first: 404 outside this workspace
    engine = INVESTIGATIONS.get(inv_id)
    if engine is not None and engine.is_running:
        engine.cancel()
        await audit(request, principal, "scan.cancel", inv_id)
        return {"status": "cancelling", "investigation_id": inv_id}
    if engine is None and await get_repo(request).request_cancel(inv_id):
        # Running on another replica: it sees the request on its next heartbeat (~1 s).
        await audit(request, principal, "scan.cancel", inv_id, details={"via": "cluster"})
        return {"status": "cancelling", "investigation_id": inv_id}
    raise HTTPException(status_code=409, detail=f"Investigation is {inv.status.value}")


@app.delete("/api/investigation/{inv_id}", status_code=204)
async def delete_investigation(inv_id: str, request: Request, ws: WorkspaceContext = ADMIN):
    """Permanently delete an investigation and all of its findings."""
    principal = ws.principal
    stored = await _resolve(inv_id, get_repo(request), ws.id)  # tenant check first: 404 outside this workspace
    if inv_id in INVESTIGATIONS or stored.status.value in ACTIVE_STATUSES:
        raise HTTPException(status_code=409, detail="Investigation is running; cancel it first")
    if not await get_repo(request).delete_investigation(inv_id):
        raise HTTPException(status_code=404, detail="Investigation not found")
    await audit(request, principal, "investigation.delete", inv_id)
    return Response(status_code=204)


@app.get("/api/investigation/{inv_id}/graph")
async def get_investigation_graph(inv_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Retrieve full Cytoscape-formatted graph elements."""
    graph = await _resolve_graph(inv_id, get_repo(request), ws.id)
    return {
        "investigation_id": inv_id,
        "elements": graph.to_cytoscape_elements(),
        "analytics": GraphIntelligenceAnalyzer.analyze(graph),
    }


@app.get("/api/investigation/{inv_id}/export/json")
async def export_graph_json(inv_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Export complete graph as JSON."""
    principal = ws.principal
    graph = await _resolve_graph(inv_id, get_repo(request), ws.id)
    await audit(request, principal, "investigation.export", inv_id, details={"format": "json"})
    return graph.to_dict()


@app.get("/api/investigation/{inv_id}/export/csv")
async def export_graph_csv(inv_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Export relationships in Maltego-compatible CSV format."""
    principal = ws.principal
    graph = await _resolve_graph(inv_id, get_repo(request), ws.id)
    await audit(request, principal, "investigation.export", inv_id, details={"format": "csv"})
    return PlainTextResponse(
        graph.to_maltego_csv(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=argus_{inv_id}_maltego.csv"},
    )


def _modules_for(inv_id: str) -> dict[str, Any]:
    engine = INVESTIGATIONS.get(inv_id)
    return engine.modules if engine else get_default_modules()


@app.get("/api/investigation/{inv_id}/attack")
async def get_attack_mapping(inv_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Findings classified by MITRE ATT&CK reconnaissance technique, with defensive guidance."""
    graph = await _resolve_graph(inv_id, get_repo(request), ws.id)
    return map_investigation(graph, _modules_for(inv_id))


@app.get("/api/investigation/{inv_id}/paths")
async def get_attack_paths(inv_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Attack Path Engine: findings chained into ranked, explained attack scenarios."""
    return find_attack_paths(await _resolve_graph(inv_id, get_repo(request), ws.id))


@app.get("/api/investigation/{inv_id}/people")
async def get_people(inv_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Identity resolution: linked identifiers grouped into personas, each with a dossier.

    Dossiers aggregate personal data, so every access is recorded in the audit log.
    """
    principal = ws.principal
    graph = await _resolve_graph(inv_id, get_repo(request), ws.id)
    await audit(request, principal, "investigation.people", inv_id)
    return resolve_people(graph, find_attack_paths(graph)["paths"])


@app.get("/api/investigation/{inv_id}/diff")
async def diff_investigation(
    inv_id: str, request: Request, against: str | None = Query(None, max_length=64), ws: WorkspaceContext = VIEWER
):
    """What changed since an earlier scan of the same target (default: the previous completed one)."""
    repo = get_repo(request)
    inv = await _resolve(inv_id, repo, ws.id)
    previous = await _resolve(against, repo, ws.id) if against else await repo.find_previous(inv)
    if previous is None:
        raise HTTPException(status_code=404, detail="No earlier completed investigation of this target to compare with")
    if previous.config.target.lower() != inv.config.target.lower():
        raise HTTPException(status_code=422, detail="Investigations are of different targets")
    diff = compare(await _resolve_graph(previous.id, repo, ws.id), await _resolve_graph(inv_id, repo, ws.id))
    return {
        "investigation_id": inv_id,
        "previous_investigation_id": previous.id,
        "previous_completed_at": previous.completed_at.isoformat() if previous.completed_at else None,
        "headline": headline(diff, inv.config.target),
        **diff,
    }


@app.get("/api/investigation/{inv_id}/export/navigator")
async def export_attack_navigator(inv_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """ATT&CK Navigator layer (open at https://mitre-attack.github.io/attack-navigator/)."""
    principal = ws.principal
    repo = get_repo(request)
    inv, graph = await _resolve(inv_id, repo, ws.id), await _resolve_graph(inv_id, repo, ws.id)
    layer = to_navigator_layer(map_investigation(graph), f"Argus: {inv.config.target}", f"Investigation {inv_id}")
    await audit(request, principal, "investigation.export", inv_id, details={"format": "attack-navigator"})
    return JSONResponse(
        layer, headers={"Content-Disposition": f"attachment; filename=argus_{inv_id}_attack_layer.json"}
    )


@app.get("/api/investigation/{inv_id}/export/stix")
async def export_stix(inv_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """STIX 2.1 bundle for threat-intelligence platforms (OpenCTI, MISP...). Marked TLP:AMBER."""
    principal = ws.principal
    repo = get_repo(request)
    inv, graph = await _resolve(inv_id, repo, ws.id), await _resolve_graph(inv_id, repo, ws.id)
    bundle = build_bundle(inv, graph)
    await audit(request, principal, "investigation.export", inv_id, details={"format": "stix-2.1"})
    return Response(
        bundle.serialize(pretty=True),
        media_type="application/stix+json;version=2.1",
        headers={"Content-Disposition": f"attachment; filename=argus_{inv_id}_stix.json"},
    )


@app.get("/api/investigation/{inv_id}/rating")
async def get_rating(inv_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Security rating (A-F) with its factor breakdown, improvement plan, trend and benchmark."""
    repo = get_repo(request)
    inv = await _resolve(inv_id, repo, ws.id)
    graph = await _resolve_graph(inv_id, repo, ws.id)
    rating = await rate(request.app, inv, graph)
    await ensure_history(request.app, ws.id, inv.config.target)  # the trend needs earlier scans rated too
    history = await request.app.state.ratings.history(inv.config.target, workspace_id=ws.id)
    return {
        **rating,
        "target": inv.config.target,
        "investigation_id": inv_id,
        "live": inv.status.value in ACTIVE_STATUSES,
        "history": history,
        "benchmark": await benchmark(request.app, ws.id, inv.config.target, rating.get("score", 0)),
    }


class ReportRequest(BaseModel):
    prepared_for: str = Field(default="", max_length=200, description="Client or recipient shown on the cover")
    tlp: Literal["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"] = "AMBER"
    include_inventory: bool = True
    compare_previous: bool = True
    include_personal_details: bool = Field(
        default=False, description="Name the people in attack paths instead of pseudonymising them (audited)"
    )


_report_limiter = SlidingWindowLimiter(limit=10, window=60)  # per principal: PDF rendering costs CPU


@app.post("/api/investigation/{inv_id}/report")
async def generate_report(
    inv_id: str, request: Request, body: ReportRequest | None = None, ws: WorkspaceContext = ANALYST
):
    """Client-ready PDF report. Each file's SHA-256 is registered so recipients can verify it."""
    principal = ws.principal
    options = body or ReportRequest()
    repo = get_repo(request)
    inv = await _resolve(inv_id, repo, ws.id)
    if inv.status.value in ACTIVE_STATUSES:
        raise HTTPException(status_code=409, detail="The scan is still running; generate the report when it finishes")
    if not _report_limiter.hit(principal.key_id):
        metrics.RATE_LIMITED.labels("report").inc()
        raise HTTPException(status_code=429, detail="Too many reports; try again in a minute")
    graph = await _resolve_graph(inv_id, repo, ws.id)
    report_options = ReportOptions(
        prepared_for=options.prepared_for.strip(),
        tlp=options.tlp,
        include_inventory=options.include_inventory,
        compare_previous=options.compare_previous,
        include_personal_details=options.include_personal_details,
    )
    issued = await issue_report(
        investigations=repo,
        reports=request.app.state.reports,
        investigation=inv,
        graph=graph,
        options=report_options,
        workspace=ws.workspace,
        issued_by=principal.name,
        base_url=public_base_url(request),
    )
    data, pdf, digest, filename = issued.data, issued.pdf, issued.sha256, issued.filename
    await audit(
        request,
        principal,
        "report.generate",
        inv_id,
        details={
            "report_id": data.report_id,
            "sha256": digest,
            "tlp": options.tlp,
            "prepared_for": options.prepared_for,
            "personal_details": options.include_personal_details,
        },
    )
    return Response(
        pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
            "X-Argus-Report-Id": data.report_id,
            "X-Argus-Report-Sha256": digest,
        },
    )


@app.get("/api/entities/search")
async def search_entities(
    request: Request,
    q: str = Query(min_length=2, max_length=253, description="Substring of the entity value"),
    type: EntityType | None = None,
    limit: int = Query(50, ge=1, le=500),
    ws: WorkspaceContext = VIEWER,
):
    """Cross-investigation pivot: every investigation *of this workspace* in which a value has been seen."""
    return await get_repo(request).search_entities(
        q, workspace_id=ws.id, entity_type=type.value if type else None, limit=limit
    )


# --------------------------------------------------------------------------- WebSocket
@app.websocket("/ws/stream/{inv_id}")
async def websocket_stream(websocket: WebSocket, inv_id: str):
    """Snapshot of everything found so far, followed by live events.

    Authenticate with ``?ticket=`` from ``POST /api/ws-ticket`` (single use, short-lived).
    """
    ticket = websocket.query_params.get("ticket")
    auth_enabled = websocket.app.state.settings.auth_enabled
    redeemed = await websocket.app.state.ws_tickets.redeem_for_workspace(ticket) if auth_enabled else None
    if auth_enabled and redeemed is None:
        metrics.AUTH_FAILURES.labels("websocket_ticket").inc()
        await websocket.close(code=4401)
        return
    repo: InvestigationRepository = websocket.app.state.repo
    engine = INVESTIGATIONS.get(inv_id)
    stored = None if engine else await repo.get_investigation(inv_id)
    owner_ws = engine.investigation.workspace_id if engine else stored.workspace_id if stored else None
    # The ticket was issued for one workspace: anything else is "not found", exactly like the REST API.
    if owner_ws is None or (redeemed is not None and redeemed[1] != owner_ws):
        await websocket.close(code=4404)
        return
    await websocket.accept()

    conn = ClientConnection(websocket, websocket.app.state.settings.ws_queue_size)
    tail_graph: IntelligenceGraph | None = None
    engine = INVESTIGATIONS.get(inv_id)  # re-check: the scan may have finished meanwhile
    if engine is not None:
        # No await between snapshot and registration: no event can slip between them.
        snapshot = _snapshot_message(_live_investigation(engine), engine.graph)
        conn.offer(snapshot)
        CONNECTIONS.setdefault(inv_id, set()).add(conn)
    else:
        inv, graph = await repo.get_investigation(inv_id), await repo.load_graph(inv_id)
        if inv is None or graph is None:
            await websocket.close(code=4404)
            return
        conn.offer(_snapshot_message(inv, graph))
        if inv.status.value in ACTIVE_STATUSES:
            tail_graph = graph  # running on another replica: follow it through the database

    client_gone = False

    async def tail_database(start: IntelligenceGraph) -> None:
        """Stream a scan owned by another replica by following its database checkpoints."""
        sent_entities = {e.id for e in start.get_all_entities()}
        sent_relations = {r.id for r in start.get_all_relations()}
        counts = (start.node_count, start.edge_count)
        interval = max(0.5, websocket.app.state.settings.persist_flush_interval)
        while True:
            await anyio.sleep(interval)
            progress = await repo.progress(inv_id)
            if progress is None:
                return  # deleted
            status, nodes, edges = progress
            finished = status not in ACTIVE_STATUSES
            if (nodes, edges) != counts or finished:
                counts = (nodes, edges)
                graph = await repo.load_graph(inv_id)
                if graph is None:
                    return
                for e in graph.get_all_entities():
                    if e.id not in sent_entities:
                        sent_entities.add(e.id)
                        conn.offer(_event_json("entity_discovered", inv_id, {"entity": e.model_dump(mode="json")}))
                for r in graph.get_all_relations():
                    if r.id not in sent_relations:
                        sent_relations.add(r.id)
                        conn.offer(_event_json("relation_discovered", inv_id, {"relation": r.model_dump(mode="json")}))
                if finished:
                    final = await repo.get_investigation(inv_id)
                    data: dict[str, Any] = {"analytics": GraphIntelligenceAnalyzer.analyze(graph)}
                    if final is not None and final.errors:
                        data["error"] = final.errors[-1]
                    kind = {"completed": "scan_completed", "cancelled": "scan_cancelled"}.get(status, "scan_failed")
                    conn.offer(_event_json(kind, inv_id, data))
                    await anyio.sleep_forever()  # keep the socket open, as for local scans

    async def drain_client() -> None:
        nonlocal client_gone
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            client_gone = True

    ws_mode = "tail" if tail_graph is not None else "live" if engine is not None else "replay"
    metrics.WS_CONNECTIONS.labels(ws_mode).inc()
    try:
        # Structured concurrency (anyio, which Starlette itself uses): whichever of
        # sender / receiver / overflow-watch finishes first cancels the other two,
        # and cancellation from the server propagates through cleanly.
        async with anyio.create_task_group() as tg:

            async def first_to_finish_wins(fn) -> None:
                try:
                    await fn()
                except Exception as exc:  # noqa: BLE001 - e.g. send on a broken socket ends this client only
                    logger.debug("WebSocket task ended: %r", exc)
                finally:
                    tg.cancel_scope.cancel()

            tg.start_soon(first_to_finish_wins, conn.pump)
            tg.start_soon(first_to_finish_wins, drain_client)
            tg.start_soon(first_to_finish_wins, conn.dead.wait)
            if tail_graph is not None:
                start_graph = tail_graph
                tg.start_soon(first_to_finish_wins, lambda: tail_database(start_graph))
    finally:
        metrics.WS_CONNECTIONS.labels(ws_mode).dec()
        conns = CONNECTIONS.get(inv_id)
        if conns is not None:
            conns.discard(conn)
            if not conns:
                CONNECTIONS.pop(inv_id, None)

    if not client_gone:  # server-side ending (e.g. slow client): tell the browser
        if conn.dead.is_set():
            metrics.WS_SLOW_CLIENTS.inc()
        try:
            await websocket.close(code=1013)
        except Exception as exc:  # noqa: BLE001 - best-effort notice to a client that may already be gone
            logger.debug("Could not close WebSocket cleanly: %r", exc)


def _event_json(kind: str, inv_id: str, data: dict[str, Any]) -> str:
    """Same wire format as engine events relayed by :func:`ws_dispatcher`."""
    from datetime import datetime, timezone

    return json.dumps(
        {"type": kind, "investigation_id": inv_id, "data": data, "timestamp": datetime.now(timezone.utc).isoformat()}
    )


def _snapshot_message(inv: Investigation, graph: IntelligenceGraph) -> str:
    return json.dumps(
        {
            "type": "snapshot",
            "investigation_id": inv.id,
            "data": {
                "investigation": _investigation_payload(inv),
                "analytics": inv.analytics,
                "entities": [e.model_dump(mode="json") for e in graph.get_all_entities()],
                "relations": [r.model_dump(mode="json") for r in graph.get_all_relations()],
            },
        }
    )


# --------------------------------------------------------------------------- static UI
if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def serve_index():
        index_file = WEB_DIR / "index.html"
        if index_file.exists():
            return HTMLResponse(content=index_file.read_text(encoding="utf-8"))
        return HTMLResponse("<h3>Argus Web UI Loading...</h3>")
