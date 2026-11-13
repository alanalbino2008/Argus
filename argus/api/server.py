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
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import anyio
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import text

from argus import __version__
from argus.api.deps import WebSocketTickets, audit, require
from argus.api.security_routes import router as security_router
from argus.core.engine import ArgusEngine
from argus.core.events import Event, event_bus
from argus.core.graph import IntelligenceGraph
from argus.core.models import EntityType, Investigation, InvestigationStatus, ScanConfig
from argus.core.settings import get_settings
from argus.modules import get_default_modules
from argus.modules.analytics.graph_analyzer import GraphIntelligenceAnalyzer
from argus.security.auth import SYSTEM, Principal, Role
from argus.security.headers import SecurityHeadersMiddleware
from argus.security.network import validate_scan_target
from argus.security.ratelimit import SlidingWindowLimiter
from argus.storage import Database, InvestigationRecorder, InvestigationRepository
from argus.storage.migrate import upgrade_database
from argus.storage.security_repo import ApiKeyRepository, AuditLog

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
    db = Database(settings.database_url, echo=settings.db_echo)
    await upgrade_database(db)
    repo = InvestigationRepository(db)
    interrupted = await repo.mark_interrupted()
    if interrupted:
        logger.warning("Marked %d interrupted investigation(s) as failed", interrupted)

    app.state.settings, app.state.db, app.state.repo = settings, db, repo
    app.state.keys = ApiKeyRepository(db)
    app.state.audit = AuditLog(db)
    app.state.ws_tickets = WebSocketTickets(settings.ws_ticket_ttl_seconds)
    app.state.scan_limiter = SlidingWindowLimiter(settings.scans_per_minute, 60)
    await _bootstrap_admin_key(app)
    event_bus.subscribe_all(ws_dispatcher)
    try:
        yield
    finally:
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


async def _bootstrap_admin_key(app: FastAPI) -> None:
    """Guarantee an administrator can always get in - without shipping a default password."""
    settings = app.state.settings
    if not settings.auth_enabled:
        logger.warning("AUTHENTICATION IS DISABLED (ARGUS_AUTH_ENABLED=false). Never expose this instance.")
        return
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

VIEWER = Depends(require(Role.VIEWER))
ANALYST = Depends(require(Role.ANALYST))
ADMIN = Depends(require(Role.ADMIN))


def get_repo(request: Request) -> InvestigationRepository:
    return request.app.state.repo


# --------------------------------------------------------------------------- helpers
class StartScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    target_type: EntityType | None = None
    max_depth: int = Field(default=2, ge=0, le=4)
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


async def _resolve(inv_id: str, repo: InvestigationRepository) -> Investigation:
    engine = INVESTIGATIONS.get(inv_id)
    if engine:
        return _live_investigation(engine)
    inv = await repo.get_investigation(inv_id)
    if inv is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv


async def _resolve_graph(inv_id: str, repo: InvestigationRepository) -> IntelligenceGraph:
    engine = INVESTIGATIONS.get(inv_id)
    if engine:
        return engine.graph
    graph = await repo.load_graph(inv_id)
    if graph is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
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


def _on_scan_done(task: asyncio.Task[None]) -> None:
    """Consume the task result so failures are logged instead of silently lost."""
    if not task.cancelled() and task.exception() is not None:
        logger.error("Scan task %s failed: %r", task.get_name(), task.exception())


# --------------------------------------------------------------------------- REST
@app.get("/api/health")
async def health(request: Request):
    """Liveness/readiness probe for Docker, Kubernetes and load balancers."""
    db: Database = request.app.state.db
    try:
        async with db.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        logger.warning("Health check: database unreachable", exc_info=True)
        db_ok = False
    body = {
        "status": "ok" if db_ok else "degraded",
        "database": {"backend": db.dialect, "reachable": db_ok},
        "active_scans": len(INVESTIGATIONS),
        "version": app.version,
    }
    if not db_ok:
        return Response(json.dumps(body), status_code=503, media_type="application/json")
    return body


@app.get("/api/modules")
async def list_modules(_: Principal = VIEWER):
    """Return list of available OSINT reconnaissance modules."""
    return [
        {
            "name": m.name,
            "description": m.description,
            "supported_types": [t.value for t in m.supported_entity_types],
        }
        for m in get_default_modules().values()
    ]


@app.get("/api/investigations")
async def list_investigations(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    status: InvestigationStatus | None = None,
    target: str | None = Query(None, max_length=253),
    _: Principal = VIEWER,
):
    """Investigation history (newest first), with live counters for running scans."""
    rows = await get_repo(request).list_investigations(
        limit=limit, offset=offset, status=status.value if status else None, target=target
    )
    for row in rows:
        engine = INVESTIGATIONS.get(row["id"])
        if engine:
            row["status"] = engine.investigation.status.value
            row["nodes_count"] = engine.graph.node_count
            row["edges_count"] = engine.graph.edge_count
    return rows


@app.post("/api/scan")
async def start_scan(req: StartScanRequest, request: Request, principal: Principal = ANALYST):
    """Initiate a new reconnaissance scan in the background."""
    from argus.cli.console import detect_target_type

    settings = request.app.state.settings
    target = req.target.strip()
    if not target:
        raise HTTPException(status_code=422, detail="Target must not be blank")
    if not req.authorized:
        await audit(request, principal, "scan.start", target, "denied", {"reason": "authorisation not confirmed"})
        raise HTTPException(status_code=422, detail="You must confirm you are authorised to investigate this target")
    if req.enabled_modules:
        unknown = set(req.enabled_modules) - set(get_default_modules())
        if unknown:
            raise HTTPException(status_code=422, detail=f"Unknown modules: {sorted(unknown)}")

    ttype = req.target_type or detect_target_type(target)
    if not settings.allow_private_targets:
        try:
            validate_scan_target(target, ttype)
        except ValueError as exc:
            await audit(request, principal, "scan.start", target, "denied", {"reason": str(exc)})
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    running = sum(1 for e in INVESTIGATIONS.values() if e.is_running or e.investigation.status.value == "initializing")
    if running >= settings.max_concurrent_scans:
        raise HTTPException(
            status_code=429, detail=f"Server is at its limit of {settings.max_concurrent_scans} concurrent scans"
        )
    limiter: SlidingWindowLimiter = request.app.state.scan_limiter
    if not limiter.hit(principal.key_id):
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
            enabled_modules=req.enabled_modules,
            concurrency_limit=req.concurrency_limit,
            allow_private_targets=settings.allow_private_targets,
        )
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors(include_url=False)) from exc

    repo = get_repo(request)
    engine = ArgusEngine(config)
    engine.investigation.created_by = principal.name
    engine.investigation.purpose = req.purpose
    try:  # fail fast (503) if we cannot record the scan, rather than run it unsaved
        await repo.save_investigation(engine.investigation)
    except Exception as exc:
        logger.exception("Database unavailable")
        raise HTTPException(status_code=503, detail="Database unavailable") from exc

    recorder = InvestigationRecorder(repo, engine, flush_interval=request.app.state.settings.persist_flush_interval)
    INVESTIGATIONS[engine.investigation_id] = engine
    # Keep a strong reference to the task (asyncio only holds weak refs) and log failures.
    task = asyncio.create_task(_run_scan(engine, recorder), name=f"scan-{engine.investigation_id}")
    task.add_done_callback(_on_scan_done)
    SCAN_TASKS[engine.investigation_id] = task
    await audit(
        request,
        principal,
        "scan.start",
        engine.investigation_id,
        details={
            "target": target,
            "target_type": ttype.value,
            "max_depth": req.max_depth,
            "purpose": req.purpose,
            "authorized_confirmed": True,
        },
    )

    return {
        "status": "launched",
        "investigation_id": engine.investigation_id,
        "target": target,
        "target_type": ttype.value,
    }


@app.get("/api/investigation/{inv_id}")
async def get_investigation(inv_id: str, request: Request, _: Principal = VIEWER):
    """Status, summary metrics and execution telemetry of an investigation."""
    return _investigation_payload(await _resolve(inv_id, get_repo(request)))


@app.post("/api/investigation/{inv_id}/cancel")
async def cancel_investigation(inv_id: str, request: Request, principal: Principal = ANALYST):
    """Request cooperative cancellation of a running investigation."""
    engine = INVESTIGATIONS.get(inv_id)
    if engine is None or not engine.is_running:
        inv = await _resolve(inv_id, get_repo(request))  # 404 if unknown
        raise HTTPException(status_code=409, detail=f"Investigation is {inv.status.value}")
    engine.cancel()
    await audit(request, principal, "scan.cancel", inv_id)
    return {"status": "cancelling", "investigation_id": inv_id}


@app.delete("/api/investigation/{inv_id}", status_code=204)
async def delete_investigation(inv_id: str, request: Request, principal: Principal = ADMIN):
    """Permanently delete an investigation and all of its findings."""
    if inv_id in INVESTIGATIONS:
        raise HTTPException(status_code=409, detail="Investigation is running; cancel it first")
    if not await get_repo(request).delete_investigation(inv_id):
        raise HTTPException(status_code=404, detail="Investigation not found")
    await audit(request, principal, "investigation.delete", inv_id)
    return Response(status_code=204)


@app.get("/api/investigation/{inv_id}/graph")
async def get_investigation_graph(inv_id: str, request: Request, _: Principal = VIEWER):
    """Retrieve full Cytoscape-formatted graph elements."""
    graph = await _resolve_graph(inv_id, get_repo(request))
    return {
        "investigation_id": inv_id,
        "elements": graph.to_cytoscape_elements(),
        "analytics": GraphIntelligenceAnalyzer.analyze(graph),
    }


@app.get("/api/investigation/{inv_id}/export/json")
async def export_graph_json(inv_id: str, request: Request, principal: Principal = VIEWER):
    """Export complete graph as JSON."""
    graph = await _resolve_graph(inv_id, get_repo(request))
    await audit(request, principal, "investigation.export", inv_id, details={"format": "json"})
    return graph.to_dict()


@app.get("/api/investigation/{inv_id}/export/csv")
async def export_graph_csv(inv_id: str, request: Request, principal: Principal = VIEWER):
    """Export relationships in Maltego-compatible CSV format."""
    graph = await _resolve_graph(inv_id, get_repo(request))
    await audit(request, principal, "investigation.export", inv_id, details={"format": "csv"})
    return PlainTextResponse(
        graph.to_maltego_csv(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=argus_{inv_id}_maltego.csv"},
    )


@app.get("/api/entities/search")
async def search_entities(
    request: Request,
    q: str = Query(min_length=2, max_length=253, description="Substring of the entity value"),
    type: EntityType | None = None,
    limit: int = Query(50, ge=1, le=500),
    _: Principal = VIEWER,
):
    """Cross-investigation pivot: every investigation in which a value has been seen."""
    return await get_repo(request).search_entities(q, type.value if type else None, limit)


# --------------------------------------------------------------------------- WebSocket
@app.websocket("/ws/stream/{inv_id}")
async def websocket_stream(websocket: WebSocket, inv_id: str):
    """Snapshot of everything found so far, followed by live events.

    Authenticate with ``?ticket=`` from ``POST /api/ws-ticket`` (single use, short-lived).
    """
    ticket = websocket.query_params.get("ticket")
    if websocket.app.state.settings.auth_enabled and websocket.app.state.ws_tickets.redeem(ticket) is None:
        await websocket.close(code=4401)
        return
    repo: InvestigationRepository = websocket.app.state.repo
    engine = INVESTIGATIONS.get(inv_id)
    if engine is None and await repo.get_investigation(inv_id) is None:
        await websocket.close(code=4404)
        return
    await websocket.accept()

    conn = ClientConnection(websocket, websocket.app.state.settings.ws_queue_size)
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

    client_gone = False

    async def drain_client() -> None:
        nonlocal client_gone
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            client_gone = True

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
    finally:
        conns = CONNECTIONS.get(inv_id)
        if conns is not None:
            conns.discard(conn)
            if not conns:
                CONNECTIONS.pop(inv_id, None)

    if not client_gone:  # server-side ending (e.g. slow client): tell the browser
        try:
            await websocket.close(code=1013)
        except Exception as exc:  # noqa: BLE001 - best-effort notice to a client that may already be gone
            logger.debug("Could not close WebSocket cleanly: %r", exc)


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
