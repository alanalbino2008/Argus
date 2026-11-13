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
from contextlib import asynccontextmanager
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import text

from argus.core.engine import ArgusEngine
from argus.core.events import Event, event_bus
from argus.core.graph import IntelligenceGraph
from argus.core.models import EntityType, Investigation, InvestigationStatus, ScanConfig
from argus.core.settings import get_settings
from argus.modules import get_default_modules
from argus.modules.analytics.graph_analyzer import GraphIntelligenceAnalyzer
from argus.storage import Database, InvestigationRecorder, InvestigationRepository

logger = logging.getLogger("argus.api")

BASE_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = BASE_DIR / "web"

# Live (running) scans only. Finished investigations are read from the database.
INVESTIGATIONS: Dict[str, ArgusEngine] = {}
SCAN_TASKS: Dict[str, "asyncio.Task[None]"] = {}


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


CONNECTIONS: Dict[str, Set[ClientConnection]] = {}


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
    await db.create_all()
    repo = InvestigationRepository(db)
    interrupted = await repo.mark_interrupted()
    if interrupted:
        logger.warning("Marked %d interrupted investigation(s) as failed", interrupted)

    app.state.settings, app.state.db, app.state.repo = settings, db, repo
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


app = FastAPI(
    title="Argus OSINT Platform API",
    description="REST & WebSocket API for Argus Reconnaissance & Relationship Graphing",
    version="1.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_repo(request: Request) -> InvestigationRepository:
    return request.app.state.repo


# --------------------------------------------------------------------------- helpers
class StartScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    target_type: Optional[EntityType] = None
    max_depth: int = Field(default=2, ge=0, le=4)
    enabled_modules: Optional[List[str]] = None
    concurrency_limit: int = Field(default=15, ge=1, le=50)


def _live_investigation(engine: ArgusEngine) -> Investigation:
    """The engine's Investigation with live counters/stats filled in."""
    inv = engine.investigation
    if engine.is_running:
        inv = inv.model_copy(update={
            "node_count": engine.graph.node_count,
            "edge_count": engine.graph.edge_count,
            "truncated": engine.truncated,
            "module_stats": {n: s.as_dict() for n, s in engine.module_stats.items()},
            "http_stats": engine.http.stats.as_dict() if engine.http else {},
        })
    return inv


def _investigation_payload(inv: Investigation) -> Dict[str, Any]:
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


def _on_scan_done(task: "asyncio.Task[None]") -> None:
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
async def list_modules():
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
    status: Optional[InvestigationStatus] = None,
    target: Optional[str] = Query(None, max_length=253),
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
async def start_scan(req: StartScanRequest, request: Request):
    """Initiate a new reconnaissance scan in the background."""
    from argus.cli.console import detect_target_type

    target = req.target.strip()
    if not target:
        raise HTTPException(status_code=422, detail="Target must not be blank")
    if req.enabled_modules:
        unknown = set(req.enabled_modules) - set(get_default_modules())
        if unknown:
            raise HTTPException(status_code=422, detail=f"Unknown modules: {sorted(unknown)}")

    ttype = req.target_type or detect_target_type(target)
    try:
        config = ScanConfig(
            target=target,
            target_type=ttype,
            max_depth=req.max_depth,
            enabled_modules=req.enabled_modules,
            concurrency_limit=req.concurrency_limit,
        )
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors(include_url=False)) from exc

    repo = get_repo(request)
    engine = ArgusEngine(config)
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

    return {
        "status": "launched",
        "investigation_id": engine.investigation_id,
        "target": target,
        "target_type": ttype.value,
    }


@app.get("/api/investigation/{inv_id}")
async def get_investigation(inv_id: str, request: Request):
    """Status, summary metrics and execution telemetry of an investigation."""
    return _investigation_payload(await _resolve(inv_id, get_repo(request)))


@app.post("/api/investigation/{inv_id}/cancel")
async def cancel_investigation(inv_id: str, request: Request):
    """Request cooperative cancellation of a running investigation."""
    engine = INVESTIGATIONS.get(inv_id)
    if engine is None or not engine.is_running:
        inv = await _resolve(inv_id, get_repo(request))  # 404 if unknown
        raise HTTPException(status_code=409, detail=f"Investigation is {inv.status.value}")
    engine.cancel()
    return {"status": "cancelling", "investigation_id": inv_id}


@app.delete("/api/investigation/{inv_id}", status_code=204)
async def delete_investigation(inv_id: str, request: Request):
    """Permanently delete an investigation and all of its findings."""
    if inv_id in INVESTIGATIONS:
        raise HTTPException(status_code=409, detail="Investigation is running; cancel it first")
    if not await get_repo(request).delete_investigation(inv_id):
        raise HTTPException(status_code=404, detail="Investigation not found")
    return Response(status_code=204)


@app.get("/api/investigation/{inv_id}/graph")
async def get_investigation_graph(inv_id: str, request: Request):
    """Retrieve full Cytoscape-formatted graph elements."""
    graph = await _resolve_graph(inv_id, get_repo(request))
    return {
        "investigation_id": inv_id,
        "elements": graph.to_cytoscape_elements(),
        "analytics": GraphIntelligenceAnalyzer.analyze(graph),
    }


@app.get("/api/investigation/{inv_id}/export/json")
async def export_graph_json(inv_id: str, request: Request):
    """Export complete graph as JSON."""
    return (await _resolve_graph(inv_id, get_repo(request))).to_dict()


@app.get("/api/investigation/{inv_id}/export/csv")
async def export_graph_csv(inv_id: str, request: Request):
    """Export relationships in Maltego-compatible CSV format."""
    graph = await _resolve_graph(inv_id, get_repo(request))
    return PlainTextResponse(
        graph.to_maltego_csv(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=argus_{inv_id}_maltego.csv"},
    )


@app.get("/api/entities/search")
async def search_entities(
    request: Request,
    q: str = Query(min_length=2, max_length=253, description="Substring of the entity value"),
    type: Optional[EntityType] = None,
    limit: int = Query(50, ge=1, le=500),
):
    """Cross-investigation pivot: every investigation in which a value has been seen."""
    return await get_repo(request).search_entities(q, type.value if type else None, limit)


# --------------------------------------------------------------------------- WebSocket
@app.websocket("/ws/stream/{inv_id}")
async def websocket_stream(websocket: WebSocket, inv_id: str):
    """Snapshot of everything found so far, followed by live events."""
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

    pump = asyncio.create_task(conn.pump())
    receiver = asyncio.create_task(_drain_client(websocket))
    dead = asyncio.create_task(conn.dead.wait())
    try:
        await asyncio.wait({pump, receiver, dead}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in (pump, receiver, dead):
            t.cancel()
        await asyncio.gather(pump, receiver, dead, return_exceptions=True)
        conns = CONNECTIONS.get(inv_id)
        if conns is not None:
            conns.discard(conn)
            if not conns:
                CONNECTIONS.pop(inv_id, None)
        try:
            await websocket.close()
        except Exception:
            pass


async def _drain_client(websocket: WebSocket) -> None:
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        return


def _snapshot_message(inv: Investigation, graph: IntelligenceGraph) -> str:
    return json.dumps({
        "type": "snapshot",
        "investigation_id": inv.id,
        "data": {
            "investigation": _investigation_payload(inv),
            "analytics": inv.analytics,
            "entities": [e.model_dump(mode="json") for e in graph.get_all_entities()],
            "relations": [r.model_dump(mode="json") for r in graph.get_all_relations()],
        },
    })


# --------------------------------------------------------------------------- static UI
if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def serve_index():
        index_file = WEB_DIR / "index.html"
        if index_file.exists():
            return HTMLResponse(content=index_file.read_text(encoding="utf-8"))
        return HTMLResponse("<h3>Argus Web UI Loading...</h3>")
