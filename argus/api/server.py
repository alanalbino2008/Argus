"""FastAPI backend server with WebSocket real-time graph telemetry."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError

from argus.core.engine import ArgusEngine
from argus.core.events import Event, EventType, event_bus
from argus.core.models import EntityType, ScanConfig
from argus.modules import get_default_modules
from argus.modules.analytics.graph_analyzer import GraphIntelligenceAnalyzer

logger = logging.getLogger("argus.api")

# In-memory storage of active engines & investigations
INVESTIGATIONS: Dict[str, ArgusEngine] = {}
SCAN_TASKS: Dict[str, "asyncio.Task[object]"] = {}
ACTIVE_WEBSOCKETS: Dict[str, List[WebSocket]] = {}


async def global_ws_dispatcher(event: Event):
    """Pipe every engine event to the WebSocket clients watching that investigation."""
    sockets = ACTIVE_WEBSOCKETS.get(event.investigation_id, [])
    if not sockets:
        return
    payload_str = json.dumps(event.model_dump(mode="json"))
    for ws in list(sockets):
        try:
            await ws.send_text(payload_str)
        except Exception:
            if ws in sockets:
                sockets.remove(ws)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    event_bus.subscribe_all(global_ws_dispatcher)
    try:
        yield
    finally:
        event_bus.unsubscribe_all(global_ws_dispatcher)
        for engine in INVESTIGATIONS.values():
            engine.cancel()
        pending = [t for t in SCAN_TASKS.values() if not t.done()]
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)


app = FastAPI(
    title="Argus OSINT Platform API",
    description="REST & WebSocket API for Argus Reconnaissance & Relationship Graphing",
    version="1.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Directory paths
BASE_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = BASE_DIR / "web"


class StartScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    target_type: Optional[EntityType] = None
    max_depth: int = Field(default=2, ge=0, le=4)
    enabled_modules: Optional[List[str]] = None
    concurrency_limit: int = Field(default=15, ge=1, le=50)


def _get_engine(inv_id: str) -> ArgusEngine:
    engine = INVESTIGATIONS.get(inv_id)
    if not engine:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return engine


def _on_scan_done(task: "asyncio.Task[object]") -> None:
    """Consume the task result so failures are logged instead of silently lost."""
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.error("Scan task %s failed: %r", task.get_name(), exc)


@app.get("/api/modules")
async def list_modules():
    """Return list of available OSINT reconnaissance modules."""
    mods = get_default_modules()
    return [
        {
            "name": m.name,
            "description": m.description,
            "supported_types": [t.value for t in m.supported_entity_types],
        }
        for m in mods.values()
    ]


@app.get("/api/investigations")
async def list_investigations():
    """List all registered investigations."""
    return [
        {
            "id": eng.investigation_id,
            "name": eng.investigation.name,
            "status": eng.investigation.status.value,
            "target": eng.config.target,
            "target_type": eng.config.target_type.value,
            "nodes_count": eng.graph.node_count,
            "edges_count": eng.graph.edge_count,
            "created_at": eng.investigation.created_at.isoformat(),
        }
        for eng in INVESTIGATIONS.values()
    ]


@app.post("/api/scan")
async def start_scan(req: StartScanRequest):
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

    engine = ArgusEngine(config)
    INVESTIGATIONS[engine.investigation_id] = engine

    # Keep a strong reference to the task (asyncio only holds weak refs) and log failures.
    task = asyncio.create_task(engine.start(), name=f"scan-{engine.investigation_id}")
    task.add_done_callback(_on_scan_done)
    SCAN_TASKS[engine.investigation_id] = task

    return {
        "status": "launched",
        "investigation_id": engine.investigation_id,
        "target": req.target,
        "target_type": ttype.value,
    }


@app.get("/api/investigation/{inv_id}")
async def get_investigation(inv_id: str):
    """Get status, summary metrics and execution telemetry of an investigation."""
    engine = _get_engine(inv_id)
    inv = engine.investigation
    return {
        "id": engine.investigation_id,
        "status": engine.investigation.status.value,
        "target": engine.config.target,
        "target_type": engine.config.target_type.value,
        "node_count": engine.graph.node_count,
        "edge_count": engine.graph.edge_count,
        "truncated": engine.truncated,
        "errors": inv.errors,
        "warnings": inv.warnings,
        "module_stats": inv.module_stats or {n: s.as_dict() for n, s in engine.module_stats.items()},
        "http_stats": inv.http_stats or (engine.http.stats.as_dict() if engine.http else {}),
        "created_at": inv.created_at.isoformat(),
        "completed_at": inv.completed_at.isoformat() if inv.completed_at else None,
    }


@app.post("/api/investigation/{inv_id}/cancel")
async def cancel_investigation(inv_id: str):
    """Request cooperative cancellation of a running investigation."""
    engine = _get_engine(inv_id)
    if not engine.is_running:
        raise HTTPException(status_code=409, detail=f"Investigation is {engine.investigation.status.value}")
    engine.cancel()
    return {"status": "cancelling", "investigation_id": inv_id}


@app.get("/api/investigation/{inv_id}/graph")
async def get_investigation_graph(inv_id: str):
    """Retrieve full Cytoscape-formatted graph elements."""
    engine = _get_engine(inv_id)

    elements = engine.graph.to_cytoscape_elements()
    analytics = GraphIntelligenceAnalyzer.analyze(engine.graph)

    return {
        "investigation_id": inv_id,
        "elements": elements,
        "analytics": analytics,
    }


@app.get("/api/investigation/{inv_id}/export/json")
async def export_graph_json(inv_id: str):
    """Export complete graph as JSON."""
    engine = _get_engine(inv_id)
    return engine.graph.to_dict()


@app.get("/api/investigation/{inv_id}/export/csv")
async def export_graph_csv(inv_id: str):
    """Export relationships in Maltego-compatible CSV format."""
    engine = _get_engine(inv_id)
    csv_data = engine.graph.to_maltego_csv()
    return PlainTextResponse(
        csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=argus_{inv_id}_maltego.csv"},
    )


@app.websocket("/ws/stream/{inv_id}")
async def websocket_stream(websocket: WebSocket, inv_id: str):
    """Live WebSocket feed streaming discovered entities and relations."""
    if inv_id not in INVESTIGATIONS:
        await websocket.close(code=4404)
        return
    await websocket.accept()
    ACTIVE_WEBSOCKETS.setdefault(inv_id, []).append(websocket)

    try:
        # Keep connection open until client disconnects
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        sockets = ACTIVE_WEBSOCKETS.get(inv_id, [])
        if websocket in sockets:
            sockets.remove(websocket)
        if not sockets:
            ACTIVE_WEBSOCKETS.pop(inv_id, None)


# Mount static web UI files
if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def serve_index():
        index_file = WEB_DIR / "index.html"
        if index_file.exists():
            return HTMLResponse(content=index_file.read_text(encoding="utf-8"))
        return HTMLResponse("<h3>Argus Web UI Loading...</h3>")
