"""FastAPI backend server with WebSocket real-time graph telemetry."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from argus.core.engine import ArgusEngine
from argus.core.events import Event, EventType, event_bus
from argus.core.models import EntityType, Investigation, InvestigationStatus, ScanConfig
from argus.modules import get_default_modules
from argus.modules.analytics.graph_analyzer import GraphIntelligenceAnalyzer

logger = logging.getLogger("argus.api")

app = FastAPI(
    title="Argus OSINT Platform API",
    description="REST & WebSocket API for Argus Reconnaissance & Relationship Graphing",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage of active engines & investigations
INVESTIGATIONS: Dict[str, ArgusEngine] = {}
ACTIVE_WEBSOCKETS: Dict[str, List[WebSocket]] = {}

# Directory paths
BASE_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = BASE_DIR / "web"


class StartScanRequest(BaseModel):
    target: str
    target_type: Optional[EntityType] = None
    max_depth: int = 2
    enabled_modules: Optional[List[str]] = None
    concurrency_limit: int = 15


@app.on_event("startup")
async def startup_event():
    """Register global event listener to pipe events into WebSockets."""
    async def global_ws_dispatcher(event: Event):
        inv_id = event.investigation_id
        sockets = ACTIVE_WEBSOCKETS.get(inv_id, [])
        if not sockets:
            return

        payload = event.model_dump(mode="json")
        payload_str = json.dumps(payload)

        dead_sockets = []
        for ws in sockets:
            try:
                await ws.send_text(payload_str)
            except Exception:
                dead_sockets.append(ws)

        for ws in dead_sockets:
            if ws in sockets:
                sockets.remove(ws)

    event_bus.subscribe_all(global_ws_dispatcher)


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

    ttype = req.target_type or detect_target_type(req.target)
    config = ScanConfig(
        target=req.target.strip(),
        target_type=ttype,
        max_depth=req.max_depth,
        enabled_modules=req.enabled_modules,
        concurrency_limit=req.concurrency_limit,
    )

    engine = ArgusEngine(config)
    INVESTIGATIONS[engine.investigation_id] = engine

    # Run engine in background task
    asyncio.create_task(engine.start())

    return {
        "status": "launched",
        "investigation_id": engine.investigation_id,
        "target": req.target,
        "target_type": ttype.value,
    }


@app.get("/api/investigation/{inv_id}")
async def get_investigation(inv_id: str):
    """Get status and summary metrics of an investigation."""
    engine = INVESTIGATIONS.get(inv_id)
    if not engine:
        raise HTTPException(status_code=404, detail="Investigation not found")

    return {
        "id": engine.investigation_id,
        "status": engine.investigation.status.value,
        "target": engine.config.target,
        "target_type": engine.config.target_type.value,
        "node_count": engine.graph.node_count,
        "edge_count": engine.graph.edge_count,
        "errors": engine.investigation.errors,
    }


@app.get("/api/investigation/{inv_id}/graph")
async def get_investigation_graph(inv_id: str):
    """Retrieve full Cytoscape-formatted graph elements."""
    engine = INVESTIGATIONS.get(inv_id)
    if not engine:
        raise HTTPException(status_code=404, detail="Investigation not found")

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
    engine = INVESTIGATIONS.get(inv_id)
    if not engine:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return engine.graph.to_dict()


@app.get("/api/investigation/{inv_id}/export/csv")
async def export_graph_csv(inv_id: str):
    """Export relationships in Maltego-compatible CSV format."""
    engine = INVESTIGATIONS.get(inv_id)
    if not engine:
        raise HTTPException(status_code=404, detail="Investigation not found")
    csv_data = engine.graph.to_maltego_csv()
    return PlainTextResponse(
        csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=argus_{inv_id}_maltego.csv"},
    )


@app.websocket("/ws/stream/{inv_id}")
async def websocket_stream(websocket: WebSocket, inv_id: str):
    """Live WebSocket feed streaming discovered entities and relations."""
    await websocket.accept()

    if inv_id not in ACTIVE_WEBSOCKETS:
        ACTIVE_WEBSOCKETS[inv_id] = []
    ACTIVE_WEBSOCKETS[inv_id].append(websocket)

    try:
        # Keep connection open until client disconnects
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in ACTIVE_WEBSOCKETS.get(inv_id, []):
            ACTIVE_WEBSOCKETS[inv_id].remove(websocket)


# Mount static web UI files
if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def serve_index():
        index_file = WEB_DIR / "index.html"
        if index_file.exists():
            return HTMLResponse(content=index_file.read_text(encoding="utf-8"))
        return HTMLResponse("<h3>Argus Web UI Loading...</h3>")
