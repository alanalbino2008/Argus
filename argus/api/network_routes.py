"""A case's network of people and organisations: the link chart, paths between people, suggestions.

* ``GET /api/cases/{id}/network``: every entity and link, with each link's kind, and the network
  analysis (key people, people who bridge groups, the groups, entities not yet connected);
* ``GET /api/cases/{id}/network/path?source=...&target=...``: the best-supported chain of links
  between two entities, and the connections they share;
* ``GET /api/cases/{id}/network/suggestions``: relationships the case's material shows but that
  are not linked yet (from linked scans, shared details, recorded employers, notes and evidence).
  The investigator adds the ones they accept as ordinary links.

Protected people (for example children) appear only as "Protected person" and never in
suggestions.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from argus.api.analyst_routes import case_documents
from argus.api.case_routes import _case
from argus.api.deps import WorkspaceContext, audit, in_workspace
from argus.intel.relationships import GROUPS, KINDS, analyse, discover, edges_at, entity_nodes, link_edges, path
from argus.reports.case_pdf import clean_chart, network_pdf
from argus.security.auth import Role

router = APIRouter(prefix="/api", tags=["network"])
VIEWER = Depends(in_workspace(Role.VIEWER))
MAX_SCANS = 10  # linked scans read for suggestions (the most recent)


async def _network(request: Request, ws: WorkspaceContext, case_id: str) -> tuple[list[Any], dict[str, Any], list[Any]]:
    await _case(request, ws, case_id)
    items = await request.app.state.cases.items(case_id)
    nodes = entity_nodes(items)
    return items, nodes, link_edges(items, nodes)


@router.get("/relationship-kinds")
async def relationship_kinds(ws: WorkspaceContext = VIEWER):
    return {"groups": list(GROUPS),
            "kinds": [{"kind": k, "group": g, "label": label, "symmetric": sym} for k, (g, label, sym) in KINDS.items()]}  # fmt: skip


@router.get("/cases/{case_id}/network")
async def case_network(case_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """The case's entities and links, and what the network's shape says."""
    _items, nodes, edges = await _network(request, ws, case_id)
    analysis = analyse(nodes, edges)
    return {"nodes": list(nodes.values()), "edges": edges, "analysis": analysis, "groups": list(GROUPS)}


class ExportRequest(BaseModel):
    chart_png: str | None = Field(default=None, max_length=12_000_000, description="The link chart as a PNG data URL")
    as_of: str | None = Field(
        default=None, pattern=r"^\d{4}(-\d{2}(-\d{2})?)?$", description="The network on this date"
    )


def chart_image(value: str | None) -> bytes | None:
    if not value:
        return None
    payload = value.split(",", 1)[1] if value.startswith("data:") else value
    try:
        return clean_chart(base64.b64decode(payload, validate=True))
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"The chart picture could not be used: {exc}") from exc


def pdf_response(data: bytes, filename: str) -> Response:
    return Response(data, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"})  # fmt: skip


@router.post("/cases/{case_id}/network.pdf")
async def network_report(case_id: str, body: ExportRequest, request: Request, ws: WorkspaceContext = VIEWER):
    """The case's network as a PDF: the chart, key people, go-betweens, groups, and every relationship."""
    case = await _case(request, ws, case_id)
    _items, nodes, edges = await _network(request, ws, case_id)
    if body.as_of:
        edges = edges_at(edges, body.as_of)
    network = {"nodes": list(nodes.values()), "edges": edges, "analysis": analyse(nodes, edges)}
    data = network_pdf(network, case, chart_image(body.chart_png), as_of=body.as_of)
    await audit(request, ws.principal, "case.export_network", case_id,
                details={"relationships": len(edges), "as_of": body.as_of, "bytes": len(data)})  # fmt: skip
    return pdf_response(data, f"argus-network-{case_id}.pdf")


@router.get("/cases/{case_id}/network/path")
async def case_path(case_id: str, request: Request, source: str = Query(max_length=64),
                    target: str = Query(max_length=64), ws: WorkspaceContext = VIEWER):  # fmt: skip
    """How two entities are connected: the best-supported chain of links, and shared connections."""
    _items, nodes, edges = await _network(request, ws, case_id)
    if source not in nodes or target not in nodes:
        raise HTTPException(status_code=404, detail="Both ends must be entities of this case")
    return path(nodes, edges, source, target)


@router.get("/cases/{case_id}/network/suggestions")
async def case_suggestions(case_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Relationships the material shows that are not linked yet. Nothing is added automatically."""
    items, nodes, _edges = await _network(request, ws, case_id)
    scans = [
        i["data"].get("investigation_id") for i in items if i["kind"] == "scan" and i["data"].get("investigation_id")
    ]
    graphs = []
    for inv_id in list(dict.fromkeys(reversed(scans)))[:MAX_SCANS]:
        inv = await request.app.state.repo.get_investigation(inv_id)
        if inv is None or inv.workspace_id != ws.id:
            continue
        graph = await request.app.state.repo.load_graph(inv_id)
        if graph is not None:
            graphs.append(graph)
    documents = [
        {"title": i["title"], "text": f"{i['title']}\n{i.get('body') or ''}"} for i in items if i["kind"] == "note"
    ]
    documents += [d for d in await case_documents(request.app, case_id) if d.get("text")]
    suggestions = discover(items, graphs, documents)
    for s in suggestions:
        s["from_label"], s["to_label"] = nodes[s["from"]]["label"], nodes[s["to"]]["label"]
    return {"suggestions": suggestions[:100], "scans_read": len(graphs), "documents_read": len(documents)}
