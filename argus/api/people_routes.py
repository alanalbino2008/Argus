"""People in a case: bring them in from scans, and see everything known about one of them.

* ``GET /api/cases/{id}/scan-people?investigation_id=...``: what a linked scan found that could
  join the case (people, organisations, accounts, contacts, places, and how they relate);
* ``POST /api/cases/{id}/scan-people``: add the chosen ones, and the relationships between them;
* ``GET /api/cases/{id}/entities/{item}/profile``: one person's (or organisation's) profile.

When a scan linked to a case finishes, the people and organisations it is fairly sure of are added
automatically (:func:`auto_import`), each noting the scan it came from; nothing is added twice.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from argus.api.analyst_routes import case_documents
from argus.api.case_routes import _case
from argus.api.deps import WorkspaceContext, audit, in_workspace
from argus.api.network_routes import ExportRequest, chart_image, pdf_response
from argus.intel.dossier import build_profile
from argus.intel.people_import import as_case_items, automatic, proposals
from argus.intel.relationships import analyse, entity_nodes, link_edges
from argus.reports.case_pdf import profile_pdf
from argus.security.auth import Principal, Role

logger = logging.getLogger("argus.people")
router = APIRouter(prefix="/api", tags=["people"])
VIEWER = Depends(in_workspace(Role.VIEWER))
ANALYST = Depends(in_workspace(Role.ANALYST))


class ImportRequest(BaseModel):
    investigation_id: str = Field(max_length=64)
    keys: list[str] = Field(max_length=500, description="The scan's entity ids to add")
    relationships: bool = Field(default=True, description="Also add the relationships between them")


def _linked_scans(items: list[dict[str, Any]]) -> list[str]:
    return list(dict.fromkeys(str(i["data"].get("investigation_id")) for i in items
                              if i["kind"] == "scan" and i["data"].get("investigation_id")))  # fmt: skip


async def _scan(app: Any, workspace_id: str, items: list[dict[str, Any]], investigation_id: str) -> tuple[Any, str]:
    if investigation_id not in _linked_scans(items):
        raise HTTPException(status_code=404, detail="That scan is not linked to this case")
    inv = await app.state.repo.get_investigation(investigation_id)
    graph = await app.state.repo.load_graph(investigation_id) if inv and inv.workspace_id == workspace_id else None
    if inv is None or graph is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return graph, inv.config.target


async def add_found(app: Any, case_id: str, chosen: dict[str, Any], *, by: str, scan_id: str,
                    scan_label: str) -> dict[str, int]:  # fmt: skip
    """Create the chosen entries and relationships; returns how many of each were added."""
    repo = app.state.cases
    entity_bodies, link_bodies = as_case_items(chosen, scan_id=scan_id, scan_label=scan_label)
    ids = {p["key"]: p["existing"] for p in chosen.get("all", chosen["entities"]) if p.get("existing")}
    for body in entity_bodies:
        key = body.pop("key")
        item = await repo.add_item(case_id, by=by, kind="entity", title=body["title"][:300], body=body["body"],
                                   data=body["data"], occurred_at=None)  # fmt: skip
        ids[key] = item["id"]
    added_links = 0
    for body in link_bodies:
        data = body["data"]
        if data["from"] not in ids or data["to"] not in ids or ids[data["from"]] == ids[data["to"]]:
            continue
        data["from"], data["to"] = ids[data["from"]], ids[data["to"]]
        await repo.add_item(case_id, by=by, kind="link", title="", body="", data=data, occurred_at=None)
        added_links += 1
    return {"entities": len(entity_bodies), "relationships": added_links}


async def auto_import(app: Any, case_id: str, investigation_id: str, principal: Principal, workspace_id: str) -> None:
    """After a linked scan: add the people and organisations it is fairly sure of."""
    try:
        items = await app.state.cases.items(case_id)
        graph = await app.state.repo.load_graph(investigation_id)
        inv = await app.state.repo.get_investigation(investigation_id)
        if graph is None or inv is None:
            return
        found = proposals(graph, items, scan_label=inv.config.target)
        chosen = {**automatic(found), "all": found["entities"]}
        if not chosen["entities"] and not chosen["relationships"]:
            return
        counts = await add_found(app, case_id, chosen, by=principal.name, scan_id=investigation_id,
                                 scan_label=inv.config.target)  # fmt: skip
        await app.state.audit.record(principal, "case.import_people", case_id, "success", None,
                                     {"scan": investigation_id, "automatic": True, **counts}, workspace_id)  # fmt: skip
    except Exception:
        logger.exception("Could not add the people found by scan %s to case %s", investigation_id, case_id)


@router.get("/cases/{case_id}/scan-people")
async def scan_people(
    case_id: str, request: Request, investigation_id: str | None = None, ws: WorkspaceContext = VIEWER
):
    """What linked scans found that could join the case. Without ``investigation_id``: the list of scans."""
    await _case(request, ws, case_id)
    items = await request.app.state.cases.items(case_id)
    if not investigation_id:
        scans = []
        for inv_id in _linked_scans(items):
            inv = await request.app.state.repo.get_investigation(inv_id)
            if inv and inv.workspace_id == ws.id:
                scans.append({"investigation_id": inv_id, "target": inv.config.target, "status": inv.status.value})
        return {"scans": scans}
    graph, label = await _scan(request.app, ws.id, items, investigation_id)
    return {"investigation_id": investigation_id, "target": label, **proposals(graph, items, scan_label=label)}


@router.post("/cases/{case_id}/scan-people", status_code=201)
async def import_scan_people(case_id: str, body: ImportRequest, request: Request, ws: WorkspaceContext = ANALYST):
    await _case(request, ws, case_id)
    items = await request.app.state.cases.items(case_id)
    graph, label = await _scan(request.app, ws.id, items, body.investigation_id)
    found = proposals(graph, items, scan_label=label)
    wanted = set(body.keys)
    entities = [p for p in found["entities"] if p["key"] in wanted and not p["existing"]]
    chosen_keys = {p["key"] for p in entities} | {p["key"] for p in found["entities"] if p["existing"]}
    rels = [r for r in found["relationships"] if r["from"] in chosen_keys and r["to"] in chosen_keys
            and (r["from"] in wanted or r["to"] in wanted)] if body.relationships else []  # fmt: skip
    counts = await add_found(request.app, case_id, {"entities": entities, "relationships": rels, "all": found["entities"]},
                             by=ws.principal.name, scan_id=body.investigation_id, scan_label=label)  # fmt: skip
    await audit(request, ws.principal, "case.import_people", case_id,
                details={"scan": body.investigation_id, "automatic": False, **counts})  # fmt: skip
    return counts


async def _profile(request: Request, ws: WorkspaceContext, case_id: str, item_id: str) -> dict[str, Any]:
    await _case(request, ws, case_id)
    items = await request.app.state.cases.items(case_id)
    if not any(i["id"] == item_id and i["kind"] == "entity" for i in items):
        raise HTTPException(status_code=404, detail="Entity not found in this case")
    graphs = []
    for inv_id in _linked_scans(items)[-10:]:
        inv = await request.app.state.repo.get_investigation(inv_id)
        if inv and inv.workspace_id == ws.id:
            graph = await request.app.state.repo.load_graph(inv_id)
            if graph is not None:
                graphs.append((inv_id, inv.config.target, graph))
    documents = await case_documents(request.app, case_id)
    nodes = entity_nodes(items)
    analysis = analyse(nodes, link_edges(items, nodes))
    return build_profile(items, item_id, documents, graphs, nodes, analysis)


@router.get("/cases/{case_id}/entities/{item_id}/profile")
async def entity_profile(case_id: str, item_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Everything the case knows about one person or organisation."""
    profile = await _profile(request, ws, case_id, item_id)
    await audit(request, ws.principal, "case.profile_view", case_id, details={"entity": item_id})
    return profile


@router.post("/cases/{case_id}/entities/{item_id}/profile.pdf")
async def entity_profile_pdf(case_id: str, item_id: str, body: ExportRequest, request: Request,
                             ws: WorkspaceContext = VIEWER):  # fmt: skip
    """A person's profile as a PDF (with their part of the link chart, when the browser sends it)."""
    case = await _case(request, ws, case_id)
    profile = await _profile(request, ws, case_id, item_id)
    data = profile_pdf(profile, case, None if profile.get("protected") else chart_image(body.chart_png))
    await audit(request, ws.principal, "case.export_profile", case_id, details={"entity": item_id, "bytes": len(data)})
    return pdf_response(data, f"argus-profile-{item_id}.pdf")
