"""Importing lawfully obtained data into a case: call records, statements, contact lists, phone extractions.

The file is kept as case evidence (fingerprinted, with its chain of custody) together with the records read
from it (``records.json``, covered by the same digest), and its records are cross-referenced with what the
case already holds: the phone numbers, addresses, usernames and names of its entities and of the people
researched on its People tab. Because these files hold other people's communications and money, a case
must record its legal authorisation before anything can be imported, and every import and every reading
of one is audited.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any

import anyio
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile

from argus.api.case_routes import _case, _repo
from argus.api.deps import WorkspaceContext, audit, in_workspace
from argus.evidence.capture import Capture, build, trusted_timestamp
from argus.intel import imports as I
from argus.security.auth import Role

router = APIRouter(prefix="/api", tags=["cases"])
VIEWER = Depends(in_workspace(Role.VIEWER))
ANALYST = Depends(in_workspace(Role.ANALYST))
LABELS = {
    "cdr": "Call records",
    "transactions": "Transactions",
    "contacts": "Contact list",
    "ufdr": "Phone extraction (UFDR)",
}


@router.post("/cases/{case_id}/imports", status_code=201)
async def import_data(case_id: str, request: Request, file: UploadFile = File(...), kind: str = Form("auto"),
                      note: str = Form(""), ws: WorkspaceContext = ANALYST):  # fmt: skip
    """Import call records, a statement, a contact list or a UFDR phone extraction into the case."""
    case = await _case(request, ws, case_id)
    if case["status"] != "open":
        raise HTTPException(status_code=409, detail="Reopen the case to import into it")
    if not (case.get("authorization") or "").strip():
        raise HTTPException(status_code=409, detail="Record the case's legal authorisation first (Edit the case): "
                                                    "these files hold other people's communications and money")  # fmt: skip
    if kind not in I.KINDS:
        raise HTTPException(status_code=422, detail=f"Kind must be one of: {', '.join(I.KINDS)}")
    settings = request.app.state.settings
    limit = settings.evidence_max_upload_mb * 1024 * 1024
    data = await file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(status_code=413, detail=f"Files up to {limit // (1024 * 1024)} MB can be imported")
    if not data:
        raise HTTPException(status_code=422, detail="The file is empty")
    name = os.path.basename(file.filename or "import.csv").replace("\x00", "")[:200] or "import.csv"
    try:
        read_kind, records = await anyio.to_thread.run_sync(lambda: I.parse(data, name, kind))
    except I.ImportError_ as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"The file could not be read ({type(exc).__name__})") from exc
    if not records:
        raise HTTPException(status_code=422, detail="No records were found in the file")
    summary = {"kind": read_kind, "label": LABELS[read_kind], "records": len(records), "filename": name}
    files = {name: (file.content_type or "application/octet-stream", data),
             "records.json": ("application/json", json.dumps(records, separators=(",", ":")).encode())}  # fmt: skip
    manifest, digest = build({"kind": "upload", "original_filename": name, "method": "import", "note": note[:500],
                              "captured_at": datetime.now(timezone.utc).isoformat(), "data_import": summary}, files)  # fmt: skip
    warnings: list[str] = []
    token = None
    try:
        token = await trusted_timestamp(digest, settings)
    except Exception as exc:  # noqa: BLE001 - a timestamp is a bonus
        warnings.append(f"The timestamp authority did not answer ({type(exc).__name__})")
    stored = await _repo(request).add_capture(case_id, ws.id, Capture(manifest, digest, files, token, warnings),
                                              by=ws.principal.name, note=(note or f"Imported: {LABELS[read_kind]}")[:1000])  # fmt: skip
    await audit(request, ws.principal, "case.import", stored["id"],
                details={"case": case_id, "kind": read_kind, "records": len(records), "file": name,
                         "digest": stored["digest"], "authorization": case.get("authorization")})  # fmt: skip
    return {**stored, "data_import": summary}


@router.get("/cases/{case_id}/imports")
async def list_imports(case_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    await _case(request, ws, case_id)
    return [c for c in await _repo(request).captures(case_id) if c.get("data_import")]


async def _people(request: Request, case_id: str) -> list[dict[str, Any]]:
    subjects = request.app.state.subjects
    return [p for p in [await subjects.get(s["id"], case_id) for s in await subjects.for_case(case_id)] if p]


_RECORDS: dict[str, list[dict[str, Any]]] = {}  # evidence never changes: an import's records can be kept
MAX_CACHED = 20


async def import_records(app: Any, capture_id: str) -> list[dict[str, Any]]:
    if capture_id not in _RECORDS:
        stored = await app.state.cases.files(capture_id)
        _RECORDS[capture_id] = json.loads(stored.get("records.json", ("", b"[]"))[1] or b"[]")
        while len(_RECORDS) > MAX_CACHED:
            _RECORDS.pop(next(iter(_RECORDS)))
    return _RECORDS[capture_id]


async def case_import_analyses(app: Any, case_id: str) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Each import of the case with what it shows about the people and details the case holds."""
    imports = [c for c in await app.state.cases.captures(case_id) if c.get("data_import")]
    if not imports:
        return []
    subjects = app.state.subjects
    people = [p for p in [await subjects.get(s["id"], case_id) for s in await subjects.for_case(case_id)] if p]
    known = I.case_identifiers(await app.state.cases.items(case_id), people)
    out = []
    for capture in imports:
        records = await import_records(app, capture["id"])
        result: dict[str, Any] = await anyio.to_thread.run_sync(I.analyse, records, known)
        out.append((capture, result))
    return out


def timeline_entries(analyses: list[tuple[dict[str, Any], dict[str, Any]]]) -> list[dict[str, Any]]:
    """For the case timeline: when each known number, address or counterparty first and last appears in an import."""
    out = []
    for capture, result in analyses:
        label = capture["data_import"]["label"]
        for party in result["in_case"][:30]:
            where = "; ".join(m["where"] for m in party["in_case"][:2])
            for edge, title in (("first", "First"), ("last", "Last")):
                moment = party.get(edge)
                if not moment or (edge == "last" and moment == party.get("first")):
                    continue
                out.append({"at": datetime.fromisoformat(moment).isoformat(), "kind": "import",
                            "title": f"{title} of {party['count']} in {label}: {party['identifier']} ({where})",
                            "detail": capture["data_import"]["filename"], "by": capture.get("captured_by"),
                            "ref": {"type": "capture", "id": capture["id"]}})  # fmt: skip
    return out


@router.get("/cases/{case_id}/imports/{capture_id}")
async def read_import(case_id: str, capture_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Who appears most in the imported records, when, and which of them the case already holds."""
    case = await _case(request, ws, case_id)
    found = next(
        (c for c in await _repo(request).captures(case_id) if c["id"] == capture_id and c.get("data_import")), None
    )
    if found is None:
        raise HTTPException(status_code=404, detail="Import not found in this case")
    records = await import_records(request.app, capture_id)
    known = I.case_identifiers(await _repo(request).items(case_id), await _people(request, case_id))
    result = await anyio.to_thread.run_sync(lambda: I.analyse(records, known))
    await audit(request, ws.principal, "case.import_view", capture_id,
                details={"case": case_id, "authorization": case.get("authorization")})  # fmt: skip
    return {"import": found["data_import"], "evidence": {"id": capture_id, "digest": found["digest"]}, **result}


# ---------------------------------------------------------------------------- mobile cells on the map
CELL_RE = re.compile(r"^\s*(\d{3})[-:/ ](\d{2,3})[-:/ ](\d{1,8})[-:/ ](\d{1,10})\s*$")
MAX_CELLS = 50


def cell_ids(records: list[dict[str, Any]]) -> dict[tuple[str, str, str, str], dict[str, Any]]:
    """The cells named in call records as MCC-MNC-LAC-CI (a cell global identity), with how often and when used."""
    cells: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for r in records:
        match = CELL_RE.match(str(r.get("cell") or ""))
        if not match:
            continue
        mcc, mnc, lac, ci = match.groups()
        entry = cells.setdefault((mcc, mnc, lac, ci), {"count": 0, "first": None, "last": None})
        entry["count"] += 1
        if r.get("when"):
            entry["first"] = min(entry["first"] or r["when"], r["when"])
            entry["last"] = max(entry["last"] or r["when"], r["when"])
    return dict(sorted(cells.items(), key=lambda kv: -kv[1]["count"])[:MAX_CELLS])


@router.post("/cases/{case_id}/imports/{capture_id}/cells")
async def place_cells(case_id: str, capture_id: str, request: Request, ws: WorkspaceContext = ANALYST):
    """Put the mobile cells used in imported call records on the case map, as approximate areas (OpenCellID)."""
    from argus.api.opsec_routes import route_for
    from argus.intel.account_watch import client

    case = await _case(request, ws, case_id)
    if case["status"] != "open":
        raise HTTPException(status_code=409, detail="Reopen the case to change it")
    settings = request.app.state.settings
    key = settings.opencellid_api_key.get_secret_value() if settings.opencellid_api_key else ""
    if not key:
        raise HTTPException(
            status_code=409, detail="Set an OpenCellID key (ARGUS_OPENCELLID_API_KEY) to place cells on the map"
        )
    found = next(
        (c for c in await _repo(request).captures(case_id) if c["id"] == capture_id and c.get("data_import")), None
    )
    if found is None or found["data_import"]["kind"] not in ("cdr", "ufdr"):
        raise HTTPException(status_code=404, detail="Call records not found in this case")
    cells = cell_ids(await import_records(request.app, capture_id))
    if not cells:
        raise HTTPException(status_code=422, detail="No cell identities (MCC-MNC-LAC-CI) were found in these records")
    route = route_for(settings, case, None)
    existing = {str((i.get("data") or {}).get("value")) for i in await _repo(request).items(case_id)}
    placed, unknown = 0, 0
    async with client(settings, route) as http:
        for (mcc, mnc, lac, ci), use in cells.items():
            label = f"Cell {mcc}-{mnc}-{lac}-{ci}"
            if label in existing:
                continue
            params = {"key": key, "mcc": mcc, "mnc": mnc, "lac": lac, "cellid": ci, "format": "json"}
            async with http.get("https://opencellid.org/cell/get", params=params) as resp:
                data = await resp.json(content_type=None) if resp.status == 200 else {}
            if not isinstance(data, dict) or data.get("lat") is None or data.get("lon") is None:
                unknown += 1
                continue
            await _repo(request).add_item(case_id, by=ws.principal.name, kind="entity", title=label,
                body=(f"Approximate area of a mobile cell (about {int(data.get('range') or 0)} m) used {use['count']} "
                      f"time(s) in {found['data_import']['filename']}, {use['first'] or '?'} to {use['last'] or '?'}. "
                      "A cell covers an area, not an address."),
                data={"type": "location", "value": label, "attributes": {
                    "lat": float(data["lat"]), "lon": float(data["lon"]), "range_m": data.get("range"),
                    "geocoded_by": "OpenCellID", "source": capture_id}}, occurred_at=None)  # fmt: skip
            placed += 1
    await audit(request, ws.principal, "case.import_cells", capture_id,
                details={"case": case_id, "placed": placed, "unknown": unknown, "route": route.name if route else "direct"})  # fmt: skip
    return {"placed": placed, "unknown": unknown, "cells": len(cells)}
