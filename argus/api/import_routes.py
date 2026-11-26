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


@router.get("/cases/{case_id}/imports/{capture_id}")
async def read_import(case_id: str, capture_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Who appears most in the imported records, when, and which of them the case already holds."""
    case = await _case(request, ws, case_id)
    found = next(
        (c for c in await _repo(request).captures(case_id) if c["id"] == capture_id and c.get("data_import")), None
    )
    if found is None:
        raise HTTPException(status_code=404, detail="Import not found in this case")
    stored = await _repo(request).files(capture_id)
    records = json.loads(stored.get("records.json", ("", b"[]"))[1] or b"[]")
    known = I.case_identifiers(await _repo(request).items(case_id), await _people(request, case_id))
    result = await anyio.to_thread.run_sync(lambda: I.analyse(records, known))
    await audit(request, ws.principal, "case.import_view", capture_id,
                details={"case": case_id, "authorization": case.get("authorization")})  # fmt: skip
    return {"import": found["data_import"], "evidence": {"id": capture_id, "digest": found["digest"]}, **result}
