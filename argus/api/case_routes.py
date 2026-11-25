"""Cases and evidence: the investigator's workspace for one story or inquiry.

**Captured pages are hostile content.** A captured page's HTML was written by whoever published
it. Served from Argus's own origin, its scripts would run with the investigator's session. So
evidence files are only ever *downloaded* (``Content-Disposition: attachment``) with
``Content-Security-Policy: sandbox``, except raster images, which are shown inline as images
(``nosniff``). SVG is treated as a document, never as an image, because it can carry script.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile
from pydantic import BaseModel, Field

from argus.api.deps import WorkspaceContext, audit, in_workspace, require_approval, throttle
from argus.api.opsec_routes import find_route, route_for
from argus.evidence.bundle import build_bundle
from argus.evidence.capture import CaptureError, capture_upload, capture_url
from argus.intel.relationships import KINDS
from argus.security.auth import Role
from argus.security.ratelimit import SlidingWindowLimiter

router = APIRouter(prefix="/api", tags=["cases"])
VIEWER = Depends(in_workspace(Role.VIEWER))
ANALYST = Depends(in_workspace(Role.ANALYST))
INLINE_IMAGES = {"image/png", "image/jpeg", "image/gif", "image/webp"}
ENTITY_TYPES = ("person", "organisation", "username", "account", "email", "phone", "domain", "ip", "address",
                "location", "vehicle", "document", "wallet", "other")  # fmt: skip
_capture_limiter = SlidingWindowLimiter(limit=20, window=60, name="case_capture")

ItemKind = Literal["note", "entity", "link", "scan", "event"]
OpsecMode = Literal["standard", "anonymous"]


class CaseRequest(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    purpose: str = Field(min_length=10, max_length=500, examples=["Investigating a fake charity fundraising online"])
    summary: str = Field(default="", max_length=20000)
    restricted: bool = Field(default=False, description="Only you and the members listed can open the case")
    members: list[str] = Field(default_factory=list, max_length=50)
    tags: list[str] = Field(default_factory=list, max_length=20)
    egress: str = Field(default="", max_length=32, description="Route its captures and scans use; empty: direct")
    opsec_mode: OpsecMode = Field(default="standard", description="anonymous: never touch the subjects directly")
    confirmed: bool = Field(description="Confirms there is a legitimate purpose for this investigation")


class CaseUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    purpose: str | None = Field(default=None, min_length=10, max_length=500)
    summary: str | None = Field(default=None, max_length=20000)
    status: Literal["open", "closed", "archived"] | None = None
    restricted: bool | None = None
    members: list[str] | None = Field(default=None, max_length=50)
    tags: list[str] | None = Field(default=None, max_length=20)
    egress: str | None = Field(default=None, max_length=32)
    opsec_mode: OpsecMode | None = None


class ItemRequest(BaseModel):
    kind: ItemKind
    title: str = Field(default="", max_length=300)
    body: str = Field(default="", max_length=50000)
    data: dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime | None = None


class ItemUpdate(BaseModel):
    title: str | None = Field(default=None, max_length=300)
    body: str | None = Field(default=None, max_length=50000)
    data: dict[str, Any] | None = None
    occurred_at: datetime | None = None


class CaptureRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    note: str = Field(default="", max_length=1000)
    egress: str | None = Field(default=None, max_length=32, description="Route for this capture; default: the case's")


def _repo(request: Request) -> Any:
    return request.app.state.cases


def _clean_list(values: list[str], limit: int = 128) -> list[str]:
    return list(dict.fromkeys(v.strip()[:limit] for v in values if v.strip()))


async def _case(request: Request, ws: WorkspaceContext, case_id: str) -> dict[str, Any]:
    case = await _repo(request).get(case_id, workspace_id=ws.id, who=ws.principal.name)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


async def _validate_item(request: Request, ws: WorkspaceContext, case_id: str, kind: str, title: str,
                         data: dict[str, Any], occurred_at: datetime | None) -> dict[str, Any]:  # fmt: skip
    """Check an item's data for its kind; returns the cleaned data."""
    if kind == "entity":
        etype = str(data.get("type") or "other")
        value = str(data.get("value") or title or "").strip()
        if etype not in ENTITY_TYPES:
            raise HTTPException(status_code=422, detail=f"Entity type must be one of: {', '.join(ENTITY_TYPES)}")
        if not value:
            raise HTTPException(status_code=422, detail="Give the entity a value (a name, handle, address...)")
        attributes = {str(k)[:64]: str(v)[:1000] for k, v in (data.get("attributes") or {}).items()}
        clean: dict[str, Any] = {"type": etype, "value": value[:500], "attributes": dict(list(attributes.items())[:50])}
        if data.get("protected") is True:  # e.g. a child: never shown by name, never profiled
            clean["protected"] = True
        for key in ("source_investigation_id", "source_entity_id"):
            if data.get(key):
                clean[key] = str(data[key])[:64]
        return clean
    if kind == "link":
        ends = [str(data.get("from") or ""), str(data.get("to") or "")]
        if ends[0] == ends[1]:
            raise HTTPException(status_code=422, detail="A link joins two different items")
        for end in ends:
            item = await _repo(request).get_item(end, case_id)
            if item is None or item["kind"] != "entity":
                raise HTTPException(status_code=422, detail="Links join two entities of this case")
        relation = str(data.get("relation") or "other")
        if relation not in KINDS:
            raise HTTPException(status_code=422, detail=f"Relationship kind must be one of: {', '.join(KINDS)}")
        clean_link: dict[str, Any] = {
            "from": ends[0], "to": ends[1], "label": str(data.get("label") or "")[:200], "relation": relation,
            "confidence": data.get("confidence") if data.get("confidence") in ("confirmed", "likely", "possible") else "likely",
        }  # fmt: skip
        for key in ("since", "until"):  # when the relationship began and ended: 2019, 2019-03 or 2019-03-14
            if data.get(key):
                if not re.fullmatch(r"\d{4}(-\d{2}(-\d{2})?)?", str(data[key])):
                    raise HTTPException(status_code=422, detail=f"'{key}' must be a year, year-month or date")
                clean_link[key] = str(data[key])
        evidence = [str(x)[:64] for x in data.get("evidence") or [] if str(x).strip()][:20]
        if evidence:
            clean_link["evidence"] = evidence  # the notes or evidence that show it
        if data.get("why"):
            clean_link["why"] = str(data["why"])[:300]  # how a suggested relationship was found
        return clean_link
    if kind == "scan":
        inv_id = str(data.get("investigation_id") or "")
        inv = await request.app.state.repo.get_investigation(inv_id) if inv_id else None
        if inv is None or inv.workspace_id != ws.id:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return {"investigation_id": inv.id, "target": inv.config.target}
    if kind == "event" and occurred_at is None:
        raise HTTPException(status_code=422, detail="An event needs a date and time")
    return {k: v for k, v in data.items() if isinstance(k, str)} if kind == "note" else {}


def _safety(request: Request, egress: str, mode: str) -> str:
    """Check a case's route and mode go together; returns the route name ("" for direct)."""
    route = find_route(request.app.state.settings, egress)
    if mode == "anonymous" and (route is None or not route.is_anonymous):
        raise HTTPException(status_code=422, detail="An anonymous case needs an anonymous route, such as Tor")
    return route.name if route else ""


def _aware(value: datetime | None) -> datetime | None:
    return value.replace(tzinfo=timezone.utc) if value and value.tzinfo is None else value


# ---------------------------------------------------------------------------- cases
@router.get("/cases")
async def list_cases(request: Request, ws: WorkspaceContext = VIEWER):
    cases = await _repo(request).list_cases(workspace_id=ws.id, who=ws.principal.name)
    months = request.app.state.settings.case_review_months
    if months:  # keep only what's still needed: untouched for months, a case is due for review
        cutoff = (datetime.now(timezone.utc) - timedelta(days=months * 30)).isoformat()
        for case in cases:
            case["review_due"] = bool(case.get("updated_at") and case["updated_at"] < cutoff)
    return cases


@router.post("/cases", status_code=201)
async def create_case(body: CaseRequest, request: Request, ws: WorkspaceContext = ANALYST):
    if not body.confirmed:
        raise HTTPException(status_code=422, detail="Confirm there is a legitimate purpose for this investigation")
    egress = _safety(request, body.egress, body.opsec_mode)
    case = await _repo(request).create(
        workspace_id=ws.id, by=ws.principal.name, title=body.title.strip(), purpose=body.purpose.strip(),
        summary=body.summary, restricted=body.restricted, members=_clean_list(body.members), tags=_clean_list(body.tags, 40),
        egress=egress, opsec_mode=body.opsec_mode,
    )  # fmt: skip
    await audit(request, ws.principal, "case.create", case["id"],
                details={"title": case["title"], "purpose": case["purpose"], "restricted": case["restricted"],
                         "route": egress or "direct", "opsec_mode": body.opsec_mode})  # fmt: skip
    return case


@router.get("/cases/{case_id}")
async def get_case(case_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """The case with its items and evidence."""
    case = await _case(request, ws, case_id)
    repo = _repo(request)
    await audit(request, ws.principal, "case.view", case_id)
    return {**case, "items": await repo.items(case_id), "captures": await repo.captures(case_id)}


@router.patch("/cases/{case_id}")
async def update_case(case_id: str, body: CaseUpdate, request: Request, ws: WorkspaceContext = ANALYST):
    case = await _case(request, ws, case_id)
    changes = body.model_dump(exclude_none=True)
    if ("restricted" in changes or "members" in changes) and ws.principal.name != case["created_by"]:
        raise HTTPException(status_code=403, detail="Only the case owner can change who may open it")
    if "members" in changes:
        changes["members"] = _clean_list(changes["members"])
    if "tags" in changes:
        changes["tags"] = _clean_list(changes["tags"], 40)
    if "egress" in changes or "opsec_mode" in changes:
        changes["egress"] = _safety(request, changes.get("egress", case["egress"]),
                                    changes.setdefault("opsec_mode", case["opsec_mode"]))  # fmt: skip
    updated = await _repo(request).update(case_id, workspace_id=ws.id, who=ws.principal.name, **changes)
    await audit(request, ws.principal, "case.update", case_id, details={k: str(v)[:200] for k, v in changes.items()})
    return updated


@router.delete("/cases/{case_id}", status_code=204)
async def delete_case(case_id: str, request: Request, ws: WorkspaceContext = ANALYST):
    case = await _case(request, ws, case_id)
    if ws.principal.name != case["created_by"] and ws.role.rank < Role.ADMIN.rank:
        raise HTTPException(status_code=403, detail="Only the case owner or a workspace admin can delete a case")
    await require_approval(request, ws, "case.delete", case_id, f"Delete case \u201c{case['title']}\u201d")
    await _repo(request).delete(case_id, workspace_id=ws.id, who=ws.principal.name)
    await audit(request, ws.principal, "case.delete", case_id, details={"title": case["title"]})
    return Response(status_code=204)


# ---------------------------------------------------------------------------- items
@router.post("/cases/{case_id}/items", status_code=201)
async def add_item(case_id: str, body: ItemRequest, request: Request, ws: WorkspaceContext = ANALYST):
    await _case(request, ws, case_id)
    data = await _validate_item(request, ws, case_id, body.kind, body.title, body.data, body.occurred_at)
    title = body.title.strip() or str(data.get("value") or data.get("label") or data.get("target") or body.kind)[:300]
    item = await _repo(request).add_item(case_id, by=ws.principal.name, kind=body.kind, title=title, body=body.body,
                                         data=data, occurred_at=_aware(body.occurred_at))  # fmt: skip
    await audit(request, ws.principal, "case.item_add", case_id, details={"item": item["id"], "kind": body.kind})
    return item


@router.patch("/cases/{case_id}/items/{item_id}")
async def update_item(case_id: str, item_id: str, body: ItemUpdate, request: Request, ws: WorkspaceContext = ANALYST):
    await _case(request, ws, case_id)
    current = await _repo(request).get_item(item_id, case_id)
    if current is None:
        raise HTTPException(status_code=404, detail="Item not found")
    changes = body.model_dump(exclude_unset=True)
    if "data" in changes:
        changes["data"] = await _validate_item(request, ws, case_id, current["kind"], changes.get("title") or current["title"],
                                               changes["data"] or {}, _aware(changes.get("occurred_at")) or
                                               (datetime.fromisoformat(current["occurred_at"]) if current["occurred_at"] else None))  # fmt: skip
    if "occurred_at" in changes:
        changes["occurred_at"] = _aware(changes["occurred_at"])
    item = await _repo(request).update_item(item_id, case_id, **changes)
    await audit(request, ws.principal, "case.item_update", case_id, details={"item": item_id})
    return item


@router.delete("/cases/{case_id}/items/{item_id}", status_code=204)
async def delete_item(case_id: str, item_id: str, request: Request, ws: WorkspaceContext = ANALYST):
    await _case(request, ws, case_id)
    if not await _repo(request).delete_item(item_id, case_id):
        raise HTTPException(status_code=404, detail="Item not found")
    await audit(request, ws.principal, "case.item_delete", case_id, details={"item": item_id})
    return Response(status_code=204)


# ---------------------------------------------------------------------------- evidence
async def _limit(ws: WorkspaceContext) -> None:
    await throttle(_capture_limiter, ws.principal.key_id, "Too many captures; wait a minute")


@router.post("/cases/{case_id}/captures", status_code=201)
async def capture_page(case_id: str, body: CaptureRequest, request: Request, ws: WorkspaceContext = ANALYST):
    """Preserve a public web page as it is now: response, screenshot, text, manifest and fingerprint."""
    case = await _case(request, ws, case_id)
    route = route_for(request.app.state.settings, case, body.egress)  # 409 if it would expose an anonymous case
    await _limit(ws)
    try:
        capture = await capture_url(body.url, request.app.state.settings, route)
    except CaptureError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    saved = await _repo(request).add_capture(case_id, ws.id, capture, by=ws.principal.name, note=body.note)
    await audit(request, ws.principal, "evidence.capture", saved["id"],
                details={"case": case_id, "url": body.url, "digest": saved["digest"], "timestamped": saved["timestamped"],
                         "route": route.name if route else "direct"})  # fmt: skip
    return saved


@router.post("/cases/{case_id}/uploads", status_code=201)
async def upload_evidence(case_id: str, request: Request, file: UploadFile = File(...), note: str = Form(""),
                          ws: WorkspaceContext = ANALYST):  # fmt: skip
    """Add evidence you already hold (a screenshot of a private chat, a document, a photo)."""
    await _case(request, ws, case_id)
    await _limit(ws)
    limit = request.app.state.settings.evidence_max_upload_mb * 1024 * 1024
    data = await file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(status_code=413, detail=f"Files up to {limit // (1024 * 1024)} MB can be added")
    if not data:
        raise HTTPException(status_code=422, detail="The file is empty")
    capture = await capture_upload(file.filename or "upload.bin", file.content_type or "", data,
                                   request.app.state.settings, note=note)  # fmt: skip
    saved = await _repo(request).add_capture(case_id, ws.id, capture, by=ws.principal.name, note=note[:1000])
    await audit(request, ws.principal, "evidence.upload", saved["id"],
                details={"case": case_id, "file": capture.manifest["original_filename"], "digest": saved["digest"]})  # fmt: skip
    return saved


async def _capture(request: Request, ws: WorkspaceContext, capture_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    found = await _repo(request).capture(capture_id, workspace_id=ws.id, who=ws.principal.name)
    if found is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return found


@router.get("/evidence/{capture_id}")
async def get_capture(capture_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    capture, _case_row = await _capture(request, ws, capture_id)
    return {**capture, "custody": await _repo(request).custody(capture_id)}


@router.get("/evidence/{capture_id}/files/{name}")
async def get_file(capture_id: str, name: str, request: Request, ws: WorkspaceContext = VIEWER, download: bool = False):
    await _capture(request, ws, capture_id)
    inline = not download
    found = await _repo(request).file(
        capture_id, name, by=ws.principal.name, action="viewed" if inline else "downloaded"
    )
    if found is None:
        raise HTTPException(status_code=404, detail="File not found")
    media, data = found
    safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)[:120]
    headers = {"X-Content-Type-Options": "nosniff", "Content-Security-Policy": "sandbox; default-src 'none'",
               "Cache-Control": "no-store"}  # fmt: skip
    if inline and media in INLINE_IMAGES:
        return Response(
            data, media_type=media, headers={**headers, "Content-Disposition": f'inline; filename="{safe_name}"'}
        )
    return Response(data, media_type="application/octet-stream",
                    headers={**headers, "Content-Disposition": f'attachment; filename="{safe_name}"'})  # fmt: skip


@router.get("/evidence/{capture_id}/timestamp.tsr")
async def get_timestamp(capture_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    await _capture(request, ws, capture_id)
    token = await _repo(request).timestamp_token(capture_id)
    if token is None:
        raise HTTPException(status_code=404, detail="This evidence has no trusted timestamp")
    return Response(token, media_type="application/timestamp-reply",
                    headers={"Content-Disposition": f'attachment; filename="{capture_id}.tsr"'})  # fmt: skip


@router.post("/evidence/{capture_id}/verify")
async def verify_capture(capture_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Recompute every hash: files against the manifest, the manifest against its digest, the custody chain."""
    await _capture(request, ws, capture_id)
    result = await _repo(request).verify(capture_id)
    await _repo(request).log(capture_id, by=ws.principal.name, action="verified",
                             detail="intact" if result["intact"] else "; ".join(result["problems"])[:500])  # fmt: skip
    return result


@router.get("/cases/{case_id}/export")
async def export_bundle(case_id: str, request: Request, ws: WorkspaceContext = ANALYST):
    """The whole case as a self-verifying evidence bundle (ZIP)."""
    case = await _case(request, ws, case_id)
    await require_approval(
        request, ws, "case.export", case_id, f"Export the evidence bundle of \u201c{case['title']}\u201d"
    )
    repo = _repo(request)
    captures = []
    for c in await repo.captures(case_id):
        await repo.log(c["id"], by=ws.principal.name, action="exported", detail=f"evidence bundle of case {case_id}")
        found = await repo.capture(c["id"], workspace_id=ws.id, who=ws.principal.name)
        captures.append({**c, "manifest": found[0]["manifest"] if found else {}, "files": await repo.files(c["id"]),
                         "custody": await repo.custody(c["id"]), "token": await repo.timestamp_token(c["id"])})  # fmt: skip
    data = build_bundle(case, await repo.items(case_id), captures, by=ws.principal.name)
    await audit(request, ws.principal, "case.export", case_id, details={"captures": len(captures), "bytes": len(data)})
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    return Response(data, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="argus-case-{case_id}-{stamp}.zip"'})  # fmt: skip
