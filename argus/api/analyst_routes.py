"""The AI analyst in a case: briefings and next steps, names and dates from the evidence, report drafts.

Nothing is sent until the investigator confirms it, every time: the request must say
``acknowledged: true``. The preview shows exactly how much will be sent, from which sources, and
what it will cost. Each evidence document sent is written to its chain-of-custody log, and the
request (task, size, route, not the content) to the audit log.

Suggestions are never added to the case automatically: the investigator reviews them and adds the
ones they accept through the ordinary case endpoints.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from argus.accounts.connect_client import ai, ai_access
from argus.api.case_routes import _case, _repo
from argus.api.deps import WorkspaceContext, audit, in_workspace
from argus.intel.analyst import BASE_CREDITS, AnalystError, Material, build_material, check, document_text, price
from argus.security.auth import Role
from argus.security.ratelimit import SlidingWindowLimiter

router = APIRouter(prefix="/api", tags=["analyst"])
VIEWER = Depends(in_workspace(Role.VIEWER))
ANALYST = Depends(in_workspace(Role.ANALYST))
_limiter = SlidingWindowLimiter(limit=6, window=60)
Task = Literal["brief", "extract", "report"]


class AnalystRequest(BaseModel):
    task: Task
    acknowledged: bool = Field(
        default=False, description="Confirms the investigator agrees to send this case's material to Anthropic"
    )
    documents: list[str] | None = Field(
        default=None, max_length=500, description="Evidence to include (capture ids); default: all of it"
    )


def _status(request: Request) -> dict[str, Any]:
    settings = request.app.state.settings
    via = ai_access()
    return {
        "available": via is not None, "via": via, "model": settings.analyst_model or "newest Claude Opus",
        "effort": settings.analyst_effort, "max_characters": settings.analyst_max_chars,
        "credits": dict(BASE_CREDITS) if via == "connect" else None,
    }  # fmt: skip


@router.get("/analyst")
async def analyst_status(request: Request, ws: WorkspaceContext = VIEWER):
    """Whether the AI analyst can be used here, and how it is reached."""
    return _status(request)


async def _material(request: Request, ws: WorkspaceContext, case_id: str,
                    selected: list[str] | None) -> tuple[dict[str, Any], list[dict[str, Any]], Material]:  # fmt: skip
    case = await _case(request, ws, case_id)
    repo = _repo(request)
    items = await repo.items(case_id)
    documents = []
    for capture in await repo.captures(case_id):
        if selected is not None and capture["id"] not in selected:
            continue
        files = await repo.files(capture["id"])  # read for the analyst; sending is logged below
        text = None
        if capture["kind"] == "web":
            if "text.txt" in files:
                text = files["text.txt"][1].decode("utf-8", "replace")
        else:
            for name, (media, data) in files.items():
                text = document_text(name, media, data)
                if text:
                    break
        documents.append({"id": capture["id"], "title": capture["title"], "url": capture.get("url"),
                          "captured_at": capture["captured_at"], "text": text})  # fmt: skip
    material = build_material(case, items, documents, max_chars=request.app.state.settings.analyst_max_chars)
    return case, items, material


@router.get("/cases/{case_id}/analyst/preview")
async def analyst_preview(case_id: str, request: Request, task: Task = "brief", ws: WorkspaceContext = ANALYST):
    """What a request would send (size, sources, documents shortened or left out) and what it costs."""
    case, _items, material = await _material(request, ws, case_id, None)
    status = _status(request)
    return {
        **status, "task": task, "anonymous_case": case["opsec_mode"] == "anonymous", **material.summary(),
        "documents": [s["title"] for s in material.sources.values() if s["kind"] == "document"],
        "price": price(task, len(material.text)) if status["via"] == "connect" else 0,
    }  # fmt: skip


@router.post("/cases/{case_id}/analyst")
async def run_analyst(case_id: str, body: AnalystRequest, request: Request, ws: WorkspaceContext = ANALYST):
    """Run one analyst task over the case. Its suggestions are returned for review, never added."""
    if not body.acknowledged:
        raise HTTPException(status_code=428, detail="Confirm that this case's material may be sent to Anthropic "
                                                    "(the company that makes Claude) for analysis")  # fmt: skip
    if ai_access() is None:
        raise HTTPException(status_code=503, detail="The AI analyst needs an Argus account (Argus Connect) or "
                                                    "your own Claude API key (ARGUS_ANTHROPIC_API_KEY)")  # fmt: skip
    if not _limiter.hit(ws.principal.key_id):
        raise HTTPException(status_code=429, detail="Too many analyst requests; wait a minute")
    case, items, material = await _material(request, ws, case_id, body.documents)
    sent = [s for s in material.sources.values() if s["kind"] == "document"]
    via = ai_access()
    repo = _repo(request)
    for source in sent:  # the evidence leaves Argus: its chain of custody says where it went
        await repo.log(source["id"], by=ws.principal.name, action="sent for AI analysis",
                       detail=f"{body.task} via {'Argus Connect' if via == 'connect' else 'own Anthropic key'}")  # fmt: skip
    details = {"task": body.task, "via": via, "characters": len(material.text), "documents": len(sent),
               "anonymous_case": case["opsec_mode"] == "anonymous"}  # fmt: skip
    try:
        answer = await ai(body.task, material.text)
    except AnalystError as exc:
        await audit(request, ws.principal, "case.analyst", case_id, details={**details, "error": exc.detail[:200]})
        raise HTTPException(status_code=exc.status, detail=exc.detail) from exc
    await audit(request, ws.principal, "case.analyst", case_id, details={**details, "model": answer.get("model")})
    return {
        "task": body.task, "via": answer["via"], "model": answer.get("model"), "cut_off": answer.get("cut_off", False),
        "credits": answer.get("credits"), "material": material.summary(),
        "result": check(body.task, answer["output"], material, items),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }  # fmt: skip
