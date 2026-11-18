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
from argus.api.case_routes import _case
from argus.api.deps import WorkspaceContext, audit, in_workspace
from argus.intel.analyst import BASE_CREDITS, AnalystError, Material, build_material, check, document_text, price
from argus.intel.relationships import redact_protected
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


async def case_material(app: Any, case: dict[str, Any],
                        selected: list[str] | None) -> tuple[list[dict[str, Any]], Material]:  # fmt: skip
    """The case's items, and its labelled material for the analyst (protected people left out)."""
    documents = await case_documents(app, case["id"], selected)
    items, documents = redact_protected(await app.state.cases.items(case["id"]), documents)
    return items, build_material(case, items, documents, max_chars=app.state.settings.analyst_max_chars)


async def case_documents(app: Any, case_id: str, selected: list[str] | None = None) -> list[dict[str, Any]]:
    """The case's evidence with its readable text (``text`` None for photos and other files)."""
    repo = app.state.cases
    documents = []
    for capture in await repo.captures(case_id):
        if selected is not None and capture["id"] not in selected:
            continue
        files = await repo.files(capture["id"])  # read for the analyst; sending is logged by analyse()
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
    return documents


async def analyse(app: Any, case: dict[str, Any], task: str, *, by: str,
                  documents: list[str] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:  # fmt: skip
    """Run one analyst task over a case: (the checked answer, details for the audit log).

    Each evidence document sent is written to its chain of custody first. Raises AnalystError, with
    the audit details on ``exc.details``.
    """
    items, material = await case_material(app, case, documents)
    sent = [s for s in material.sources.values() if s["kind"] == "document"]
    via = ai_access()
    for source in sent:  # the evidence leaves Argus: its chain of custody says where it went
        await app.state.cases.log(source["id"], by=by, action="sent for AI analysis",
                                  detail=f"{task} via {'Argus Connect' if via == 'connect' else 'own Anthropic key'}")  # fmt: skip
    details = {"task": task, "via": via, "characters": len(material.text), "documents": len(sent),
               "anonymous_case": case["opsec_mode"] == "anonymous"}  # fmt: skip
    try:
        answer = await ai(task, material.text)
    except AnalystError as exc:
        exc.details = {**details, "error": exc.detail[:200]}
        raise
    result = {
        "task": task, "via": answer["via"], "model": answer.get("model"), "cut_off": answer.get("cut_off", False),
        "credits": answer.get("credits"), "material": material.summary(),
        "result": check(task, answer["output"], material, items),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }  # fmt: skip
    return result, {**details, "model": answer.get("model")}


@router.get("/cases/{case_id}/analyst/preview")
async def analyst_preview(case_id: str, request: Request, task: Task = "brief", ws: WorkspaceContext = ANALYST):
    """What a request would send (size, sources, documents shortened or left out) and what it costs."""
    case = await _case(request, ws, case_id)
    _items, material = await case_material(request.app, case, None)
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
    case = await _case(request, ws, case_id)
    try:
        result, details = await analyse(request.app, case, body.task, by=ws.principal.name, documents=body.documents)
    except AnalystError as exc:
        await audit(request, ws.principal, "case.analyst", case_id, details=exc.details)
        raise HTTPException(status_code=exc.status, detail=exc.detail) from exc
    await audit(request, ws.principal, "case.analyst", case_id, details=details)
    return result
