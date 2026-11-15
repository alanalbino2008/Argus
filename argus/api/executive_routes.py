"""The executive view: one page and a board report summarising every area of Argus."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from argus.api.deps import WorkspaceContext, audit, in_workspace
from argus.api.executive_service import collect, issue_board_report
from argus.intel.executive import assess
from argus.observability import metrics
from argus.security.auth import Role
from argus.security.ratelimit import SlidingWindowLimiter

router = APIRouter(prefix="/api/executive", tags=["executive"])
VIEWER = Depends(in_workspace(Role.VIEWER))
ANALYST = Depends(in_workspace(Role.ANALYST))
Period = Literal[30, 90, 180]
PERIODS = (30, 90, 180)
_board_limiter = SlidingWindowLimiter(limit=6, window=60)  # rendering costs CPU


class BoardReportRequest(BaseModel):
    days: Period = 90
    tlp: Literal["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"] = "AMBER"
    prepared_for: str = Field(default="", max_length=200, examples=["Board of Directors, Q4 meeting"])


@router.get("")
async def executive_overview(
    request: Request, ws: WorkspaceContext = VIEWER, days: int = Query(90, description="30, 90 or 180")
):
    """Overall status, five areas (red / amber / green with reasons), key messages and top risks."""
    if days not in PERIODS:
        raise HTTPException(status_code=422, detail="The period is 30, 90 or 180 days")
    raw = await collect(request.app, ws.id, days)
    return assess(raw, datetime.now(timezone.utc), days)


@router.post("/report")
async def board_report(body: BoardReportRequest, request: Request, ws: WorkspaceContext = ANALYST):
    """A two-page board report (PDF). Its fingerprint is registered so copies can be verified."""
    if not _board_limiter.hit(ws.principal.key_id):
        metrics.RATE_LIMITED.labels("board_report").inc()
        raise HTTPException(status_code=429, detail="Too many reports; try again in a minute")
    issued = await issue_board_report(request.app, ws.workspace, days=body.days, tlp=body.tlp,
                                      prepared_for=body.prepared_for.strip(), issued_by=ws.principal.name)  # fmt: skip
    await audit(request, ws.principal, "report.board", issued["record"]["id"],
                details={"sha256": issued["sha256"], "days": body.days, "tlp": body.tlp,
                         "overall": issued["summary"]["overall"]})  # fmt: skip
    return Response(issued["pdf"], media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="{issued["filename"]}"',
        "X-Report-Id": issued["record"]["id"], "X-Report-SHA256": issued["sha256"],
    })  # fmt: skip
