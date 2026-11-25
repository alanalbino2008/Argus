"""Retention policies and legal hold (Phase 91). See :mod:`argus.intel.retention`."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from argus.api.deps import WorkspaceContext, audit, in_workspace, require_approval
from argus.intel.retention import MIN_DAYS
from argus.security.auth import Role

router = APIRouter(prefix="/api", tags=["security"])
ADMIN = Depends(in_workspace(Role.ADMIN))


class Policy(BaseModel):
    investigations_days: int = Field(default=0, ge=0, le=3650, description="0 keeps them forever")
    alerts_days: int = Field(default=0, ge=0, le=3650)
    cases_days: int = Field(default=0, ge=0, le=3650, description="Closed or archived cases; legal hold always wins")

    @field_validator("investigations_days", "alerts_days", "cases_days")
    @classmethod
    def at_least_a_week(cls, value: int) -> int:
        if 0 < value < MIN_DAYS:
            raise ValueError(f"Keep data at least {MIN_DAYS} days, or 0 to keep it forever")
        return value


class LegalHold(BaseModel):
    hold: bool
    note: str = Field(default="", max_length=200, description="e.g. the matter or the counsel who asked")


def _shorter(before: int, after: int) -> bool:
    """Whether a new period deletes more than the old one (0 means forever)."""
    return after != 0 and (before == 0 or after < before)


@router.get("/retention")
async def get_retention(request: Request, ws: WorkspaceContext = ADMIN):
    """The workspace's retention periods, and what a purge would delete now (nothing is deleted)."""
    retention = request.app.state.retention
    plan = await retention.plan(ws.id)
    return {**await retention.policy(ws.id), "would_delete": plan["counts"], "kept": plan["kept"]}


@router.put("/retention")
async def set_retention(body: Policy, request: Request, ws: WorkspaceContext = ADMIN):
    """Set how long to keep data. Deleting cases sooner counts as deleting cases (two-person approval applies)."""
    retention = request.app.state.retention
    before = await retention.policy(ws.id)
    if _shorter(before["cases_days"], body.cases_days):
        await require_approval(request, ws, "case.delete", f"retention:{body.cases_days}",
                               f"Delete closed cases after {body.cases_days} days")  # fmt: skip
    policy = await retention.set_policy(ws.id, by=ws.principal.name, **body.model_dump())
    await audit(request, ws.principal, "retention.policy", ws.id,
                details={"before": {k: before[k] for k in body.model_dump()}, "after": body.model_dump()})  # fmt: skip
    return policy


@router.post("/retention/run")
async def run_retention(request: Request, ws: WorkspaceContext = ADMIN):
    """Purge now instead of waiting for the next scheduled run."""
    return await request.app.state.retention.purge(ws.id, by=ws.principal)


@router.put("/cases/{case_id}/legal-hold")
async def set_legal_hold(case_id: str, body: LegalHold, request: Request, ws: WorkspaceContext = ADMIN):
    """Put a case on legal hold (it can then never be deleted), or release it."""
    cases = request.app.state.cases
    case = await cases.get(case_id, workspace_id=ws.id, who=ws.principal.name)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    if case["legal_hold"] and not body.hold:
        await require_approval(request, ws, "case.delete", f"hold:{case_id}",
                               f"Release the legal hold on “{case['title']}”")  # fmt: skip
    updated = await cases.set_legal_hold(case_id, workspace_id=ws.id, hold=body.hold, note=body.note.strip(),
                                         by=ws.principal.name)  # fmt: skip
    await audit(request, ws.principal, "case.legal_hold" if body.hold else "case.legal_hold_release", case_id,
                details={"note": body.note.strip()[:200]})  # fmt: skip
    return updated
