"""Two-person approval: the workspace's policy, and approving or rejecting requests (Phase 90).

See :mod:`argus.security.approvals`.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from argus.api.deps import WorkspaceContext, audit, in_workspace, require_approval
from argus.security.approvals import POLICY_ACTIONS
from argus.security.auth import Role

router = APIRouter(prefix="/api", tags=["security"])
ANALYST = Depends(in_workspace(Role.ANALYST))
ADMIN = Depends(in_workspace(Role.ADMIN))


class Policy(BaseModel):
    actions: list[str] = Field(max_length=len(POLICY_ACTIONS))


class Decision(BaseModel):
    note: str = Field(default="", max_length=500)


@router.get("/approval-policy")
async def get_approval_policy(request: Request, ws: WorkspaceContext = ANALYST):
    """The actions that need a second administrator's approval in this workspace."""
    return await request.app.state.approvals.policy(ws.id)


@router.put("/approval-policy")
async def set_approval_policy(body: Policy, request: Request, ws: WorkspaceContext = ADMIN):
    """Choose the protected actions. Adding is immediate; removing one needs an approval itself."""
    unknown = [a for a in body.actions if a not in POLICY_ACTIONS]
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown action(s): {', '.join(unknown)}")
    repo = request.app.state.approvals
    wanted = sorted(set(body.actions))
    current = (await repo.policy(ws.id))["actions"]
    removed = sorted(set(current) - set(wanted))
    if removed:
        await require_approval(request, ws, "approval.policy", ",".join(wanted) or "none",
                               f"Stop requiring approval for: {', '.join(removed)}")  # fmt: skip
    policy = await repo.set_policy(ws.id, wanted, by=ws.principal.name)
    await audit(request, ws.principal, "approval.policy", ws.id, details={"before": current, "after": wanted})
    return policy


@router.get("/approvals")
async def list_approvals(
    request: Request, ws: WorkspaceContext = ANALYST,
    status: Literal["pending", "approved", "rejected", "used", "expired", "all"] = "pending",
):  # fmt: skip
    return await request.app.state.approvals.list(ws.id, status=status)


@router.get("/approvals/{approval_id}")
async def get_approval(approval_id: str, request: Request, ws: WorkspaceContext = ANALYST):
    found = await request.app.state.approvals.get(approval_id, ws.id)
    if found is None:
        raise HTTPException(status_code=404, detail="Approval request not found")
    return found


async def _decide(request: Request, ws: WorkspaceContext, approval_id: str, approve: bool, note: str):
    try:
        decided = await request.app.state.approvals.decide(approval_id, ws.id, approve=approve,
                                                           key_id=ws.principal.key_id, name=ws.principal.name,
                                                           note=note)  # fmt: skip
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        await audit(request, ws.principal, "approval.self_approve", approval_id, "denied")
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await audit(request, ws.principal, "approval.approve" if approve else "approval.reject", approval_id,
                details={"action": decided["action"], "resource": decided["resource"],
                         "requested_by": decided["requested_by"], "note": note[:200]})  # fmt: skip
    return decided


@router.post("/approvals/{approval_id}/approve")
async def approve_request(approval_id: str, body: Decision, request: Request, ws: WorkspaceContext = ADMIN):
    """Approve someone else's request. They then repeat their call with ``X-Argus-Approval``."""
    return await _decide(request, ws, approval_id, True, body.note)


@router.post("/approvals/{approval_id}/reject")
async def reject_request(approval_id: str, body: Decision, request: Request, ws: WorkspaceContext = ADMIN):
    return await _decide(request, ws, approval_id, False, body.note)
