"""Monitoring endpoints: scheduled re-scans and drift alerts."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from argus.api.deps import WorkspaceContext, audit, in_workspace
from argus.core.models import EntityType
from argus.security.auth import Role
from argus.security.network import validate_scan_target
from argus.storage.monitor_repo import ALERT_STATUSES

router = APIRouter(prefix="/api", tags=["monitoring"])


class CreateMonitorRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    target_type: EntityType | None = None
    interval_hours: int = Field(default=24, ge=1, le=24 * 30)
    max_depth: int = Field(default=2, ge=0, le=4)
    passive_only: bool = False
    purpose: str = Field(min_length=5, max_length=500)
    authorized: bool = Field(description="Confirms you are authorised to monitor this target on an ongoing basis")


class UpdateMonitorRequest(BaseModel):
    enabled: bool


@router.get("/monitors")
async def list_monitors(request: Request, ws: WorkspaceContext = Depends(in_workspace(Role.VIEWER))):
    return await request.app.state.monitors.list_monitors(workspace_id=ws.id)


@router.post("/monitors", status_code=201)
async def create_monitor(
    body: CreateMonitorRequest, request: Request, ws: WorkspaceContext = Depends(in_workspace(Role.ANALYST))
):
    """Watch a target: it is scanned now and then every ``interval_hours``; material changes raise alerts."""
    from argus.cli.console import detect_target_type

    principal = ws.principal

    target = body.target.strip()
    if not body.authorized:
        raise HTTPException(status_code=422, detail="You must confirm you are authorised to monitor this target")
    ttype = body.target_type or detect_target_type(target)
    if not request.app.state.settings.allow_private_targets:
        try:
            validate_scan_target(target, ttype)
        except ValueError as exc:
            await audit(request, principal, "monitor.create", target, "denied", {"reason": str(exc)})
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    monitor = await request.app.state.monitors.create(
        target=target,
        target_type=ttype.value,
        max_depth=body.max_depth,
        passive_only=body.passive_only,
        interval_hours=body.interval_hours,
        purpose=body.purpose,
        created_by=principal.name,
        workspace_id=ws.id,
    )
    await audit(
        request,
        principal,
        "monitor.create",
        monitor["id"],
        details={
            "target": target,
            "interval_hours": body.interval_hours,
            "purpose": body.purpose,
            "authorized_confirmed": True,
        },
    )
    if request.app.state.settings.monitors_enabled:
        await request.app.state.scheduler.tick()  # first (baseline) scan starts immediately
    return await request.app.state.monitors.get(monitor["id"], workspace_id=ws.id)


@router.patch("/monitors/{monitor_id}")
async def update_monitor(
    monitor_id: str,
    body: UpdateMonitorRequest,
    request: Request,
    ws: WorkspaceContext = Depends(in_workspace(Role.ANALYST)),
):
    if not await request.app.state.monitors.set_enabled(monitor_id, body.enabled, workspace_id=ws.id):
        raise HTTPException(status_code=404, detail="Monitor not found")
    await audit(request, ws.principal, "monitor.update", monitor_id, details={"enabled": body.enabled})
    return await request.app.state.monitors.get(monitor_id, workspace_id=ws.id)


@router.delete("/monitors/{monitor_id}", status_code=204)
async def delete_monitor(monitor_id: str, request: Request, ws: WorkspaceContext = Depends(in_workspace(Role.ANALYST))):
    if not await request.app.state.monitors.delete(monitor_id, workspace_id=ws.id):
        raise HTTPException(status_code=404, detail="Monitor not found")
    await audit(request, ws.principal, "monitor.delete", monitor_id)
    return Response(status_code=204)


@router.get("/alerts")
async def list_alerts(
    request: Request,
    unacknowledged: bool = False,
    limit: int = Query(50, ge=1, le=500),
    status: str | None = Query(None, description="Comma-separated: open, investigating, resolved, false_positive"),
    assignee: str | None = Query(None, description="A name, 'me', or 'none' for unassigned alerts"),
    ws: WorkspaceContext = Depends(in_workspace(Role.VIEWER)),
):
    statuses = [x.strip() for x in status.split(",") if x.strip()] if status else None
    if statuses and set(statuses) - set(ALERT_STATUSES):
        raise HTTPException(status_code=422, detail=f"Statuses are {', '.join(ALERT_STATUSES)}")
    who = (
        None if assignee is None else ws.principal.name if assignee == "me" else "" if assignee == "none" else assignee
    )
    return await request.app.state.monitors.alerts(workspace_id=ws.id, limit=limit, unacknowledged_only=unacknowledged,
                                                   statuses=statuses, assignee=who)  # fmt: skip


@router.get("/alerts/stats")
async def alert_stats(request: Request, days: int = Query(30, ge=1, le=365),
                      ws: WorkspaceContext = Depends(in_workspace(Role.VIEWER))):  # fmt: skip
    """Open alerts by severity and unassigned, and the median hours to acknowledge and to resolve."""
    return await request.app.state.monitors.alert_stats(workspace_id=ws.id, days=days)


class AlertUpdate(BaseModel):
    status: Literal["open", "investigating", "resolved", "false_positive"] | None = None
    assignee: str | None = Field(
        default=None, max_length=128, description="A member's name or email, 'me', or '' to unassign"
    )
    note: str = Field(default="", max_length=2000, description="Why (kept in the alert's activity)")


class AlertComment(BaseModel):
    body: str = Field(min_length=1, max_length=4000)


async def _assignable(request: Request, ws: WorkspaceContext, value: str) -> str:
    """Members of the workspace (by email or name), or the caller themself."""
    if value in ("me", ws.principal.name):
        return ws.principal.name
    members = await request.app.state.workspaces.members(ws.id)
    for member in members:
        if not member["disabled"] and value.strip().lower() in {
            str(member["email"] or "").lower(),
            str(member["name"] or "").lower(),
        }:
            return str(member["email"] or member["name"])
    raise HTTPException(status_code=422, detail="Assign alerts to a member of this workspace (or to yourself)")


@router.get("/alerts/assignees")
async def alert_assignees(request: Request, ws: WorkspaceContext = Depends(in_workspace(Role.VIEWER))):
    """Who alerts can be assigned to: the workspace's active members, and the caller."""
    members = await request.app.state.workspaces.members(ws.id)
    names = [str(m["email"] or m["name"]) for m in members if not m["disabled"] and m["role"] != "viewer"]
    return {"me": ws.principal.name, "assignees": sorted(set(names) | {ws.principal.name}, key=str.lower)}


@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: str, request: Request, ws: WorkspaceContext = Depends(in_workspace(Role.VIEWER))):
    """One alert with its activity: comments, status changes and assignments."""
    alert = await request.app.state.monitors.get_alert(alert_id, workspace_id=ws.id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/alerts/{alert_id}")
async def update_alert(alert_id: str, body: AlertUpdate, request: Request,
                       ws: WorkspaceContext = Depends(in_workspace(Role.ANALYST))):  # fmt: skip
    """Move an alert along (open, investigating, resolved, false positive) and/or assign it."""
    assignee = None if body.assignee in (None, "") else await _assignable(request, ws, body.assignee)
    alert = await request.app.state.monitors.update_alert(
        alert_id, workspace_id=ws.id, by=ws.principal.name, status=body.status, assignee=assignee,
        unassign=body.assignee == "", note=body.note.strip(),
    )  # fmt: skip
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    await audit(request, ws.principal, "alert.update", alert_id,
                details={"status": alert["status"], "assignee": alert["assignee"]})  # fmt: skip
    return alert


@router.post("/alerts/{alert_id}/comments", status_code=201)
async def comment_alert(alert_id: str, body: AlertComment, request: Request,
                        ws: WorkspaceContext = Depends(in_workspace(Role.ANALYST))):  # fmt: skip
    entry = await request.app.state.monitors.comment(alert_id, workspace_id=ws.id, by=ws.principal.name,
                                                     body=body.body.strip())  # fmt: skip
    if entry is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    await audit(request, ws.principal, "alert.comment", alert_id)
    return entry


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str, request: Request, ws: WorkspaceContext = Depends(in_workspace(Role.ANALYST))
):
    if not await request.app.state.monitors.acknowledge(alert_id, ws.principal.name, workspace_id=ws.id):
        raise HTTPException(status_code=404, detail="Unacknowledged alert not found")
    await audit(request, ws.principal, "alert.acknowledge", alert_id)
    return {"status": "acknowledged", "alert_id": alert_id}
