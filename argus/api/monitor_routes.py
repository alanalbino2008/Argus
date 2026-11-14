"""Monitoring endpoints: scheduled re-scans and drift alerts."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from argus.api.deps import audit, require
from argus.core.models import EntityType
from argus.security.auth import Principal, Role
from argus.security.network import validate_scan_target

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
async def list_monitors(request: Request, _: Principal = Depends(require(Role.VIEWER))):
    return await request.app.state.monitors.list_monitors()


@router.post("/monitors", status_code=201)
async def create_monitor(
    body: CreateMonitorRequest, request: Request, principal: Principal = Depends(require(Role.ANALYST))
):
    """Watch a target: it is scanned now and then every ``interval_hours``; material changes raise alerts."""
    from argus.cli.console import detect_target_type

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
    return await request.app.state.monitors.get(monitor["id"])


@router.patch("/monitors/{monitor_id}")
async def update_monitor(
    monitor_id: str, body: UpdateMonitorRequest, request: Request, principal: Principal = Depends(require(Role.ANALYST))
):
    if not await request.app.state.monitors.set_enabled(monitor_id, body.enabled):
        raise HTTPException(status_code=404, detail="Monitor not found")
    await audit(request, principal, "monitor.update", monitor_id, details={"enabled": body.enabled})
    return await request.app.state.monitors.get(monitor_id)


@router.delete("/monitors/{monitor_id}", status_code=204)
async def delete_monitor(monitor_id: str, request: Request, principal: Principal = Depends(require(Role.ANALYST))):
    if not await request.app.state.monitors.delete(monitor_id):
        raise HTTPException(status_code=404, detail="Monitor not found")
    await audit(request, principal, "monitor.delete", monitor_id)
    return Response(status_code=204)


@router.get("/alerts")
async def list_alerts(
    request: Request,
    unacknowledged: bool = False,
    limit: int = Query(50, ge=1, le=500),
    _: Principal = Depends(require(Role.VIEWER)),
):
    return await request.app.state.monitors.alerts(limit=limit, unacknowledged_only=unacknowledged)


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str, request: Request, principal: Principal = Depends(require(Role.ANALYST))):
    if not await request.app.state.monitors.acknowledge(alert_id, principal.name):
        raise HTTPException(status_code=404, detail="Unacknowledged alert not found")
    await audit(request, principal, "alert.acknowledge", alert_id)
    return {"status": "acknowledged", "alert_id": alert_id}
