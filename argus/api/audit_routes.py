"""Audit log export and streaming to a SIEM (Phase 92).

See :mod:`argus.security.audit_export` and :mod:`argus.security.audit_stream`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel

from argus.api.deps import WorkspaceContext, audit, in_workspace, require_approval, throttle
from argus.security import audit_export
from argus.security.audit_stream import KINDS
from argus.security.auth import Role
from argus.security.ratelimit import SlidingWindowLimiter

router = APIRouter(prefix="/api", tags=["security"])
ADMIN = Depends(in_workspace(Role.ADMIN))
_export_limiter = SlidingWindowLimiter(limit=10, window=60, name="audit_export")  # each reads up to 100,000 entries


class NewStream(BaseModel):
    channel_id: str
    platform: bool = False  # every entry, not just this workspace's (platform administrators)
    start: Literal["now", "beginning"] = "now"


class StreamChange(BaseModel):
    enabled: bool


@router.get("/audit/export")
async def export_audit(
    request: Request, ws: WorkspaceContext = ADMIN,
    format: Literal["jsonl", "csv"] = "jsonl",
    since: str | None = Query(None, max_length=40, description="ISO date or time, inclusive"),
    until: str | None = Query(None, max_length=40, description="ISO date or time, exclusive"),
    action: str | None = Query(None, max_length=64), actor_id: str | None = Query(None, max_length=64),
    scope: Literal["workspace", "all"] = "workspace",
):  # fmt: skip
    """The audit log as a file: JSON Lines with each entry's chain hashes and a signed manifest
    (check it with ``argus --verify-audit``), or CSV for a spreadsheet."""
    from argus.api.case_report_routes import report_signer

    await throttle(_export_limiter, ws.principal.key_id, "Too many exports; wait a minute")
    if scope == "all" and not ws.principal.platform_admin:
        raise HTTPException(
            status_code=403, detail="Only platform administrators can export every workspace's audit log"
        )
    for value in (since, until):
        if value:
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=f"Not a date or time: {value}") from exc
    log = request.app.state.audit
    rows = await log.export(workspace_id=None if scope == "all" else ws.id, since=since, until=until,
                            action=action, actor_id=actor_id)  # fmt: skip
    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y%m%d-%H%M%S")
    await audit(request, ws.principal, "audit.export", ws.id,
                details={"format": format, "entries": len(rows), "scope": scope, "since": since, "until": until,
                         "action": action})  # fmt: skip
    if format == "csv":
        return Response(audit_export.to_csv(rows), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="argus-audit-{stamp}.csv"'})  # fmt: skip
    manifest = {
        "exported_at": now.isoformat(), "exported_by": ws.principal.name, "scope": scope,
        "workspace_id": None if scope == "all" else ws.id, "head": await log.head(),
        "filters": {"since": since, "until": until, "action": action, "actor_id": actor_id},
    }  # fmt: skip
    data = audit_export.jsonl(rows, manifest, await report_signer(request))
    return Response(data, media_type="application/x-ndjson",
                    headers={"Content-Disposition": f'attachment; filename="argus-audit-{stamp}.jsonl"'})  # fmt: skip


@router.get("/audit/streams")
async def list_streams(request: Request, ws: WorkspaceContext = ADMIN):
    return await request.app.state.audit_streams.list(ws.id)


@router.post("/audit/streams", status_code=201)
async def create_stream(body: NewStream, request: Request, ws: WorkspaceContext = ADMIN):
    """Forward the audit log to one of this workspace's Splunk, Sentinel or webhook destinations."""
    channel = await request.app.state.notifications.get_channel(body.channel_id, workspace_id=ws.id)
    if channel is None:
        raise HTTPException(status_code=404, detail="Destination not found")
    if channel["type"] not in KINDS:
        raise HTTPException(status_code=422, detail="Audit entries go to Splunk, Sentinel or a webhook destination")
    if body.platform and not ws.principal.platform_admin:
        raise HTTPException(status_code=403, detail="Only platform administrators can stream every workspace's entries")
    stream = await request.app.state.audit_streams.create(workspace_id=ws.id, channel_id=body.channel_id,
                                                          platform=body.platform, start=body.start,
                                                          by=ws.principal.name)  # fmt: skip
    await audit(request, ws.principal, "audit.stream_create", stream["id"],
                details={"channel": body.channel_id, "type": channel["type"], "platform": body.platform,
                         "start": body.start})  # fmt: skip
    return stream


async def _stream(request: Request, ws: WorkspaceContext, stream_id: str) -> dict:
    found = await request.app.state.audit_streams.get(stream_id, ws.id)
    if found is None:
        raise HTTPException(status_code=404, detail="Audit stream not found")
    return found


@router.patch("/audit/streams/{stream_id}")
async def change_stream(stream_id: str, body: StreamChange, request: Request, ws: WorkspaceContext = ADMIN):
    """Pause or resume a stream. Pausing can require a second administrator's approval."""
    await _stream(request, ws, stream_id)
    if not body.enabled:
        await require_approval(
            request, ws, "audit.stream_stop", stream_id, "Pause forwarding the audit log to the SIEM"
        )
    changed = await request.app.state.audit_streams.set_enabled(stream_id, ws.id, body.enabled)
    await audit(request, ws.principal, "audit.stream_resume" if body.enabled else "audit.stream_pause", stream_id)
    return changed


@router.delete("/audit/streams/{stream_id}", status_code=204)
async def delete_stream(stream_id: str, request: Request, ws: WorkspaceContext = ADMIN):
    await _stream(request, ws, stream_id)
    await require_approval(request, ws, "audit.stream_stop", stream_id, "Stop forwarding the audit log to the SIEM")
    await request.app.state.audit_streams.delete(stream_id, ws.id)
    await audit(request, ws.principal, "audit.stream_delete", stream_id)
    return Response(status_code=204)
