"""Notification channels and integrations, and their deliveries.

Channels: Slack, Microsoft Teams, email and signed webhooks. Integrations: Jira and ServiceNow
(alerts become tickets) and Splunk and Microsoft Sentinel (alerts and reports become events).

Workspace administrators manage their own workspace's channels; nothing here is visible
from another workspace (foreign ids answer 404). Destination URLs are write-only: after
creation only a masked hint is returned, and a webhook's signing secret is shown once.
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from argus.api.deps import WorkspaceContext, audit, in_workspace
from argus.notify import render
from argus.notify.channels import INTEGRATIONS, SEVERITIES, TICKETING, TYPES, ChannelConfigError, validate
from argus.security.auth import Role
from argus.storage.notification_repo import NotificationRepository

router = APIRouter(prefix="/api/notifications", tags=["notifications"])
ADMIN = Depends(in_workspace(Role.ADMIN))
VIEWER = Depends(in_workspace(Role.VIEWER))

ChannelType = Literal["slack", "teams", "webhook", "email", "jira", "servicenow", "splunk", "sentinel"]
Severity = Literal["low", "medium", "high", "critical"]


class Destination(BaseModel):
    """Where a channel sends. Which fields apply depends on the channel type (see docs/API.md).

    Credentials (``api_token``, ``password``, ``token``, ``client_secret``) are write-only: they are
    encrypted and never returned. When editing, leave one out to keep the saved value, which
    works only while the host stays the same.
    """

    url: str | None = Field(default=None, max_length=2048, description="Webhook URL, or the site/collector URL")
    recipients: list[str] | str | None = Field(default=None, description="Email: up to 20 addresses")
    # Jira
    project_key: str | None = Field(default=None, max_length=16, examples=["SEC"])
    issue_type: str | None = Field(default=None, max_length=64, examples=["Task"])
    email: str | None = Field(default=None, max_length=254, description="Jira Cloud: the API token's account")
    api_token: str | None = Field(default=None, max_length=1024, description="Jira API token or personal access token")
    # ServiceNow
    username: str | None = Field(default=None, max_length=128)
    password: str | None = Field(default=None, max_length=1024)
    assignment_group: str | None = Field(default=None, max_length=100)
    # Splunk HTTP Event Collector
    token: str | None = Field(default=None, max_length=1024, description="Splunk HEC token")
    index: str | None = Field(default=None, max_length=80)
    sourcetype: str | None = Field(default=None, max_length=100)
    # Microsoft Sentinel (Logs Ingestion API)
    dce_url: str | None = Field(default=None, max_length=2048, description="Data collection endpoint URL")
    dcr_id: str | None = Field(default=None, max_length=64, description="Data collection rule immutable ID")
    stream: str | None = Field(default=None, max_length=120, examples=["Custom-ArgusEvents_CL"])
    tenant_id: str | None = Field(default=None, max_length=253)
    client_id: str | None = Field(default=None, max_length=64)
    client_secret: str | None = Field(default=None, max_length=1024)


class CreateChannelRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    type: ChannelType
    min_severity: Severity = "high"
    enabled: bool = True
    destination: Destination


class UpdateChannelRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    min_severity: Severity | None = None
    enabled: bool | None = None
    destination: Destination | None = None


def _repo(request: Request) -> NotificationRepository:
    repo: NotificationRepository = request.app.state.notifications
    return repo


def _validated(
    request: Request, channel_type: str, destination: Destination, current: dict[str, Any] | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    if channel_type == "email" and not request.app.state.settings.smtp_host:
        raise HTTPException(
            status_code=409, detail="Email isn't configured on this server (ask an operator to set ARGUS_SMTP_HOST)"
        )
    try:
        return validate(
            channel_type,
            destination.model_dump(exclude_none=True),
            allow_private=request.app.state.settings.allow_private_targets,
            private_ok=request.app.state.settings.integration_allowed_hosts,
            current=current,
        )
    except ChannelConfigError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/capabilities")
async def capabilities(request: Request, _: WorkspaceContext = VIEWER):
    """Which channel types this server can use (the UI hides the rest)."""
    settings = request.app.state.settings
    secure_storage = _repo(request).box.available
    return {
        "types": [t for t in TYPES if (t == "email" and settings.smtp_host) or (t != "email" and secure_storage)],
        "email": bool(settings.smtp_host),
        "encryption": secure_storage,
        "severities": list(SEVERITIES),
        "public_url": bool(settings.public_url),
        "integrations": [t for t in INTEGRATIONS if secure_storage],
        "ticketing": list(TICKETING),
        "private_hosts_allowed": len(settings.integration_allowed_hosts),
    }


@router.get("/channels")
async def list_channels(request: Request, ws: WorkspaceContext = ADMIN):
    return await _repo(request).list_channels(workspace_id=ws.id)


@router.post("/channels", status_code=201)
async def create_channel(body: CreateChannelRequest, request: Request, ws: WorkspaceContext = ADMIN):
    public, secret_values = _validated(request, body.type, body.destination)
    try:
        channel, signing_secret = await _repo(request).create_channel(
            workspace_id=ws.id,
            name=body.name.strip(),
            channel_type=body.type,
            min_severity=body.min_severity,
            enabled=body.enabled,
            public=public,
            secret_values=secret_values,
            by=ws.principal.name,
        )
    except ChannelConfigError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await audit(
        request,
        ws.principal,
        "notification.channel_create",
        channel["id"],
        details={"type": body.type, "name": channel["name"], "min_severity": body.min_severity, **public},
    )
    if signing_secret:
        channel["signing_secret"] = signing_secret  # shown once
    return channel


@router.patch("/channels/{channel_id}")
async def update_channel(channel_id: str, body: UpdateChannelRequest, request: Request, ws: WorkspaceContext = ADMIN):
    repo = _repo(request)
    current = await repo.get_channel(channel_id, workspace_id=ws.id)
    if current is None:
        raise HTTPException(status_code=404, detail="Channel not found")
    public = secret_values = None
    if body.destination is not None:
        saved = await repo.channel_secrets(channel_id, workspace_id=ws.id) if current["type"] in INTEGRATIONS else None
        public, secret_values = _validated(request, current["type"], body.destination, saved)
    try:
        updated = await repo.update_channel(
            channel_id,
            workspace_id=ws.id,
            name=body.name.strip() if body.name else None,
            min_severity=body.min_severity,
            enabled=body.enabled,
            public=public,
            secret_values=secret_values,
        )
    except ChannelConfigError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if updated is None:
        raise HTTPException(status_code=404, detail="Channel not found")
    changes = body.model_dump(exclude_none=True, exclude={"destination"})
    if public is not None:
        changes["destination"] = public
    await audit(request, ws.principal, "notification.channel_update", channel_id, details=changes)
    return updated


@router.delete("/channels/{channel_id}", status_code=204)
async def delete_channel(channel_id: str, request: Request, ws: WorkspaceContext = ADMIN):
    if not await _repo(request).delete_channel(channel_id, workspace_id=ws.id):
        raise HTTPException(status_code=404, detail="Channel not found")
    await audit(request, ws.principal, "notification.channel_delete", channel_id)
    return Response(status_code=204)


@router.post("/channels/{channel_id}/test", status_code=202)
async def send_test(channel_id: str, request: Request, ws: WorkspaceContext = ADMIN):
    """Queue a test message through the real pipeline (signing, retries, delivery log)."""
    repo = _repo(request)
    channel = await repo.get_channel(channel_id, workspace_id=ws.id)
    if channel is None:
        raise HTTPException(status_code=404, detail="Channel not found")
    event = render.probe_event(ws.workspace, channel["name"], ws.principal.name)
    delivery = await repo.enqueue_test(channel_id, workspace_id=ws.id, event=event)
    await audit(request, ws.principal, "notification.channel_test", channel_id)
    return delivery


@router.post("/channels/{channel_id}/rotate-secret")
async def rotate_secret(channel_id: str, request: Request, ws: WorkspaceContext = ADMIN):
    """New webhook signing secret; the previous one stays valid for 24 hours."""
    secret = await _repo(request).rotate_secret(channel_id, workspace_id=ws.id)
    if secret is None:
        raise HTTPException(status_code=404, detail="Webhook channel not found")
    await audit(request, ws.principal, "notification.secret_rotate", channel_id)
    return {"signing_secret": secret, "previous_valid_hours": 24}


@router.get("/deliveries")
async def list_deliveries(
    request: Request,
    ws: WorkspaceContext = ADMIN,
    channel_id: str | None = Query(None, max_length=32),
    status: Literal["pending", "sending", "delivered", "failed", "cancelled"] | None = None,
    limit: int = Query(50, ge=1, le=200),
):
    return await _repo(request).deliveries(workspace_id=ws.id, channel_id=channel_id, status=status, limit=limit)


@router.post("/deliveries/{delivery_id}/retry")
async def retry_delivery(delivery_id: str, request: Request, ws: WorkspaceContext = ADMIN):
    delivery = await _repo(request).retry(delivery_id, workspace_id=ws.id)
    if delivery is None:
        raise HTTPException(status_code=404, detail="Delivery not found")
    await audit(request, ws.principal, "notification.delivery_retry", delivery_id)
    return delivery
