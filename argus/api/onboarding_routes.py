"""Guided first scan: a pre-flight check before scanning, and getting-started progress.

``POST /api/scan/preflight`` answers "what would happen if I scanned this?" without
scanning: the detected target type, whether it is allowed at all, exactly which sources
would run (and which would contact the target), and scope warnings. The same warnings are
recorded with the scan when it starts (see ``start_scan``), so the audit log shows what the
person was told.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from argus.api.deps import WorkspaceContext, in_workspace
from argus.core.models import EntityType
from argus.demo import demo_ids
from argus.modules import get_module_catalog
from argus.security.auth import Role
from argus.security.network import validate_scan_target
from argus.security.scope import as_dicts, assess

router = APIRouter(tags=["getting started"])
ANALYST = Depends(in_workspace(Role.ANALYST))
VIEWER = Depends(in_workspace(Role.VIEWER))

TYPE_LABELS = {
    "domain": "a domain",
    "subdomain": "a subdomain",
    "ip_address": "an IP address",
    "email": "an email address",
    "username": "a username",
    "phone": "a phone number",
    "person": "a person",
}


class PreflightRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    target_type: EntityType | None = None
    passive_only: bool = True


def scope_warnings(target: str, target_type: EntityType, passive_only: bool) -> list[dict[str, str]]:
    active = sum(1 for m in get_module_catalog().values() if m.active and m.is_configured())
    return as_dicts(assess(target, target_type, passive_only=passive_only, active_checks=active))


@router.post("/api/scan/preflight")
async def preflight(body: PreflightRequest, request: Request, ws: WorkspaceContext = ANALYST):
    from argus.cli.console import detect_target_type

    target = body.target.strip()
    ttype = body.target_type or detect_target_type(target)
    blocked = None
    if not request.app.state.settings.allow_private_targets:
        try:
            validate_scan_target(target, ttype)
        except ValueError as exc:
            blocked = str(exc)

    catalog = get_module_catalog().values()

    def describe(m: Any) -> dict[str, Any]:
        return {"name": m.name, "description": m.description, "handles_target": ttype in m.supported_entity_types}

    will_run = [m for m in catalog if m.is_configured() and not (body.passive_only and m.active)]
    recent = None
    for row in await request.app.state.repo.list_investigations(workspace_id=ws.id, target=target, limit=10):
        created = datetime.fromisoformat(row["created_at"])
        created = created if created.tzinfo else created.replace(tzinfo=timezone.utc)
        if row["target"].lower() == target.lower() and datetime.now(timezone.utc) - created < timedelta(days=1):
            recent = {"id": row["id"], "status": row["status"], "created_at": row["created_at"]}
            break
    return {
        "target": target,
        "target_type": ttype.value,
        "type_label": TYPE_LABELS.get(ttype.value, ttype.value.replace("_", " ")),
        "allowed": blocked is None,
        "blocked_reason": blocked,
        "warnings": scope_warnings(target, ttype, body.passive_only),
        "sources": {
            "passive": [describe(m) for m in will_run if not m.active],
            "active": [describe(m) for m in will_run if m.active],
            "needs_key": [
                {"name": m.name, "requires": list(m.requires_settings)} for m in catalog if not m.is_configured()
            ],
        },
        "contacts_target": any(m.active for m in will_run),
        "recent": recent,
    }


@router.get("/api/onboarding")
async def onboarding(request: Request, ws: WorkspaceContext = VIEWER):
    """Getting-started progress for this workspace, derived from what has actually been done."""
    state = request.app.state
    demo = set(demo_ids(ws.id))
    investigations = await state.repo.list_investigations(workspace_id=ws.id, limit=50)
    completed = [r for r in investigations if r["status"] == "completed"]
    own = [r for r in completed if r["id"] not in demo]
    admin = ws.role == Role.ADMIN
    analyst = ws.role in (Role.ANALYST, Role.ADMIN)
    steps = [
        {"id": "demo", "done": any(r["id"] in demo for r in investigations), "available": admin},
        {"id": "first_scan", "done": bool(own), "available": analyst},
        {"id": "watch", "done": bool(await state.monitors.list_monitors(workspace_id=ws.id)),
         "available": analyst},
        {"id": "destination", "done": bool(admin and await state.notifications.list_channels(workspace_id=ws.id)),
         "available": admin},
        {"id": "report", "done": bool(await state.reports.list_reports(workspace_id=ws.id, limit=1)),
         "available": analyst},
        {"id": "schedule", "done": bool(admin and await state.schedules.list_schedules(workspace_id=ws.id)),
         "available": admin},
    ]  # fmt: skip
    return {
        "steps": steps,
        "first_scan_id": own[0]["id"] if own else None,
        "latest_id": completed[0]["id"] if completed else None,
    }
