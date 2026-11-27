"""Remediation: tasks from findings, deadlines, triage, verification and metrics."""

from __future__ import annotations

import io
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from argus.api.deps import WorkspaceContext, audit, in_workspace
from argus.core import csvsafe
from argus.intel.paths import find_attack_paths
from argus.intel.remediation import (
    ACTIVE,
    CLOSED,
    DEFAULT_SLA_DAYS,
    MAX_ACCEPTANCE,
    SEVERITIES,
    from_exposure,
    from_path,
    from_supplier,
    metrics,
    scan_scope,
    transition_error,
)
from argus.intel.suppliers import min_grade as supplier_min_grade
from argus.security.auth import Role

router = APIRouter(prefix="/api/remediation", tags=["remediation"])
VIEWER = Depends(in_workspace(Role.VIEWER))
ANALYST = Depends(in_workspace(Role.ANALYST))
ADMIN = Depends(in_workspace(Role.ADMIN))

Severity = Literal["critical", "high", "medium", "low"]
Status = Literal["open", "in_progress", "fixed", "verified", "accepted"]


class Source(BaseModel):
    type: Literal["attack_path", "exposure", "supplier", "manual"]
    investigation_id: str | None = Field(default=None, max_length=64, description="attack_path: the scan")
    path_id: str | None = Field(default=None, max_length=64, description="attack_path: the path")
    finding_id: str | None = Field(default=None, max_length=32, description="exposure: the finding")
    supplier_id: str | None = Field(default=None, max_length=32, description="supplier: the supplier")
    title: str | None = Field(default=None, max_length=300, description="manual: what needs doing")
    description: str | None = Field(default=None, max_length=4000)
    severity: Severity | None = None
    target: str | None = Field(default=None, max_length=253)


class CreateTask(BaseModel):
    source: Source
    assignee: str | None = Field(default=None, max_length=128)
    due_at: datetime | None = Field(default=None, description="Defaults to the workspace's deadline for the severity")
    external_ref: str | None = Field(default=None, max_length=128, examples=["SEC-142"])
    note: str = Field(default="", max_length=2000)


class UpdateTask(BaseModel):
    status: Status | None = None
    assignee: str | None = Field(default=None, max_length=128, description="Empty string unassigns")
    due_at: datetime | None = None
    severity: Severity | None = None
    title: str | None = Field(default=None, min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=4000)
    external_ref: str | None = Field(default=None, max_length=128)
    accepted_until: datetime | None = Field(default=None, description="Required when accepting the risk (max 1 year)")
    note: str = Field(default="", max_length=2000, description="Why: recorded on the task's timeline")


class Comment(BaseModel):
    text: str = Field(min_length=1, max_length=2000)


class Policy(BaseModel):
    sla_days: dict[str, int] = Field(default_factory=lambda: dict(DEFAULT_SLA_DAYS), examples=[DEFAULT_SLA_DAYS])
    auto_create: Literal["off", "critical", "high"] = "off"


def _repo(request: Request) -> Any:
    return request.app.state.remediation


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


async def _fields_for(request: Request, ws: WorkspaceContext, source: Source) -> dict[str, Any]:
    """Build a task from its finding, read from the workspace (so nothing about it is taken on trust)."""
    app = request.app
    if source.type == "attack_path":
        if not (source.investigation_id and source.path_id):
            raise HTTPException(status_code=422, detail="Give the investigation_id and path_id")
        inv = await app.state.repo.get_investigation(source.investigation_id)
        graph = await app.state.repo.load_graph(source.investigation_id) if inv else None
        if inv is None or inv.workspace_id != ws.id or graph is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        path = next((p for p in find_attack_paths(graph)["paths"] if p["id"] == source.path_id), None)
        if path is None:
            raise HTTPException(status_code=404, detail="Attack path not found in that investigation")
        return from_path(path, target=inv.config.target.strip().lower(), investigation_id=inv.id,
                         scope=scan_scope(inv.config))  # fmt: skip
    if source.type == "exposure":
        findings = await app.state.exposure.findings(workspace_id=ws.id)
        finding = next((f for f in findings if f["id"] == source.finding_id), None)
        if finding is None:
            raise HTTPException(status_code=404, detail="Exposure finding not found")
        return from_exposure(finding)
    if source.type == "supplier":
        supplier = await app.state.suppliers.get(source.supplier_id or "", workspace_id=ws.id)
        if supplier is None:
            raise HTTPException(status_code=404, detail="Supplier not found")
        floor = supplier_min_grade(supplier["tier"], supplier["min_grade_override"])
        return from_supplier({**supplier, "grade": supplier["last_grade"] or "unrated", "min_grade": floor or "none"})
    if not source.title or not source.severity:
        raise HTTPException(status_code=422, detail="A manual task needs a title and a severity")
    return {"source_type": "manual", "source_key": None, "target": (source.target or "").strip().lower(),
            "title": source.title.strip(), "description": (source.description or "").strip(),
            "severity": source.severity, "details": {}}  # fmt: skip


async def _sync_exposure(request: Request, ws: WorkspaceContext, task: dict[str, Any], status: str, note: str) -> None:
    """Closing an exposure task resolves its finding (and accepting it accepts the finding)."""
    if task["source_type"] != "exposure" or status not in ("fixed", "verified", "accepted", "open"):
        return
    finding_status = {"fixed": "resolved", "verified": "resolved", "accepted": "accepted", "open": "open"}[status]
    await request.app.state.exposure.set_status([task["source_key"]], workspace_id=ws.id, status=finding_status,
                                                by=ws.principal.name, note=note or f"Remediation task {task['id']}")  # fmt: skip


# ---------------------------------------------------------------------------- reading
@router.get("")
async def list_tasks(
    request: Request,
    ws: WorkspaceContext = VIEWER,
    status: Literal["active", "closed", "all", "open", "in_progress", "fixed", "verified", "accepted"] = "active",
    assignee: str | None = Query(None, max_length=128, description="A name, 'me', or 'unassigned'"),
    severity: Severity | None = None,
    source_type: Literal["attack_path", "exposure", "supplier", "manual"] | None = None,
    overdue: bool = False,
):
    """Tasks (most urgent first) with the workspace's metrics and policy."""
    repo = _repo(request)
    every = await repo.list_tasks(workspace_id=ws.id)
    wanted = {"active": ACTIVE, "closed": CLOSED, "all": ACTIVE + CLOSED}.get(status, (status,))
    who = ws.principal.name if assignee == "me" else assignee
    tasks = [
        t for t in every
        if t["status"] in wanted
        and (assignee is None or (t["assignee"] or "") == ("" if who == "unassigned" else who))
        and (severity is None or t["severity"] == severity)
        and (source_type is None or t["source_type"] == source_type)
        and (not overdue or t["overdue"])
    ]  # fmt: skip
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    tasks.sort(key=lambda t: (t["status"] in CLOSED, not t["overdue"], t["due_at"] or "", rank[t["severity"]]))
    members = await request.app.state.workspaces.members(ws.id)
    people = sorted(
        {m["email"] for m in members if not m["disabled"]} | {t["assignee"] for t in every if t["assignee"]}
    )
    return {
        "tasks": tasks,
        "metrics": metrics(every, datetime.now(timezone.utc)),
        "policy": await repo.policy(workspace_id=ws.id),
        "assignees": people,
        "me": ws.principal.name,
    }


@router.get("/policy")
async def get_policy(request: Request, ws: WorkspaceContext = VIEWER):
    return await _repo(request).policy(workspace_id=ws.id)


@router.put("/policy")
async def set_policy(body: Policy, request: Request, ws: WorkspaceContext = ADMIN):
    """Deadlines by severity (1-365 days) and whether new findings open tasks automatically."""
    if set(body.sla_days) - set(SEVERITIES):
        raise HTTPException(status_code=422, detail=f"Deadlines are set per severity: {', '.join(SEVERITIES)}")
    days = {**DEFAULT_SLA_DAYS, **body.sla_days}
    if any(not 1 <= d <= 365 for d in days.values()):
        raise HTTPException(status_code=422, detail="Deadlines must be between 1 and 365 days")
    policy = await _repo(request).set_policy(workspace_id=ws.id, sla_days=days, auto_create=body.auto_create,
                                             by=ws.principal.name)  # fmt: skip
    await audit(
        request, ws.principal, "remediation.policy", None, details={"sla_days": days, "auto_create": body.auto_create}
    )
    return policy


@router.get("/export.csv")
async def export_tasks(request: Request, ws: WorkspaceContext = VIEWER):
    tasks = await _repo(request).list_tasks(workspace_id=ws.id)
    out = io.StringIO()
    writer = csvsafe.writer(out)
    writer.writerow(["ID", "Title", "Severity", "Status", "Assignee", "Due", "Overdue", "Source", "Target", "Ticket",
                     "Created", "Closed", "Verified by", "Reopened"])  # fmt: skip
    for t in tasks:
        writer.writerow([t["id"], t["title"], t["severity"], t["status"], t["assignee"] or "", (t["due_at"] or "")[:10],
                         "yes" if t["overdue"] else "", t["source_type"], t["target"], t["external_ref"] or "",
                         (t["created_at"] or "")[:10], (t["closed_at"] or "")[:10], t["verified_by"] or "",
                         t["reopen_count"]])  # fmt: skip
    await audit(request, ws.principal, "remediation.export", None, details={"tasks": len(tasks)})
    return Response(out.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="remediation.csv"'})  # fmt: skip


@router.get("/{task_id}")
async def get_task(task_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    task = await _repo(request).get(task_id, workspace_id=ws.id, events=True)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


# ---------------------------------------------------------------------------- changing
@router.post("", status_code=201)
async def create_task(body: CreateTask, request: Request, response: Response, ws: WorkspaceContext = ANALYST):
    """Open a task for a finding. A finding that already has a task returns it (HTTP 200)."""
    fields = await _fields_for(request, ws, body.source)
    task, created = await _repo(request).create(
        workspace_id=ws.id, by=ws.principal.name, fields=fields, assignee=(body.assignee or "").strip() or None,
        due_at=_aware(body.due_at) if body.due_at else None, external_ref=body.external_ref, note=body.note,
    )  # fmt: skip
    if not created:
        response.status_code = 200
        return {**task, "created": False}
    await audit(request, ws.principal, "remediation.create", task["id"],
                details={"source": fields["source_type"], "title": task["title"], "assignee": task["assignee"]})  # fmt: skip
    return {**task, "created": True}


@router.patch("/{task_id}")
async def update_task(task_id: str, body: UpdateTask, request: Request, ws: WorkspaceContext = ANALYST):
    repo = _repo(request)
    task = await repo.get(task_id, workspace_id=ws.id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    changes = body.model_dump(exclude_unset=True, exclude={"note"})
    now = datetime.now(timezone.utc)
    if "assignee" in changes:
        changes["assignee"] = (changes["assignee"] or "").strip() or None
    if changes.get("due_at"):
        changes["due_at"] = _aware(changes["due_at"])
        if changes["due_at"] > now + timedelta(days=730):
            raise HTTPException(status_code=422, detail="Set a due date within two years")
    status = changes.get("status")
    if status:
        if error := transition_error(task, status):
            raise HTTPException(status_code=409, detail=error)
        if status == "accepted":
            until = _aware(changes["accepted_until"]) if changes.get("accepted_until") else None
            if until is None or not now < until <= now + MAX_ACCEPTANCE:
                raise HTTPException(status_code=422, detail="Accepting a risk needs an end date within the next year")
            if len(body.note.strip()) < 5:
                raise HTTPException(status_code=422, detail="Say why the risk is accepted")
            changes["accepted_until"] = until
    if status != "accepted":
        changes.pop("accepted_until", None)  # only meaningful together with accepting the risk
    updated = await repo.update(task_id, workspace_id=ws.id, by=ws.principal.name, changes=changes, note=body.note)
    if status:
        await _sync_exposure(request, ws, updated, status, body.note)
    await audit(request, ws.principal, "remediation.update", task_id,
                details={k: str(v) for k, v in {**changes, "note": body.note}.items() if v not in (None, "")})  # fmt: skip
    return updated


@router.post("/{task_id}/comments", status_code=201)
async def comment(task_id: str, body: Comment, request: Request, ws: WorkspaceContext = ANALYST):
    if not await _repo(request).comment(task_id, workspace_id=ws.id, by=ws.principal.name, text=body.text.strip()):
        raise HTTPException(status_code=404, detail="Task not found")
    return await _repo(request).get(task_id, workspace_id=ws.id, events=True)


@router.post("/{task_id}/rescan", status_code=202)
async def rescan(task_id: str, request: Request, ws: WorkspaceContext = ANALYST):
    """Rescan the target exactly as it was first scanned, to verify the fix with evidence."""
    task = await _repo(request).get(task_id, workspace_id=ws.id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    if task["source_type"] != "attack_path":
        raise HTTPException(status_code=409, detail="Only attack-path tasks are verified by scanning")
    original = await request.app.state.repo.get_investigation(task["details"].get("found_in", ""))
    if original is None or original.workspace_id != ws.id:
        raise HTTPException(
            status_code=409, detail="The scan that found this path is gone; start a scan of the target instead"
        )
    purpose = f"Remediation verification of {task_id} ({task['title']}); original purpose: {original.purpose or ''}"[
        :500
    ]
    inv_id = await request.app.state.rescan(original.config, ws.principal, purpose, ws.id)
    await _repo(request).comment(task_id, workspace_id=ws.id, by=ws.principal.name,
                                 text=f"Verification scan started: {inv_id}")  # fmt: skip
    await audit(request, ws.principal, "remediation.rescan", task_id, details={"investigation_id": inv_id})
    return {"status": "launched", "investigation_id": inv_id}


@router.delete("/{task_id}", status_code=204)
async def delete_task(task_id: str, request: Request, ws: WorkspaceContext = ADMIN):
    """Delete a task created by mistake. To stop tracking a real finding, accept its risk instead."""
    if not await _repo(request).delete(task_id, workspace_id=ws.id):
        raise HTTPException(status_code=404, detail="Task not found")
    await audit(request, ws.principal, "remediation.delete", task_id)
    return Response(status_code=204)
