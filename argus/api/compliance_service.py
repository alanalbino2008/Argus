"""Gather a workspace's evidence for compliance mapping (see argus/intel/compliance.py)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from argus.intel.executive import redact
from argus.intel.paths import find_attack_paths
from argus.intel.remediation import ACTIVE
from argus.intel.remediation import metrics as remediation_metrics

MAX_OWN_TARGETS = 20


def _task(sources: dict[str, dict[str, Any]], key: str) -> dict[str, Any] | None:
    task = sources.get(key)
    return task if task and task["status"] in ACTIVE else None


async def evidence_context(app: Any, workspace_id: str) -> dict[str, Any]:
    from argus.api.rating_routes import ensure_history
    from argus.api.supplier_routes import supplier_view

    state = app.state
    remediation = state.remediation
    path_tasks = await remediation.sources(workspace_id=workspace_id, source_type="attack_path")
    exposure_tasks = await remediation.sources(workspace_id=workspace_id, source_type="exposure")
    supplier_tasks = await remediation.sources(workspace_id=workspace_id, source_type="supplier")

    exposure_by_subject = await state.exposure.open_by_subject(workspace_id=workspace_id)
    suppliers = []
    for s in await state.suppliers.list_suppliers(workspace_id=workspace_id):
        view = await supplier_view(app, workspace_id, s)
        view["exposure"] = exposure_by_subject.get(s["domain"], {})
        view["task"] = _task(supplier_tasks, s["id"])
        suppliers.append(view)
    supplier_domains = {s["domain"] for s in suppliers}

    await ensure_history(app, workspace_id)
    own_scans: list[dict[str, Any]] = []
    paths: list[dict[str, Any]] = []
    for rating in (await state.ratings.latest_per_target(workspace_id=workspace_id))[:MAX_OWN_TARGETS]:
        target = rating["target"]
        if target in supplier_domains:
            continue
        inv = await state.repo.get_investigation(rating["investigation_id"])
        graph = await state.repo.load_graph(rating["investigation_id"]) if inv else None
        if inv is None or graph is None:
            continue
        completed = inv.completed_at or inv.created_at
        own_scans.append({"target": target, "investigation_id": inv.id, "completed_at": completed.isoformat()})
        paths.extend(
            {"rule": p["rule"], "severity": p["severity"], "title": redact(p["title"]), "target": target,
             "path_id": p["id"], "investigation_id": inv.id, "task": _task(path_tasks, f"{target}|{p['id']}")}
            for p in find_attack_paths(graph)["paths"]
        )  # fmt: skip

    findings = [
        {"kind": f["kind"], "severity": f["severity"], "title": redact(f["title"]), "target": f["subject"],
         "finding_id": f["id"], "account_masked": f["account_masked"], "task": _task(exposure_tasks, f["id"])}
        for f in await state.exposure.findings(workspace_id=workspace_id, status="open")
        if not f["supplier_id"]
    ]  # fmt: skip
    watches = await state.exposure.list_watches(workspace_id=workspace_id)
    tasks = await remediation.list_tasks(workspace_id=workspace_id)
    return {
        "own_scans": own_scans,
        "paths": paths,
        "exposure_findings": findings,
        "exposure_watches": sum(1 for w in watches if w["scope"] == "domain" and w["enabled"]),
        "suppliers": suppliers,
        "monitors": await state.monitors.list_monitors(workspace_id=workspace_id),
        "channels": await state.notifications.list_channels(workspace_id=workspace_id),
        "remediation": remediation_metrics(tasks, datetime.now(timezone.utc)) if tasks else None,
        "policy": await remediation.policy(workspace_id=workspace_id),
    }
