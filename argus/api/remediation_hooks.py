"""Where remediation meets the rest of Argus.

* **Scans** verify or reopen attack-path tasks (every completed scan of the target), and, for
  monitored targets with automation on, open tasks for qualifying attack paths.
* **Supplier assessments** close a supplier's task when it meets its minimum grade again, and
  open (or reopen) one when it falls below.
* **Exposure checks** open tasks for qualifying new findings. Resolving a finding closes its
  task, and closing a task resolves its finding, so the two pages never disagree.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import FastAPI

from argus.core.graph import IntelligenceGraph
from argus.core.models import Investigation, InvestigationStatus
from argus.intel.paths import find_attack_paths
from argus.intel.remediation import ACTIVE, from_exposure, from_path, from_supplier, meets_threshold, scan_scope

logger = logging.getLogger("argus.remediation")
SYSTEM = "Argus automation"


async def ensure_task(app: FastAPI, workspace_id: str, fields: dict[str, Any], *, reopen_text: str) -> dict[str, Any]:
    """Open a task for a finding, or reopen its closed task (one task per finding, with its history)."""
    repo = app.state.remediation
    task, created = await repo.create(workspace_id=workspace_id, by=SYSTEM, fields=fields,
                                      note="Opened automatically by the workspace's remediation policy")  # fmt: skip
    if not created and task["status"] == "verified":
        task = await repo.update(task["id"], workspace_id=workspace_id, by=SYSTEM, changes={"status": "open"},
                                 note=reopen_text)  # fmt: skip
    return task


async def after_scan(app: FastAPI, inv: Investigation, graph: IntelligenceGraph, *, truncated: bool) -> dict[str, Any]:
    """Every completed scan: evidence for (or against) the attack-path tasks of its target."""
    if inv.status != InvestigationStatus.COMPLETED:
        return {}
    paths = find_attack_paths(graph)["paths"]
    target = inv.config.target.strip().lower()
    scan = {**scan_scope(inv.config), "truncated": truncated}
    outcome = await app.state.remediation.apply_scan(
        workspace_id=inv.workspace_id, target=target, present={p["id"] for p in paths}, scan=scan,
        investigation_id=inv.id,
    )  # fmt: skip
    created = []
    if inv.monitor_id:
        policy = await app.state.remediation.policy(workspace_id=inv.workspace_id)
        for path in paths:
            if meets_threshold(path["severity"], policy["auto_create"]):
                fields = from_path(path, target=target, investigation_id=inv.id, scope=scan_scope(inv.config))
                task = await ensure_task(
                    app, inv.workspace_id, fields, reopen_text="Regression: the attack path is back"
                )
                created.append(task["id"])
    if outcome["verified"] or outcome["reopened"] or created:
        logger.info("Remediation after %s: %d verified, %d reopened, %d opened", inv.id, len(outcome["verified"]),
                    len(outcome["reopened"]), len(created))  # fmt: skip
    return {**outcome, "opened": created}


async def after_supplier_assessment(
    app: FastAPI, workspace_id: str, supplier: dict[str, Any], *, grade: str, floor: str | None, below: bool
) -> None:
    repo = app.state.remediation
    if not below:
        await repo.close_source(workspace_id=workspace_id, source_type="supplier", source_key=supplier["id"],
                                by=SYSTEM, text=f"Verified: rated {grade}, which meets the minimum {floor or ''}".strip())  # fmt: skip
        return
    policy = await repo.policy(workspace_id=workspace_id)
    severity = "critical" if supplier["tier"] == "critical" else "high"
    if meets_threshold(severity, policy["auto_create"]):
        view = {**supplier, "grade": grade, "min_grade": floor}
        await ensure_task(
            app, workspace_id, from_supplier(view), reopen_text=f"Fell below the minimum again: rated {grade}"
        )


async def after_exposure_check(app: FastAPI, workspace_id: str, new: list[dict[str, Any]]) -> None:
    policy = await app.state.remediation.policy(workspace_id=workspace_id)
    for finding in new:
        if meets_threshold(finding["severity"], policy["auto_create"]):
            await ensure_task(app, workspace_id, from_exposure(finding), reopen_text="Seen again")


async def exposure_triaged(app: FastAPI, workspace_id: str, finding_ids: list[str], status: str, by: str) -> None:
    """Findings resolved or accepted on the Exposure page close their tasks."""
    repo = app.state.remediation
    for finding_id in finding_ids:
        if status == "resolved":
            await repo.close_source(workspace_id=workspace_id, source_type="exposure", source_key=finding_id, by=by,
                                    text="Verified: the finding was resolved on the Exposure page")  # fmt: skip
        elif status == "accepted":
            task = await repo.by_source(workspace_id, "exposure", finding_id)
            if task and task["status"] in ACTIVE:
                until = datetime.now(timezone.utc) + timedelta(days=365)
                await repo.update(task["id"], workspace_id=workspace_id, by=by,
                                  changes={"status": "accepted", "accepted_until": until},
                                  note="The finding's risk was accepted on the Exposure page")  # fmt: skip
