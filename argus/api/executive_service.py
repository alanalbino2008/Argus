"""Collect a workspace's numbers for the executive view (used by the API and the report scheduler)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from argus.intel.exposure import summarise
from argus.intel.paths import find_attack_paths
from argus.intel.remediation import metrics as remediation_metrics

MAX_OWN_TARGETS = 10  # attack-path graphs loaded to find critical paths nobody owns
TREND_POINTS = 8


async def collect(app: Any, workspace_id: str, days: int) -> dict[str, Any]:
    from argus.api.rating_routes import ensure_history
    from argus.api.supplier_routes import supplier_view

    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)

    # Suppliers first: their domains are someone else's attack surface, not yours.
    suppliers = [await supplier_view(app, workspace_id, s)
                 for s in await app.state.suppliers.list_suppliers(workspace_id=workspace_id)]  # fmt: skip
    exposure_by_subject = await app.state.exposure.open_by_subject(workspace_id=workspace_id)
    for s in suppliers:
        s["exposure"] = exposure_by_subject.get(s["domain"], {})
    supplier_domains = {s["domain"] for s in suppliers}

    await ensure_history(app, workspace_id)
    organisations = []
    for r in await app.state.ratings.latest_per_target(workspace_id=workspace_id):
        if r["target"] in supplier_domains:
            continue
        history = await app.state.ratings.history(r["target"], workspace_id=workspace_id, limit=TREND_POINTS)
        organisations.append({
            "target": r["target"], "grade": r["grade"], "score": r["score"], "investigation_id": r["investigation_id"],
            "critical_issues": r.get("critical_issues", 0), "history": history,
            "trend": [h["score"] for h in history],
            "change": round(history[-1]["score"] - history[0]["score"], 1) if len(history) > 1 else None,
        })  # fmt: skip

    findings = await app.state.exposure.findings(workspace_id=workspace_id, reveal=True)
    own_open: dict[str, int] = {}
    for f in findings:
        if f["status"] == "open" and not f["supplier_id"]:
            own_open[f["kind"]] = own_open.get(f["kind"], 0) + 1
    watches = await app.state.exposure.list_watches(workspace_id=workspace_id)

    tasks = await app.state.remediation.list_tasks(workspace_id=workspace_id)
    tracked = await app.state.remediation.sources(workspace_id=workspace_id, source_type="attack_path")
    untracked: list[dict[str, Any]] = []
    for org in sorted(organisations, key=lambda o: o["score"])[:MAX_OWN_TARGETS]:
        graph = await app.state.repo.load_graph(org["investigation_id"])
        if graph is None:
            continue
        untracked.extend(
            {"id": p["id"], "title": p["title"], "severity": p["severity"], "target": org["target"],
             "investigation_id": org["investigation_id"]}
            for p in find_attack_paths(graph)["paths"]
            if p["severity"] == "critical" and f"{org['target']}|{p['id']}" not in tracked
        )  # fmt: skip

    alerts = [a for a in await app.state.monitors.alerts(workspace_id=workspace_id, limit=500)
              if a["created_at"] and datetime.fromisoformat(a["created_at"]) >= since]  # fmt: skip
    return {
        "organisations": organisations,
        "suppliers": suppliers,
        "exposure_summary": summarise([f for f in findings if not f["supplier_id"]]),
        "exposure_own": own_open,
        "exposure_watched": sum(1 for w in watches if w["scope"] == "domain"),
        "remediation": remediation_metrics(tasks, now) if tasks else None,
        "active_tasks": [t for t in tasks if t["status"] in ("open", "in_progress", "fixed")],
        "untracked_critical": len(untracked),
        "untracked_paths": untracked,
        "alerts": alerts,
        "watched": len(await app.state.monitors.list_monitors(workspace_id=workspace_id)) + len(watches),
    }


BOARD_TARGET = "Board report"


async def issue_board_report(
    app: Any,
    workspace: dict[str, Any],
    *,
    days: int,
    tlp: str,
    prepared_for: str,
    issued_by: str,
    trigger: str = "manual",
    keep_file_for: Any = None,
    after_record: Any = None,
) -> dict[str, Any]:
    """Render, fingerprint and register a board report (one code path for the API and schedules)."""
    import hashlib

    import anyio

    from argus import __version__
    from argus.intel.executive import assess
    from argus.observability import metrics
    from argus.reports.board import render_board_pdf
    from argus.reports.data import new_report_id
    from argus.reports.service import default_issuer

    summary = assess(await collect(app, workspace["id"], days), datetime.now(timezone.utc), days)
    branding = await app.state.reports.branding(workspace["id"], default_org=default_issuer(workspace))
    base = app.state.settings.public_url
    verify_url = f"{base.rstrip('/')}/api/reports/verify/<sha256>" if base else None
    report_id, generated_at = new_report_id(), datetime.now(timezone.utc)
    pdf = await anyio.to_thread.run_sync(lambda: render_board_pdf(
        summary, branding=branding, report_id=report_id, workspace=str(workspace.get("name") or workspace["id"]),
        tlp=tlp, prepared_for=prepared_for, generated_at=generated_at, generator=f"Argus {__version__}",
        verify_url=verify_url,
    ))  # fmt: skip
    digest = hashlib.sha256(pdf).hexdigest()
    filename = f"argus-board-report-{generated_at:%Y%m%d}-{report_id}.pdf"
    record, after = await app.state.reports.record(
        fields={"id": report_id, "workspace_id": workspace["id"], "investigation_id": "", "target": BOARD_TARGET,
                "sha256": digest, "size": len(pdf), "tlp": tlp, "prepared_for": prepared_for or None,
                "issued_by_org": branding.organisation, "created_by": issued_by[:128]},
        file=(filename, pdf, keep_file_for) if keep_file_for else None,
        after_record=(lambda session, rec: after_record(session, rec, summary)) if after_record else None,
    )  # fmt: skip
    metrics.REPORTS_GENERATED.labels(f"board_{trigger}").inc()
    return {"record": record, "pdf": pdf, "sha256": digest, "filename": filename, "summary": summary, "after": after}
