"""Remediation: turning findings into tracked work, with deadlines, proof and metrics.

A **task** comes from an attack path, an exposure finding, a supplier, or a person. Its lifecycle:

    open -> in_progress -> fixed -> verified
                \\-> accepted (risk accepted, until a date; reopens when it expires)

* **Deadlines (SLAs)** follow severity, per workspace (defaults: critical 7 days, high 30,
  medium 90, low 180), the usual shape of a vulnerability-management policy.
* **Verification by evidence.** "Fixed" is a claim. For an attack path, Argus checks the claim
  with the next scan of the target. The path is *verified* when a comparable scan no longer finds
  it, and *reopened* when a scan still finds it. A scan is **comparable** only if it looked at
  least as hard as the scan that found the path: same or greater depth, no more passive, and not
  cut short, and running every module the original ran. Absence in a lighter scan proves nothing, but presence in any scan proves the path
  is still there. Supplier tasks are verified when the supplier's grade meets its minimum again;
  exposure tasks when their finding is resolved.
* **Regressions.** A verified path that comes back reopens its task, and the reopen is counted.

Metrics follow common vulnerability-management reporting:
* **MTTR**, the median days from opening to verified fix, by severity;
* **SLA compliance**, the share of tasks closed on time;
* **overdue counts**;
* a weekly opened-versus-closed trend.
"""

from __future__ import annotations

import statistics
from datetime import datetime, timedelta, timezone
from typing import Any

STATUSES = ("open", "in_progress", "fixed", "verified", "accepted")
ACTIVE = ("open", "in_progress", "fixed")  # still needs something to happen
CLOSED = ("verified", "accepted")
SEVERITIES = ("critical", "high", "medium", "low")
SOURCES = ("attack_path", "exposure", "supplier", "manual")
DEFAULT_SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}
MAX_ACCEPTANCE = timedelta(days=365)
AUTO_CREATE = ("off", "critical", "high")  # create tasks automatically for new findings of at least this severity
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Which status changes a person may make. "verified" for attack paths is reserved for scans.
TRANSITIONS: dict[str, tuple[str, ...]] = {
    "open": ("in_progress", "fixed", "accepted"),
    "in_progress": ("open", "fixed", "accepted"),
    "fixed": ("open", "in_progress", "verified", "accepted"),
    "verified": ("open",),
    "accepted": ("open",),
}


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def due_date(severity: str, created: datetime, sla_days: dict[str, int] | None = None) -> datetime:
    days = (sla_days or DEFAULT_SLA_DAYS).get(severity, DEFAULT_SLA_DAYS[severity])
    return created + timedelta(days=int(days))


def meets_threshold(severity: str, threshold: str) -> bool:
    return threshold != "off" and SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK[threshold]


def transition_error(task: dict[str, Any], new: str, *, by_person: bool = True) -> str | None:
    """Why a person cannot move ``task`` to ``new`` (None when they can)."""
    current = task["status"]
    if new == current:
        return None
    if new not in TRANSITIONS.get(current, ()):
        return f"This task is {current.replace('_', ' ')}; it cannot be moved to {new.replace('_', ' ')}"
    if by_person and new == "verified" and task["source_type"] == "attack_path":
        return "Attack paths are verified by a scan: mark the task fixed, then rescan the target"
    if by_person and new == "verified" and task["source_type"] == "supplier":
        return "Supplier tasks are verified when the supplier's next assessment meets its minimum grade"
    return None


# ---------------------------------------------------------------------------- verification by scans
def scan_scope(config: Any) -> dict[str, Any]:
    modules = getattr(config, "enabled_modules", None)
    return {
        "max_depth": int(config.max_depth),
        "passive_only": bool(config.passive_only),
        "modules": sorted(modules) if modules is not None else None,  # None: every module
        "target_type": getattr(getattr(config, "target_type", None), "value", None),
    }


def comparable(task_scope: dict[str, Any], scan: dict[str, Any]) -> bool:
    """Did this scan look at least as hard as the one that found the path?"""
    if scan.get("truncated"):
        return False
    if scan["max_depth"] < int(task_scope.get("max_depth", 0)):
        return False
    if scan["passive_only"] and not task_scope.get("passive_only", False):
        return False
    wanted, used = task_scope.get("modules"), scan.get("modules")
    # A scan restricted to some modules must include every module the original ran.
    return used is None or (wanted is not None and set(wanted) <= set(used))


def verification(task: dict[str, Any], present: bool, scan: dict[str, Any]) -> str | None:
    """What a completed scan means for an attack-path task: 'verified', 'reopened' or None."""
    status = task["status"]
    if status == "accepted":
        return None  # a conscious decision; scans do not override it
    if present:
        return "reopened" if status in ("fixed", "verified") else None
    if status in ACTIVE and comparable(task["details"].get("scope", {}), scan):
        return "verified"
    return None


# ---------------------------------------------------------------------------- metrics
def _days(a: datetime, b: datetime) -> float:
    return max(0.0, (b - a).total_seconds() / 86400)


def metrics(tasks: list[dict[str, Any]], now: datetime, *, window_days: int = 90, weeks: int = 12) -> dict[str, Any]:
    """Headline numbers for the Remediation page and reports."""

    def at(task: dict[str, Any], key: str) -> datetime | None:
        value = task.get(key)
        return _utc(datetime.fromisoformat(value)) if isinstance(value, str) else _utc(value)

    active = [t for t in tasks if t["status"] in ACTIVE]
    overdue = [t for t in active if (due := at(t, "due_at")) is not None and due < now]
    since = now - timedelta(days=window_days)
    closed_recently = [t for t in tasks if t["status"] == "verified" and (c := at(t, "closed_at")) and c >= since]
    on_time = [t for t in closed_recently if (c := at(t, "closed_at")) and (d := at(t, "due_at")) and c <= d]
    mttr: dict[str, float | None] = {}
    for severity in SEVERITIES:
        durations = [
            _days(created, closed)
            for t in closed_recently
            if t["severity"] == severity and (created := at(t, "created_at")) and (closed := at(t, "closed_at"))
        ]
        mttr[severity] = round(statistics.median(durations), 1) if durations else None

    start = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    trend = []
    for i in range(weeks - 1, -1, -1):
        week_start, week_end = start - timedelta(weeks=i), start - timedelta(weeks=i - 1)
        trend.append({
            "week": week_start.date().isoformat(),
            "opened": sum(1 for t in tasks if (c := at(t, "created_at")) and week_start <= c < week_end),
            "closed": sum(1 for t in tasks if t["status"] in CLOSED and (c := at(t, "closed_at"))
                          and week_start <= c < week_end),
        })  # fmt: skip

    by_assignee: dict[str, dict[str, int]] = {}
    for t in active:
        who = t.get("assignee") or "Unassigned"
        entry = by_assignee.setdefault(who, {"open": 0, "overdue": 0})
        entry["open"] += 1
        entry["overdue"] += t in overdue
    return {
        "active": len(active),
        "overdue": len(overdue),
        "overdue_by_severity": {s: sum(1 for t in overdue if t["severity"] == s) for s in SEVERITIES},
        "due_within_7_days": sum(1 for t in active if (d := at(t, "due_at")) and now <= d < now + timedelta(days=7)),
        "awaiting_verification": sum(1 for t in tasks if t["status"] == "fixed"),
        "accepted": sum(1 for t in tasks if t["status"] == "accepted"),
        "closed_in_window": len(closed_recently),
        "sla_compliance": round(100 * len(on_time) / len(closed_recently)) if closed_recently else None,
        "mttr_days": mttr,
        "window_days": window_days,
        "trend": trend,
        "by_assignee": dict(sorted(by_assignee.items(), key=lambda kv: (-kv[1]["overdue"], -kv[1]["open"], kv[0]))),
        "regressions": sum(int(t.get("reopen_count") or 0) for t in tasks),
    }


# ---------------------------------------------------------------------------- tasks from findings
def from_path(path: dict[str, Any], *, target: str, investigation_id: str, scope: dict[str, Any]) -> dict[str, Any]:
    """Task fields for an attack path (a snapshot: the task stays readable after the scan is purged)."""
    evidence = [str(e) for e in (path.get("evidence") or [])][:10]
    steps = " → ".join(s.get("label", "") for s in path.get("steps", [])[:8])
    return {
        "source_type": "attack_path",
        "source_key": f"{target}|{path['id']}",
        "target": target,
        "severity": path["severity"],
        "title": path["title"][:300],
        "description": f"{path.get('narrative', '')}\n\nPath: {steps}"[:4000],
        "details": {
            "path_id": path["id"], "rule": path.get("rule"), "score": path.get("score"),
            "remediation": path.get("remediation"), "evidence": evidence,
            "techniques": [t.get("id") for t in path.get("techniques", [])][:12],
            "found_in": investigation_id, "scope": scope,
        },
    }  # fmt: skip


def from_exposure(finding: dict[str, Any]) -> dict[str, Any]:
    """Task fields for an exposure finding. Staff addresses stay masked in the task."""
    who = f" ({finding['account_masked']})" if finding.get("account_masked") else ""
    advice = {
        "stealer_log": "Reset the password, revoke sessions and MFA tokens, and clean or re-image the infected device.",
        "ransomware_post": "Start incident response (or, for a supplier, contact them and assess what data they held).",
        "domain_breach": "Confirm what was taken and that the cause has been fixed.",
        "breach_account": "Force a password reset where passwords were exposed and check for password reuse.",
        "darkweb_mention": "Review the dark-web listing: confirm whether it concerns you, and what (if anything) is "
        "exposed. Preserve the reference; do not visit the onion service.",
        "paste_leak": "Review the paste/leak-forum post for exposed data. If credentials appear, reset them and "
        "revoke sessions; preserve the reference as evidence.",
    }.get(finding["kind"], "")
    return {
        "source_type": "exposure",
        "source_key": finding["id"],
        "target": finding["subject"],
        "severity": finding["severity"],
        "title": f"{finding['title']}{who}"[:300],
        "description": advice,
        "details": {"finding_id": finding["id"], "kind": finding["kind"], "remediation": advice},
    }


def from_supplier(supplier: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_type": "supplier",
        "source_key": supplier["id"],
        "target": supplier["domain"],
        "severity": "critical" if supplier["tier"] == "critical" else "high",
        "title": f"Bring supplier {supplier['name']} up to grade {supplier['min_grade']} (now {supplier['grade']})"[
            :300
        ],
        "description": (
            f"{supplier['name']} ({supplier['domain']}) is rated {supplier['grade']}, below the "
            f"{supplier['min_grade']} required for {supplier['tier']} suppliers. Share the rating's "
            "findings with the supplier and agree a remediation plan."
        ),
        "details": {
            "supplier_id": supplier["id"],
            "min_grade": supplier["min_grade"],
            "grade_at_creation": supplier["grade"],
        },
    }
