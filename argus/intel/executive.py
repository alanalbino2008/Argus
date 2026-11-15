"""The executive view: Argus's modules summarised as a board would ask for them.

A board doesn't want 40 charts. It wants to know:
* how exposed we are;
* whether we are fixing things fast enough;
* what is new or dangerous;
* whether the trend is up or down.

This module turns the workspace's numbers into exactly that, deterministically:

* **Five areas**, each red / amber / green (or grey when not measured):
  * attack surface (security ratings of your own organisations);
  * remediation (overdue work and SLA compliance);
  * breach & dark-web exposure;
  * supplier risk;
  * threat activity (alerts in the period).

  Each status carries the reason it was given. Nothing is red without a sentence saying why.
* **Key messages**: the most important facts, worst first, in plain English, positive news
  included. Boards distrust reports that only ever say things are bad, or only ever say good.
* **Top risks** an owner should act on, including critical attack paths that **nobody owns** yet.

Every rule is a pure function of the numbers, so the same data always gives the same report.
Thresholds follow common practice (e.g. 90% of fixes on time is a typical SLA target).
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any

from argus.intel.exposure import mask_email

GRADE_ORDER = "ABCDF"
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SLA_TARGET = 90  # % of fixes verified on time
SLA_FLOOR = 70
STATUS_RANK = {"red": 3, "amber": 2, "green": 1, "grey": 0}
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _plural(n: int, word: str, plural: str | None = None) -> str:
    return f"{n} {word if n == 1 else plural or word + 's'}"


def _area(key: str, title: str, status: str, reason: str, **figures: Any) -> dict[str, Any]:
    return {"key": key, "title": title, "status": status, "reason": reason, "figures": figures}


def score_change(history: list[dict[str, Any]], since: datetime) -> tuple[float | None, str | None]:
    """(score change, grade at the start) over the period; None without a baseline in it."""
    if len(history) < 2:
        return None, None
    before = [h for h in history if h.get("assessed_at") and datetime.fromisoformat(h["assessed_at"]) <= since]
    start = before[-1] if before else history[0]
    if start is history[-1]:
        return None, None
    return round(history[-1]["score"] - start["score"], 1), start["grade"]


# ---------------------------------------------------------------------------- the five areas
def surface_area(orgs: list[dict[str, Any]], since: datetime) -> tuple[dict[str, Any], list[tuple[int, str]]]:
    messages: list[tuple[int, str]] = []
    if not orgs:
        return _area("surface", "Attack surface", "grey", "No organisation of yours has been rated yet."), messages
    weakest = max(orgs, key=lambda o: (GRADE_ORDER.index(o["grade"]), -o["score"]))
    critical = sum(o.get("critical_issues", 0) for o in orgs)
    if GRADE_ORDER.index(weakest["grade"]) >= 3 or critical:
        status = "red"
    elif weakest["grade"] == "C":
        status = "amber"
    else:
        status = "green"
    reason = f"Weakest: {weakest['target']} at {weakest['grade']} ({round(weakest['score'])})" + (
        f"; {_plural(critical, 'critical issue')} open" if critical else ""
    )
    for o in orgs:
        change, start_grade = score_change(o.get("history", []), since)
        if change is None:
            continue
        if o["grade"] != start_grade:
            better = GRADE_ORDER.index(o["grade"]) < GRADE_ORDER.index(start_grade or o["grade"])
            messages.append((60 if not better else 30, f"{o['target']}'s security rating "
                             f"{'improved' if better else 'fell'} from {start_grade} to {o['grade']} "
                             f"({change:+g} points)."))  # fmt: skip
        elif abs(change) >= 5:
            messages.append((25, f"{o['target']} is rated {o['grade']}, {'up' if change > 0 else 'down'} "
                             f"{abs(change):g} points in the period."))  # fmt: skip
    if critical:
        messages.append((80, f"{_plural(critical, 'critical issue')} on your own attack surface "
                             f"{'caps' if critical == 1 else 'cap'} the security rating."))  # fmt: skip
    average = round(sum(o["score"] for o in orgs) / len(orgs))
    return _area("surface", "Attack surface", status, reason, organisations=len(orgs), weakest=weakest["target"],
                 weakest_grade=weakest["grade"], average_score=average, critical_issues=critical), messages  # fmt: skip


def remediation_area(m: dict[str, Any] | None, untracked: int) -> tuple[dict[str, Any], list[tuple[int, str]]]:
    messages: list[tuple[int, str]] = []
    if not m or (not m["active"] and not m["closed_in_window"]):
        if untracked:
            messages.append((85, f"{_plural(untracked, 'critical attack path')} {'has' if untracked == 1 else 'have'} "
                                 "no owner: nobody is tracking a fix."))  # fmt: skip
            return _area("remediation", "Remediation", "red", f"{untracked} critical attack path(s) untracked",
                         untracked_critical=untracked), messages  # fmt: skip
        return _area("remediation", "Remediation", "grey", "No remediation work tracked yet."), messages
    overdue, critical_overdue, sla = m["overdue"], m["overdue_by_severity"]["critical"], m["sla_compliance"]
    if critical_overdue or untracked or (sla is not None and sla < SLA_FLOOR):
        status = "red"
    elif overdue or (sla is not None and sla < SLA_TARGET):
        status = "amber"
    else:
        status = "green"
    parts = [f"{_plural(overdue, 'task')} overdue" if overdue else "nothing overdue"]
    if sla is not None:
        parts.append(f"{sla}% fixed on time")
    if untracked:
        parts.append(f"{untracked} critical path(s) untracked")
    if critical_overdue:
        messages.append((90, f"{_plural(critical_overdue, 'critical fix')} {'is' if critical_overdue == 1 else 'are'} "
                             "past its deadline."))  # fmt: skip
    elif overdue:
        messages.append((55, f"{_plural(overdue, 'remediation task')} {'is' if overdue == 1 else 'are'} overdue."))
    else:
        messages.append((20, "No remediation work is overdue."))
    if untracked:
        messages.append((85, f"{_plural(untracked, 'critical attack path')} {'has' if untracked == 1 else 'have'} no "
                             "owner: nobody is tracking a fix."))  # fmt: skip
    if sla is not None:
        good = sla >= SLA_TARGET
        messages.append((15 if good else 50, f"{sla}% of fixes were verified within their deadline "
                         f"(target {SLA_TARGET}%)."))  # fmt: skip
    if m["mttr_days"].get("critical") is not None:
        messages.append((10, f"Critical issues take a median of {m['mttr_days']['critical']} days to fix and verify."))
    if m.get("regressions"):
        messages.append((40, f"{_plural(m['regressions'], 'fix', 'fixes')} came undone and had to be reopened."))
    return _area("remediation", "Remediation", status, "; ".join(parts).capitalize(), active=m["active"],
                 overdue=overdue, critical_overdue=critical_overdue, sla_compliance=sla,
                 mttr_critical=m["mttr_days"].get("critical"), untracked_critical=untracked), messages  # fmt: skip


def exposure_area(
    summary: dict[str, Any] | None, watched: int, own: dict[str, int]
) -> tuple[dict[str, Any], list[tuple[int, str]]]:
    """``own``: open findings by kind about your own domains (supplier findings belong to the supplier area)."""
    messages: list[tuple[int, str]] = []
    if not watched:
        return _area("exposure", "Breach & dark-web exposure", "grey", "No domain is watched for exposure."), messages
    stealers, ransomware = own.get("stealer_log", 0), own.get("ransomware_post", 0)
    accounts, breached = summary["accounts"] if summary else 0, own.get("domain_breach", 0)
    if stealers or ransomware:
        status = "red"
    elif accounts or breached:
        status = "amber"
    else:
        status = "green"
    if ransomware:
        messages.append((100, "Your organisation was named on a ransomware group's leak site."))
    if stealers:
        whose = "1 employee's" if stealers == 1 else f"{stealers} employees'"
        messages.append((95, f"{whose} credentials were stolen by infostealer malware."))
    if accounts:
        messages.append((35, f"{_plural(accounts, 'staff account')} {'appears' if accounts == 1 else 'appear'} "
                             "in third-party data breaches."))  # fmt: skip
    reason = ", ".join(x for x in (
        f"{stealers} infostealer infection(s)" if stealers else "", f"{ransomware} leak-site post(s)" if ransomware else "",
        f"{accounts} breached account(s)" if accounts else "") if x) or "No open exposure"  # fmt: skip
    return _area("exposure", "Breach & dark-web exposure", status, reason, infostealers=stealers,
                 ransomware_posts=ransomware, breached_accounts=accounts, watched=watched), messages  # fmt: skip


def supplier_area(suppliers: list[dict[str, Any]]) -> tuple[dict[str, Any], list[tuple[int, str]]]:
    messages: list[tuple[int, str]] = []
    if not suppliers:
        return _area("suppliers", "Supplier risk", "grey", "No suppliers registered."), messages
    below = [s for s in suppliers if s["status"] == "below_minimum"]
    critical_below = [s for s in below if s["tier"] == "critical"]
    hit = [s for s in suppliers if (s.get("exposure") or {}).get("ransomware_post")]
    breached = [s for s in suppliers if (s.get("exposure") or {}).get("domain_breach")]
    status = "red" if critical_below or hit else "amber" if below or breached else "green"
    messages.extend(
        (98, f"Supplier {s['name']} was named on a ransomware leak site: check what data of yours it holds.")
        for s in hit
    )
    if critical_below:
        names = ", ".join(s["name"] for s in critical_below[:3])
        messages.append((70, f"{_plural(len(critical_below), 'critical supplier')} {'is' if len(critical_below) == 1 else 'are'} "
                             f"below the minimum security grade ({names})."))  # fmt: skip
    elif below:
        messages.append((45, f"{_plural(len(below), 'supplier')} {'is' if len(below) == 1 else 'are'} below "
                             "the minimum grade for their tier."))  # fmt: skip
    reason = f"{len(below)} of {len(suppliers)} below minimum" + (f"; {len(hit)} hit by ransomware" if hit else "")
    high_risk = sum(1 for s in suppliers if s["risk"]["level"] in ("critical", "high"))
    return _area("suppliers", "Supplier risk", status, reason, total=len(suppliers), below_minimum=len(below),
                 critical_below=len(critical_below), high_risk=high_risk, ransomware=len(hit)), messages  # fmt: skip


def threat_area(alerts: list[dict[str, Any]], days: int, watched: int) -> tuple[dict[str, Any], list[tuple[int, str]]]:
    if not watched and not alerts:  # silence from nothing watching is not good news
        return _area("threats", "Threat activity", "grey", "Nothing is monitored, so no alerts can be raised."), []
    counts = {s: sum(1 for a in alerts if a["severity"] == s) for s in ("critical", "high", "medium", "low")}
    status = "red" if counts["critical"] else "amber" if counts["high"] else "green"
    reason = f"{_plural(len(alerts), 'alert')} in {days} days" + (
        f", {counts['critical']} critical" if counts["critical"] else ""
    )
    messages = (
        [(40, f"{_plural(counts['critical'], 'critical alert')} in the last {days} days.")]
        if counts["critical"]
        else []
    )
    return _area("threats", "Threat activity", status, reason, alerts=len(alerts), **counts), messages


# ---------------------------------------------------------------------------- the whole picture
def assess(raw: dict[str, Any], now: datetime, days: int) -> dict[str, Any]:
    """Areas, overall status, key messages and top risks from the collected numbers."""
    since = now - timedelta(days=days)
    results = [
        surface_area(raw["organisations"], since),
        remediation_area(raw["remediation"], raw["untracked_critical"]),
        exposure_area(raw["exposure_summary"], raw["exposure_watched"], raw["exposure_own"]),
        supplier_area(raw["suppliers"]),
        threat_area(raw["alerts"], days, raw.get("watched", 0)),
    ]
    areas = [a for a, _ in results]
    messages = sorted((m for _, ms in results for m in ms), key=lambda m: -m[0])
    measured = [a for a in areas if a["status"] != "grey"]
    overall = max((a["status"] for a in measured), key=lambda s: STATUS_RANK[s], default="grey")
    red = [a["title"] for a in areas if a["status"] == "red"]
    verdict = {
        "red": f"Action needed: {', '.join(red)}.",
        "amber": "No emergencies, but some areas are below target.",
        "green": "Within tolerance in every measured area.",
        "grey": "Not enough data yet: watch a domain, rate your organisation, or add suppliers.",
    }[overall]
    return {
        "generated_at": now.isoformat(),
        "period_days": days,
        "overall": overall,
        "verdict": verdict,
        "areas": areas,
        "messages": [text for _, text in messages[:7]],
        "top_risks": top_risks(raw),
        "organisations": [
            {k: o[k] for k in ("target", "grade", "score", "trend", "change") if k in o} for o in raw["organisations"]
        ],
    }


def redact(text: str) -> str:
    """Board material names owners (accountability) but never the people a finding is about."""
    return EMAIL.sub(lambda m: mask_email(m.group(0)), text)


def top_risks(raw: dict[str, Any], limit: int = 6) -> list[dict[str, Any]]:
    """What an owner should act on first: overdue and critical work, then critical paths with no owner."""
    risks = [
        {"title": t["title"], "severity": t["severity"], "target": t["target"], "owner": t["assignee"],
         "due_at": t["due_at"], "overdue": t["overdue"], "status": t["status"], "task_id": t["id"]}
        for t in raw["active_tasks"]
    ]  # fmt: skip
    risks += [{"title": p["title"], "severity": p["severity"], "target": p["target"], "owner": None, "due_at": None,
               "overdue": False, "status": "untracked", "path_id": p["id"], "investigation_id": p["investigation_id"]}
              for p in raw["untracked_paths"]]  # fmt: skip
    risks.sort(key=lambda r: (-SEVERITY_RANK.get(r["severity"], 0), not r["overdue"], r["status"] != "untracked",
                              r["due_at"] or "9999"))  # fmt: skip
    return [{**r, "title": redact(r["title"])} for r in risks[:limit]]
