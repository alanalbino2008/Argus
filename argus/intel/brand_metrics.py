"""Brand-protection metrics: what brand watches found, what is still live, and how fast it goes away.

The numbers a security lead reports upwards:

* **found**: lookalike domains known, and new in the period;
* **open threats**: lookalikes now judged an active phishing page, a copy of the brand's site, or a
  mail-capable lookalike of high severity, with no takedown that succeeded;
* **takedowns**: drafted, reported, taken down and closed; how many were reported and taken down in
  the period; the **median time to takedown** (reported to down) and how long open ones have waited;
* **campaigns**: how many, and the largest;
* **trend**: new lookalikes and takedowns per week over the period.

Computed from what the watches recorded; nothing is looked up.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Any

THREAT_VERDICTS = {"phishing", "clone"}
OPEN = ("drafted", "reported")


def _when(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _days(delta: timedelta) -> float:
    return round(delta.total_seconds() / 86400, 1)


def summarise(
    watches: list[tuple[dict[str, Any], dict[str, str], dict[str, Any]]],
    campaigns: list[dict[str, Any]],
    *,
    days: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    """``watches``: (full watch view, first-seen by name, details by name), as the brand-watch repository gives."""
    now = now or datetime.now(timezone.utc)
    start = now - timedelta(days=days)
    weeks = max(1, (days + 6) // 7)
    new_by_week = [0] * weeks
    down_by_week = [0] * weeks
    brands, threats, open_takedowns = [], [], []
    verdicts: Counter[str] = Counter()
    techniques: Counter[str] = Counter()
    status: Counter[str] = Counter()
    times_to_down: list[float] = []
    reported_in_period = down_in_period = new_in_period = known = 0

    def week(moment: datetime) -> int:
        return min(weeks - 1, max(0, int((moment - start).total_seconds() // (7 * 86400))))

    for watch, first_seen, details in watches:
        triage = watch.get("triage") or {}
        takedowns = watch.get("takedowns") or {}
        brand_new = brand_threats = 0
        for name, seen in first_seen.items():
            verdict = (triage.get(name) or {}).get("verdict") or ""
            if verdict == "yours":
                continue
            known += 1
            verdicts[verdict or "unchecked"] += 1
            techniques[str((details.get(name) or {}).get("technique") or "lookalike")] += 1
            moment = _when(seen)
            if moment and moment >= start:
                new_in_period += 1
                brand_new += 1
                new_by_week[week(moment)] += 1
            record = takedowns.get(name) or {}
            severity = (triage.get(name) or {}).get("severity") or ""
            threat = verdict in THREAT_VERDICTS or (verdict == "mail" and severity in ("high", "critical"))
            if threat and record.get("status") != "down":
                brand_threats += 1
                threats.append({"domain": name, "brand": watch["domain"], "verdict": verdict,
                                "label": (triage.get(name) or {}).get("label") or verdict, "severity": severity,
                                "first_seen": seen, "takedown": record.get("status")})  # fmt: skip
        for name, record in takedowns.items():
            status[record.get("status") or "drafted"] += 1
            reported, down = _when(record.get("reported_at")), _when(record.get("down_at"))
            if reported and reported >= start:
                reported_in_period += 1
            if down and down >= start:
                down_in_period += 1
                down_by_week[week(down)] += 1
            if reported and down and down >= reported:
                times_to_down.append(_days(down - reported))
            if record.get("status") in OPEN:
                since = reported or _when((record.get("history") or [{}])[0].get("at"))
                open_takedowns.append({"domain": name, "brand": watch["domain"], "status": record.get("status"),
                                       "waiting_days": _days(now - since) if since else None,
                                       "recipients": len((record.get("draft") or {}).get("to") or [])})  # fmt: skip
        brands.append({"domain": watch["domain"], "known": len(first_seen), "new": brand_new, "threats": brand_threats,
                       "last_run_at": watch.get("last_run_at"), "last_status": watch.get("last_status")})  # fmt: skip

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    threats.sort(key=lambda t: (order.get(t["severity"], 4), t["first_seen"] or ""))
    open_takedowns.sort(key=lambda t: -(t["waiting_days"] or 0))
    return {
        "period_days": days,
        "generated_at": now.isoformat(),
        "brands": brands,
        "found": {"known": known, "new": new_in_period},
        "open_threats": {"count": len(threats), "top": threats[:15]},
        "verdicts": dict(verdicts.most_common()),
        "techniques": dict(techniques.most_common()),
        "takedowns": {
            "by_status": dict(status),
            "reported_in_period": reported_in_period,
            "down_in_period": down_in_period,
            "median_days_to_down": median(times_to_down) if times_to_down else None,
            "open": open_takedowns[:15],
        },
        "campaigns": {
            "count": len(campaigns),
            "largest": [{"name": c["name"], "size": c["size"], "severity": c["severity"]} for c in campaigns[:5]],
        },
        "trend": {
            "week_starts": [(start + timedelta(days=7 * i)).date().isoformat() for i in range(weeks)],
            "new_lookalikes": new_by_week,
            "taken_down": down_by_week,
        },
    }
