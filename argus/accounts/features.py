"""What each plan includes, enforced in Argus Personal from its signed licence.

| Feature | Bring your own keys | Personal | Professional | Business |
|---|---|---|---|---|
| Investigations, cases, evidence, link chart, exports | yes | yes | yes | yes |
| Monitoring and watches (scheduled scans, account and breach watches, scheduled reports) | | | yes | yes |
| Branded reports (your logo and colours) | | | yes | yes |
| Playbooks | | | yes | yes |
| Team tools (members, shared credits) | | | | yes |

The free trial includes everything an individual can buy (Professional), so people see it all.

The plan's features travel inside the signed licence, so they are enforced on the computer even
offline and cannot be edited. A feature a plan lacks answers ``403`` with ``upgrade: true`` and
says which plans include it. What is already there stays readable: only starting or changing
those things waits, and background runs (scheduled scans, watches) pause.

Other installations (the team server, the account service) are not licensed per plan: every
feature is available there.
"""

from __future__ import annotations

import re
from typing import Any

from argus.accounts.licence import PLANS
from argus.core.settings import get_settings

LABELS = {
    "monitoring": "Monitoring and watches",
    "branded_reports": "Branded reports",
    "playbooks": "Playbooks",
    "team": "Team tools",
}
# writes that need a feature (reading what already exists is always allowed)
GATED: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^/api/monitors(/|$)"), "monitoring"),
    (re.compile(r"^/api/cases/[^/]+/watches(/|$)"), "monitoring"),
    (re.compile(r"^/api/exposure/watches(/|$)"), "monitoring"),
    (re.compile(r"^/api/reports/schedules(/|$)"), "monitoring"),
    (re.compile(r"^/api/reports/branding(/|$)"), "branded_reports"),
    (re.compile(r"^/api/cases/[^/]+/playbooks$"), "playbooks"),
]  # team tools are checked by the account service itself (only a Business owner can manage a team)


def plan_features(payload: dict[str, Any] | None) -> set[str]:
    """The features a licence grants (older licences: from their plan)."""
    if not payload:
        return set()
    if isinstance(payload.get("features"), list):
        return {str(f) for f in payload["features"]}
    return set(PLANS.get(str(payload.get("plan")), {}).get("features", []))


def allows(feature: str) -> bool:
    """Whether this installation may use ``feature`` now."""
    if get_settings().edition != "personal":
        return True
    from argus.accounts import personal

    licence = personal.CURRENT
    return feature in plan_features(licence.payload if licence else None)


def needed(path: str) -> str | None:
    """The feature a write to ``path`` needs, if any."""
    return next((feature for pattern, feature in GATED if pattern.match(path)), None)


def upgrade_message(feature: str) -> str:
    plans = [
        info["label"] for info in PLANS.values() if feature in info.get("features", []) and info is not PLANS["trial"]
    ]
    return (f"{LABELS.get(feature, feature)} {'is' if not LABELS.get(feature, '').endswith('s') else 'are'} included "
            f"in the {' and '.join(plans)} plan{'s' if len(plans) > 1 else ''}: upgrade under Settings → "
            "Your Argus subscription.")  # fmt: skip


def summary(payload: dict[str, Any] | None) -> dict[str, bool]:
    granted = plan_features(payload)
    return {feature: feature in granted for feature in LABELS}
