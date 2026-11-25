"""Watch health: a watch that keeps failing tells the team that owns it, then pauses itself.

Phase 84 lets the platform's operators see failing watches in Prometheus. The team that set a watch
up usually holds the fix (its Shodan key ran out, its route was removed, its brand domain changed),
and until now saw only a status in Monitoring. Now:

* after :data:`ALERT_AFTER` failed runs in a row, the workspace gets one alert with the error and what
  to do about it (:func:`advice`);
* when a watch has failed every run for :data:`PAUSE_AFTER`, it is paused: it stops spending the
  team's third-party credits on a search that cannot work, and the workspace gets a second alert.
  **Run now** resumes it;
* the first successful run after an alert sends a low-severity "working again" alert.

A brand-watch run where one Certificate Transparency source failed and the other worked counts as a
success: the watch still finds lookalikes.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

ALERT_AFTER = 3
PAUSE_AFTER = timedelta(days=7)
SUCCESS = ("ok", "partial")


def advice(message: str) -> str:
    """What the team can do about a watch's error message."""
    text = message.lower()
    if "no shodan key" in text or "no censys key" in text or "key is configured" in text:
        return "Add the API key in Settings → Integrations (or ask your administrator to)."
    if "401" in text or "403" in text or ("invalid" in text and "key" in text) or "unauthor" in text:
        return "The API key was refused: it may have been revoked or expired. Replace it in Settings → Integrations."
    if "429" in text or "rate-limit" in text or "quota" in text or "credits" in text or "free limit" in text:
        return ("The source's quota is used up. The watch tries again on its schedule; a paid key or a longer "
                "interval avoids this.")  # fmt: skip
    if "route" in text and ("not configured" in text or "removed" in text):
        return "The anonymising route this watch uses was removed. Choose another route for the watch."
    if "could not be reached" in text or "timeout" in text or "unreachable" in text:
        return ("Argus could not reach the source. It is often a short outage; if it lasts, check the "
                "deployment's outbound network (egress proxy, firewall).")  # fmt: skip
    return "Open the watch in Monitoring to see its last error, then use Run now to try again."


def after_run(data: dict[str, Any], status: str, now: datetime) -> tuple[dict[str, Any], str | None]:
    """The watch's health fields after a run, and what to tell the team: ``failing``, ``paused``,
    ``recovered`` or ``None``."""
    data = dict(data)
    if status in SUCCESS:
        event = "recovered" if data.get("health_alerted") else None
        for key in ("failures", "failing_since", "health_alerted", "paused_at", "paused_reason"):
            data.pop(key, None)
        return data, event
    failures = int(data.get("failures") or 0) + 1
    since = data.get("failing_since") or now.isoformat()
    data["failures"], data["failing_since"] = failures, since
    started = datetime.fromisoformat(since)
    if failures >= ALERT_AFTER and now - started >= PAUSE_AFTER:
        data["paused_at"], data["health_alerted"] = now.isoformat(), True
        data["paused_reason"] = f"Paused by Argus after {failures} failed runs since {since[:10]}"
        return data, "paused"
    if failures == ALERT_AFTER:
        data["health_alerted"] = True
        return data, "failing"
    return data, None


def resumed(data: dict[str, Any]) -> dict[str, Any]:
    """A paused watch started again by hand: it gets a fresh week before it can be paused again."""
    data = dict(data)
    for key in ("failing_since", "paused_at", "paused_reason"):
        data.pop(key, None)
    data["failures"] = 0
    return data


def view(data: dict[str, Any]) -> dict[str, Any]:
    """The health fields the API shows with a watch."""
    return {"failures": int(data.get("failures") or 0), "failing_since": data.get("failing_since"),
            "paused_reason": data.get("paused_reason")}  # fmt: skip


def headline(kind: str, name: str, event: str, failures: int) -> str:
    what = "Brand watch" if kind == "brand" else "Fingerprint watch"
    if event == "paused":
        return f"{what} {name} paused after failing for a week"
    if event == "recovered":
        return f"{what} {name} is working again"
    return f"{what} {name} has failed {failures} runs in a row"
