"""Warn a workspace before one of its API keys expires (Phase 89).

A key that expires silently breaks the SIEM connector or script that uses it, usually at night. Each
hour, keys that expire within ``ARGUS_API_KEY_EXPIRY_WARNING_DAYS`` raise one alert in their
workspace (claimed atomically, so one replica sends it), naming the key and how to rotate it.
Platform keys belong to no workspace: their warning goes to the audit log.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from typing import Any

logger = logging.getLogger("argus.key_expiry")
POLL_SECONDS = 3600


async def warn_expiring(app: Any) -> list[str]:
    """Send the warnings due now; returns the ids of the keys warned about."""
    from argus.api.scheduler import SCHEDULER
    from argus.observability import metrics

    keys = app.state.keys
    days = app.state.settings.api_key_expiry_warning_days
    warned = []
    for key in await keys.expiring(timedelta(days=days)):
        if not await keys.mark_warned(key["id"]):
            continue  # another replica sent it
        warned.append(key["id"])
        left = key["expires_in_days"]
        details = {"key": key["id"], "name": key["name"], "expires_at": key["expires_at"]}
        if key["workspace_id"]:
            await app.state.monitors.create_alert(
                monitor_id=None, investigation_id="", previous_investigation_id="", target=key["name"],
                severity="medium", headline=f"API key {key['name']} expires in {left:g} days",
                summary={"api_key_expiry": {**details, "expires_in_days": left,
                         "advice": "Rotate it in Settings → API keys (or POST /api/keys/{id}/rotate): the old key "
                                   "keeps working for a day while you switch the integration over."}},
                workspace_id=key["workspace_id"], public_url=app.state.settings.public_url,
            )  # fmt: skip
            metrics.ALERTS_RAISED.labels("medium").inc()
        await app.state.audit.record(SCHEDULER, "key.expiry_warning", key["id"], details=details,
                                     workspace_id=key["workspace_id"])  # fmt: skip
    return warned


async def run_forever(app: Any, poll_seconds: float = POLL_SECONDS) -> None:
    while True:
        try:
            await warn_expiring(app)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Key expiry check failed")
        await asyncio.sleep(poll_seconds)
