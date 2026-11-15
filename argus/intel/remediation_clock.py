"""The remediation clock: deadlines and risk acceptances, checked on every replica.

* Tasks that pass their due date are announced once, in one alert per workspace per check, through
  the normal notification channels. Each task is claimed atomically, so replicas never repeat
  each other.
* Risk acceptances end on their date: the task reopens and someone has to decide again. This is
  what keeps "accepted" from becoming a place where findings go to be forgotten.
* Closed tasks are kept for the metrics, then purged after the retention period.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from argus.core.settings import Settings
from argus.intel.remediation import SEVERITIES, SEVERITY_RANK
from argus.storage.remediation_repo import RemediationRepository

logger = logging.getLogger("argus.remediation")
PURGE_EVERY = 6 * 3600.0
CLOSED_RETENTION_DAYS = 730  # two years of history for trends and audits


def overdue_alert(workspace_id: str, tasks: list[dict[str, Any]]) -> dict[str, Any]:
    by_severity = {s: sum(1 for t in tasks if t["severity"] == s) for s in SEVERITIES}
    worst = max((t["severity"] for t in tasks), key=lambda s: SEVERITY_RANK[s])
    counts = ", ".join(f"{n} {s}" for s, n in by_severity.items() if n)
    first = sorted(tasks, key=lambda t: -SEVERITY_RANK[t["severity"]])[0]
    many = len(tasks) != 1
    text = f"{len(tasks)} remediation task{'s' if many else ''} {'are' if many else 'is'} now overdue ({counts}), " \
           f"e.g. “{first['title']}”"  # fmt: skip
    return {
        "target": "remediation",
        "severity": worst,
        "headline": text,
        "summary": {
            "summary": {},
            "remediation": {
                "overdue": len(tasks),
                "by_severity": by_severity,
                "task_ids": [t["id"] for t in tasks][:50],
            },
        },
    }


class RemediationClock:
    def __init__(self, repo: RemediationRepository, settings: Settings):
        self.repo = repo
        self.settings = settings
        self._last_purge = 0.0

    async def tick(self) -> dict[str, int]:
        reopened = await self.repo.expire_acceptances()
        alerts = await self.repo.announce_overdue(overdue_alert, public_url=self.settings.public_url)
        if time.monotonic() - self._last_purge > PURGE_EVERY:
            self._last_purge = time.monotonic()
            await self.repo.purge_closed(older_than_days=CLOSED_RETENTION_DAYS)
        if reopened or alerts:
            logger.info("Remediation: %d acceptance(s) expired, %d overdue alert(s)", reopened, len(alerts))
        return {"reopened": reopened, "alerts": len(alerts)}

    async def run_forever(self) -> None:
        while True:
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Remediation tick failed")
            await asyncio.sleep(self.settings.remediation_poll_seconds)
