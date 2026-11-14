"""Monitor scheduler: re-scan watched targets and raise alerts on material drift.

Kept independent of the web server (it receives callables rather than importing
it) so it can be unit-tested with a fake launcher and driven tick-by-tick.

Safety properties:

* respects the server-wide concurrent-scan cap - due monitors simply wait for the
  next tick rather than overloading the server;
* re-validates each monitor's scope before every run, so tightening the scope
  policy (e.g. disabling private targets) takes effect immediately;
* schedules the next run *before* the scan finishes, so a slow scan is never
  started twice;
* every automated scan is attributed to the scheduler in the audit log;
* cluster-safe: every replica runs a scheduler, but each due monitor is *claimed*
  with an atomic conditional UPDATE, so exactly one replica starts it.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from argus.core.models import EntityType, ScanConfig
from argus.core.settings import Settings
from argus.observability import metrics
from argus.security.auth import Principal, Role
from argus.security.network import validate_scan_target
from argus.storage.monitor_repo import MonitorRepository
from argus.storage.security_repo import AuditLog

logger = logging.getLogger("argus.scheduler")

SCHEDULER = Principal(key_id="scheduler", name="scheduler", role=Role.ANALYST)

# config, created_by, purpose, monitor_id, workspace_id -> investigation id
Launcher = Callable[[ScanConfig, str, str, str, str], Awaitable[str]]


class MonitorScheduler:
    def __init__(
        self,
        monitors: MonitorRepository,
        audit: AuditLog,
        settings: Settings,
        launch: Launcher,
        running_scans: Callable[[], int | Awaitable[int]],
    ):
        self.monitors = monitors
        self.audit = audit
        self.settings = settings
        self.launch = launch
        self.running_scans = running_scans

    async def tick(self) -> list[str]:
        """Start every due monitor that fits under the concurrency cap; returns investigation ids."""
        launched: list[str] = []
        for monitor in await self.monitors.due():
            running = self.running_scans()
            if inspect.isawaitable(running):
                running = await running
            if running >= self.settings.max_concurrent_scans:
                break  # try again next tick
            if not await self.monitors.claim(monitor["id"]):
                metrics.MONITOR_CLAIMS_LOST.inc()
                continue  # another replica took it
            await self._run(monitor, launched)
        return launched

    async def _run(self, monitor: dict[str, Any], launched: list[str]) -> None:
        target_type = EntityType(monitor["target_type"])
        if not self.settings.allow_private_targets:
            try:
                validate_scan_target(monitor["target"], target_type)
            except ValueError as exc:
                await self.monitors.set_enabled(monitor["id"], False, workspace_id=None)
                await self.audit.record(
                    SCHEDULER, "monitor.disabled", monitor["id"], "denied", details={"reason": str(exc)},
                    workspace_id=monitor["workspace_id"],
                )  # fmt: skip
                return
        config = ScanConfig(
            target=monitor["target"],
            target_type=target_type,
            max_depth=monitor["max_depth"],
            passive_only=bool(monitor.get("passive_only")),
            allow_private_targets=self.settings.allow_private_targets,
        )
        try:
            inv_id = await self.launch(
                config, f"monitor:{monitor['created_by']}", monitor["purpose"], monitor["id"], monitor["workspace_id"]
            )
        except Exception:
            logger.exception("Monitor %s failed to launch", monitor["id"])
            await self.monitors.release(monitor["id"])  # retry on the next tick
            return
        await self.monitors.mark_started(monitor["id"], inv_id)
        metrics.MONITOR_RUNS.inc()
        await self.audit.record(
            SCHEDULER, "monitor.run", monitor["id"], details={"investigation_id": inv_id, "target": monitor["target"]},
            workspace_id=monitor["workspace_id"],
        )  # fmt: skip
        launched.append(inv_id)

    async def run_forever(self) -> None:
        while True:
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Monitor scheduler tick failed")
            await asyncio.sleep(self.settings.monitor_poll_seconds)
