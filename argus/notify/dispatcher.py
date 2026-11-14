"""The notification dispatcher: every replica runs one; the outbox makes them cooperate.

Each tick claims due deliveries (see ``NotificationRepository.claim_due``), sends them a
few at a time, and records the outcome. Failed attempts are retried with exponential
backoff and jitter - 30 s, 2 min, 10 min, 30 min, 1 h, 2 h, 4 h - so a receiver that is
down for a few hours still gets every alert, without Argus hammering it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from argus.core.settings import Settings
from argus.notify import render
from argus.notify.signing import sign_headers
from argus.notify.transport import Result, Transport
from argus.observability import metrics
from argus.storage.notification_repo import NotificationRepository

logger = logging.getLogger("argus.notify")

FileLoader = Callable[[str, str], Awaitable[tuple[str, bytes] | None]]  # (report id, workspace id)
BACKOFF_SECONDS = (30, 120, 600, 1800, 3600, 7200, 14400)
CONCURRENCY = 5
PURGE_EVERY = 3600.0


def backoff(attempt: int) -> float:
    """Delay before attempt ``attempt + 1`` (1-based ``attempt``), with ±20 % jitter."""
    base = BACKOFF_SECONDS[min(attempt, len(BACKOFF_SECONDS)) - 1]
    return float(base * random.uniform(0.8, 1.2))


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


class NotificationDispatcher:
    def __init__(
        self,
        repo: NotificationRepository,
        settings: Settings,
        transport: Transport | None = None,
        files: FileLoader | None = None,
    ):
        self.repo = repo
        self.settings = settings
        self.transport = transport or Transport(settings)
        self.files = files  # loads a stored report PDF to attach to emails
        self._last_purge = 0.0

    async def tick(self) -> int:
        """Send everything currently due; returns how many deliveries were attempted."""
        claimed = await self.repo.claim_due(
            self.settings.instance_id, lease_seconds=self.settings.notify_timeout_seconds * 3 + 30
        )
        if claimed:
            gate = asyncio.Semaphore(CONCURRENCY)

            async def one(item: dict[str, Any]) -> None:
                async with gate:
                    await self._deliver(item)

            await asyncio.gather(*(one(item) for item in claimed))
        metrics.NOTIFICATIONS_PENDING.set(await self.repo.backlog())
        if time.monotonic() - self._last_purge > PURGE_EVERY:
            self._last_purge = time.monotonic()
            await self.repo.purge()
        return len(claimed)

    async def run_forever(self) -> None:
        try:
            while True:
                try:
                    await self.tick()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("Notification dispatcher tick failed")
                await asyncio.sleep(self.settings.notify_poll_seconds)
        finally:
            await self.transport.close()

    async def send(
        self, channel: dict[str, Any], secrets: dict[str, Any], event: dict[str, Any], msg_id: str
    ) -> Result:
        kind = channel["type"]
        if kind == "email":
            if not self.transport.email_available:
                return Result(False, False, error="Email is not configured on this server")
            attachment = None
            if event.get("type") == "report.scheduled":
                report = event["report"]
                attachment = await self.files(report["id"], event["workspace"]["id"]) if self.files else None
                if attachment is None:
                    return Result(False, False, error="The report file has expired; generate the report again")
            message = render.email(
                event, self.settings.smtp_from, list(channel.get("recipients") or []), attachment=attachment
            )
            return await self.transport.send_email(message)
        url = secrets.get("url")
        if not url:
            return Result(False, False, error="The channel has no destination URL")
        if kind == "slack":
            body = render.slack(event)
        elif kind == "teams":
            body = render.teams(event)
        else:
            body = event
        raw = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
        headers: dict[str, str] = {}
        if kind == "webhook":
            in_use = [secrets.get("signing_secret", "")]
            until = _parse(secrets.get("previous_until"))
            if secrets.get("previous_secret") and until and until > datetime.now(timezone.utc):
                in_use.append(secrets["previous_secret"])
            headers = sign_headers(in_use, msg_id, raw)
        return await self.transport.post(url, raw, headers)

    async def _deliver(self, item: dict[str, Any]) -> None:
        delivery, channel = item["delivery"], item["channel"]
        kind, instance = channel["type"], self.settings.instance_id
        if not channel["enabled"] and delivery["event_type"] != "notification.test":
            await self.repo.record_failed(
                delivery["id"], channel["id"], instance, error="Channel disabled", status_code=None, cancelled=True
            )
            metrics.NOTIFICATIONS.labels(kind, "cancelled").inc()
            return
        if "secrets_error" in item:
            result = Result(False, False, error=f"Cannot decrypt the channel's settings: {item['secrets_error']}")
        else:
            try:
                result = await self.send(channel, item.get("secrets", {}), item["payload"], delivery["id"])
            except Exception as exc:  # a bug must not wedge the outbox: count it as a retryable failure
                logger.exception("Delivery %s crashed", delivery["id"])
                result = Result(False, True, error=f"Internal error ({type(exc).__name__})")

        if result.ok:
            await self.repo.record_delivered(delivery["id"], channel["id"], instance, result.status_code)
            metrics.NOTIFICATIONS.labels(kind, "delivered").inc()
            created = _parse(delivery["created_at"])
            if created:
                elapsed = (datetime.now(timezone.utc) - created).total_seconds()
                metrics.NOTIFICATION_LATENCY.labels(kind).observe(max(0.0, elapsed))
            return
        attempts = delivery["attempts"]  # includes this attempt: claiming increments the stored count
        error = result.error or "Delivery failed"
        if result.retryable and attempts < self.settings.notify_max_attempts:
            delay = result.retry_after if result.retry_after is not None else backoff(attempts)
            at = datetime.now(timezone.utc) + timedelta(seconds=delay)
            await self.repo.record_retry(
                delivery["id"], channel["id"], instance, error=error, status_code=result.status_code, at=at
            )
            metrics.NOTIFICATIONS.labels(kind, "retry").inc()
            logger.info("Notification %s to %s will be retried: %s", delivery["id"], channel["name"], error)
        else:
            await self.repo.record_failed(
                delivery["id"], channel["id"], instance, error=error, status_code=result.status_code
            )
            metrics.NOTIFICATIONS.labels(kind, "failed").inc()
            logger.warning("Notification %s to %s failed: %s", delivery["id"], channel["name"], error)
