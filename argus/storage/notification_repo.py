"""Persistence for notification channels and the delivery outbox.

The outbox pattern: when an alert is raised, one delivery row per matching channel is
written **in the same database transaction** as the alert. Either both exist or neither
does, so a crash can never lose a notification for an alert that was saved, and a slow or
unreachable Slack never slows down or breaks alert creation. Dispatchers on every replica
then work through due rows:

* a row is **claimed** with a conditional UPDATE and a time-limited **lease**, so exactly
  one replica sends it; if that replica dies mid-send, the lease expires and another
  replica retries;
* results are recorded only by the replica that still holds the claim (**fencing**);
* the ``webhook-id`` is the delivery id, stable across retries, so receivers can drop the
  rare duplicate (at-least-once delivery).
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, cast

from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession

from argus.notify.channels import INTEGRATIONS, SEVERITY_RANK, ChannelConfigError
from argus.notify.render import alert_event
from argus.notify.signing import new_secret
from argus.security.crypto import SecretBox, SecretBoxError
from argus.storage.db import Database, NotificationChannelRow, NotificationDeliveryRow, WorkspaceRow

ROTATION_OVERLAP = timedelta(hours=24)
RETENTION = timedelta(days=30)
DONE = ("delivered", "failed", "cancelled")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value: datetime | None) -> str | None:
    v = _utc(value)
    return v.isoformat() if v else None


def _context(workspace_id: str, channel_id: str) -> str:
    return f"notification-channel:{workspace_id}:{channel_id}"


def _channel(row: NotificationChannelRow) -> dict[str, Any]:
    health = "untested"
    if row.consecutive_failures:
        health = "failing"
    elif row.last_success_at:
        health = "ok"
    return {
        "id": row.id,
        "workspace_id": row.workspace_id,
        "name": row.name,
        "type": row.type,
        "enabled": bool(row.enabled),
        "min_severity": row.min_severity,
        **(row.config or {}),
        "signed": row.type == "webhook",
        "integration": row.type in INTEGRATIONS,
        "health": health,
        "created_at": _iso(row.created_at),
        "created_by": row.created_by,
        "updated_at": _iso(row.updated_at),
        "last_success_at": _iso(row.last_success_at),
        "last_failure_at": _iso(row.last_failure_at),
        "last_error": row.last_error,
        "consecutive_failures": row.consecutive_failures or 0,
    }


def _delivery(row: NotificationDeliveryRow, channel: NotificationChannelRow | None = None) -> dict[str, Any]:
    out = {
        "id": row.id,
        "workspace_id": row.workspace_id,
        "channel_id": row.channel_id,
        "event_type": row.event_type,
        "event_id": row.event_id,
        "status": row.status,
        "attempts": row.attempts or 0,
        "next_attempt_at": _iso(row.next_attempt_at),
        "last_status_code": row.last_status_code,
        "last_error": row.last_error,
        "created_at": _iso(row.created_at),
        "delivered_at": _iso(row.delivered_at),
        "reference": row.reference,
        "summary": _summary(row.payload),
    }
    if channel is not None:
        out["channel_name"] = channel.name
        out["channel_type"] = channel.type
    return out


def _summary(event: dict[str, Any]) -> str:
    if event.get("type") == "report.scheduled":
        report = event.get("report") or {}
        if report.get("kind") == "board":
            return f"Board report {report.get('id')} ({str(report.get('overall', '')).upper()})"[:300]
        return f"Report {report.get('id')} for {report.get('target')} ({str(report.get('rating', '')).upper()})"[:300]
    if event.get("type") == "alert.raised":
        alert = event.get("alert") or {}
        return f"{str(alert.get('severity', '')).upper()}: {alert.get('headline', '')}"[:300]
    return str(event.get("message") or event.get("type") or "")[:300]


def _new_delivery(channel: NotificationChannelRow, event: dict[str, Any], moment: datetime) -> NotificationDeliveryRow:
    return NotificationDeliveryRow(
        id=f"dlv_{secrets.token_hex(8)}",
        workspace_id=channel.workspace_id,
        channel_id=channel.id,
        event_type=str(event["type"]),
        event_id=str(event["id"]),
        payload=event,
        status="pending",
        attempts=0,
        next_attempt_at=moment,
        created_at=moment,
    )


async def enqueue_event(session: AsyncSession, workspace_id: str, event: dict[str, Any], severity: str) -> int:
    """Queue ``event`` for every enabled channel of the workspace whose threshold it meets.

    Runs inside the caller's transaction (the transactional outbox).
    """
    rank = SEVERITY_RANK.get(severity, 0)
    channels = (
        await session.scalars(
            select(NotificationChannelRow).where(
                NotificationChannelRow.workspace_id == workspace_id, NotificationChannelRow.enabled.is_(True)
            )
        )
    ).all()
    moment = _now()
    queued = 0
    for channel in channels:
        if rank >= SEVERITY_RANK.get(channel.min_severity, 99):
            session.add(_new_delivery(channel, event, moment))
            queued += 1
    return queued


async def enqueue_to_channels(
    session: AsyncSession, workspace_id: str, channel_ids: list[str], event: dict[str, Any]
) -> int:
    """Queue ``event`` for the listed channels that still exist in this workspace and are enabled."""
    if not channel_ids:
        return 0
    channels = (
        await session.scalars(
            select(NotificationChannelRow).where(
                NotificationChannelRow.id.in_(channel_ids),
                NotificationChannelRow.workspace_id == workspace_id,
                NotificationChannelRow.enabled.is_(True),
            )
        )
    ).all()
    moment = _now()
    for channel in channels:
        session.add(_new_delivery(channel, event, moment))
    return len(channels)


async def enqueue_alert(session: AsyncSession, alert: dict[str, Any], public_url: str | None) -> int:
    """Build the alert's event and queue it (inside the transaction that saves the alert)."""
    workspace = await session.get(WorkspaceRow, alert["workspace_id"])
    ws = {"id": alert["workspace_id"], "name": workspace.name if workspace else alert["workspace_id"]}
    return await enqueue_event(session, alert["workspace_id"], alert_event(alert, ws, public_url), alert["severity"])


class NotificationRepository:
    def __init__(self, db: Database, box: SecretBox):
        self.db = db
        self.box = box

    # ------------------------------------------------------------------ channels
    def _seal(self, workspace_id: str, channel_id: str, secret_values: dict[str, Any]) -> str:
        try:
            return self.box.seal(secret_values, _context(workspace_id, channel_id))
        except SecretBoxError as exc:
            raise ChannelConfigError(
                "This server has no encryption key, so it cannot store webhook URLs safely. "
                "An administrator must set ARGUS_ENCRYPTION_KEY."
            ) from exc

    def open_secrets(self, row: NotificationChannelRow) -> dict[str, Any]:
        if not row.sealed:
            return {}
        return self.box.open(row.sealed, _context(row.workspace_id, row.id))

    async def create_channel(
        self,
        *,
        workspace_id: str,
        name: str,
        channel_type: str,
        min_severity: str,
        enabled: bool,
        public: dict[str, Any],
        secret_values: dict[str, Any],
        by: str,
    ) -> tuple[dict[str, Any], str | None]:
        channel_id = f"chan_{secrets.token_hex(8)}"
        signing_secret = new_secret() if channel_type == "webhook" else None
        if signing_secret:
            secret_values = {**secret_values, "signing_secret": signing_secret}
        moment = _now()
        row = NotificationChannelRow(
            id=channel_id,
            workspace_id=workspace_id,
            name=name,
            type=channel_type,
            enabled=enabled,
            min_severity=min_severity,
            config=public,
            sealed=self._seal(workspace_id, channel_id, secret_values) if secret_values else None,
            created_at=moment,
            created_by=by,
            updated_at=moment,
            consecutive_failures=0,
        )
        async with self.db.session() as s, s.begin():
            s.add(row)
        return _channel(row), signing_secret

    async def _row(self, s: AsyncSession, channel_id: str, workspace_id: str) -> NotificationChannelRow | None:
        row = await s.get(NotificationChannelRow, channel_id)
        return row if row is not None and row.workspace_id == workspace_id else None

    async def list_channels(self, *, workspace_id: str) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = await s.scalars(
                select(NotificationChannelRow)
                .where(NotificationChannelRow.workspace_id == workspace_id)
                .order_by(NotificationChannelRow.created_at)
            )
            return [_channel(r) for r in rows]

    async def get_channel(self, channel_id: str, *, workspace_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await self._row(s, channel_id, workspace_id)
            return _channel(row) if row else None

    async def update_channel(
        self,
        channel_id: str,
        *,
        workspace_id: str,
        name: str | None = None,
        min_severity: str | None = None,
        enabled: bool | None = None,
        public: dict[str, Any] | None = None,
        secret_values: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        async with self.db.session() as s, s.begin():
            row = await self._row(s, channel_id, workspace_id)
            if row is None:
                return None
            if name is not None:
                row.name = name
            if min_severity is not None:
                row.min_severity = min_severity
            if enabled is not None:
                row.enabled = enabled
            if public is not None:
                row.config = public
            if secret_values is not None:  # a new destination keeps its signing secrets
                kept = (
                    {}  # validate() already carried over the credentials it allows to be kept
                    if row.type in INTEGRATIONS
                    else {k: v for k, v in self.open_secrets(row).items() if k != "url"}
                )
                row.sealed = (
                    self._seal(workspace_id, channel_id, {**kept, **secret_values}) if (kept or secret_values) else None
                )
                row.consecutive_failures, row.last_error = 0, None
            row.updated_at = _now()
            return _channel(row)

    async def channel_secrets(self, channel_id: str, *, workspace_id: str) -> dict[str, Any] | None:
        """The decrypted settings of a channel (server-side only: used to keep credentials on edit)."""
        async with self.db.session() as s:
            row = await self._row(s, channel_id, workspace_id)
            if row is None:
                return None
            try:
                return self.open_secrets(row)
            except SecretBoxError:  # e.g. the encryption key changed: the credentials must be entered again
                return None

    async def rotate_secret(self, channel_id: str, *, workspace_id: str) -> str | None:
        """New signing secret; the previous one keeps signing too for 24 h so receivers can switch."""
        async with self.db.session() as s, s.begin():
            row = await self._row(s, channel_id, workspace_id)
            if row is None or row.type != "webhook":
                return None
            current = self.open_secrets(row)
            secret = new_secret()
            current.update(
                signing_secret=secret,
                previous_secret=current.get("signing_secret"),
                previous_until=(_now() + ROTATION_OVERLAP).isoformat(),
            )
            row.sealed = self._seal(workspace_id, channel_id, current)
            row.updated_at = _now()
            return secret

    async def delete_channel(self, channel_id: str, *, workspace_id: str) -> bool:
        async with self.db.session() as s, s.begin():
            row = await self._row(s, channel_id, workspace_id)
            if row is None:
                return False
            await s.execute(delete(NotificationDeliveryRow).where(NotificationDeliveryRow.channel_id == channel_id))
            await s.delete(row)
            return True

    # ------------------------------------------------------------------ deliveries
    async def enqueue_test(self, channel_id: str, *, workspace_id: str, event: dict[str, Any]) -> dict[str, Any] | None:
        async with self.db.session() as s, s.begin():
            row = await self._row(s, channel_id, workspace_id)
            if row is None:
                return None
            delivery = _new_delivery(row, event, _now())
            s.add(delivery)
            return _delivery(delivery, row)

    async def deliveries(
        self, *, workspace_id: str, channel_id: str | None = None, status: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        stmt = (
            select(NotificationDeliveryRow, NotificationChannelRow)
            .join(NotificationChannelRow, NotificationChannelRow.id == NotificationDeliveryRow.channel_id)
            .where(NotificationDeliveryRow.workspace_id == workspace_id)
            .order_by(NotificationDeliveryRow.created_at.desc())
            .limit(limit)
        )
        if channel_id:
            stmt = stmt.where(NotificationDeliveryRow.channel_id == channel_id)
        if status:
            stmt = stmt.where(NotificationDeliveryRow.status == status)
        async with self.db.session() as s:
            return [_delivery(d, c) for d, c in (await s.execute(stmt)).all()]

    async def retry(self, delivery_id: str, *, workspace_id: str) -> dict[str, Any] | None:
        """Send a failed delivery again, with a fresh set of attempts."""
        async with self.db.session() as s, s.begin():
            row = await s.get(NotificationDeliveryRow, delivery_id)
            if row is None or row.workspace_id != workspace_id:
                return None
            if row.status in ("failed", "cancelled"):
                row.status, row.attempts, row.next_attempt_at = "pending", 0, _now()
                row.lease_until = row.claimed_by = None
            return _delivery(row)

    def _due(self, moment: datetime) -> Any:
        return or_(
            and_(NotificationDeliveryRow.status == "pending", NotificationDeliveryRow.next_attempt_at <= moment),
            and_(NotificationDeliveryRow.status == "sending", NotificationDeliveryRow.lease_until < moment),
        )

    async def claim_due(self, instance: str, *, limit: int = 20, lease_seconds: float = 60.0) -> list[dict[str, Any]]:
        """Claim up to ``limit`` due deliveries for this replica, with their channel and secrets."""
        moment = _now()
        async with self.db.session() as s:
            ids = list(
                await s.scalars(
                    select(NotificationDeliveryRow.id)
                    .where(self._due(moment))
                    .order_by(NotificationDeliveryRow.next_attempt_at)
                    .limit(limit)
                )
            )
        claimed: list[dict[str, Any]] = []
        for delivery_id in ids:
            async with self.db.session() as s, s.begin():
                result = await s.execute(
                    update(NotificationDeliveryRow)
                    .where(NotificationDeliveryRow.id == delivery_id, self._due(moment))
                    .values(
                        status="sending",
                        claimed_by=instance,
                        lease_until=moment + timedelta(seconds=lease_seconds),
                        attempts=NotificationDeliveryRow.attempts + 1,
                    )
                    .execution_options(synchronize_session=False)
                )
                if (cast("CursorResult[Any]", result).rowcount or 0) != 1:
                    continue  # another replica took it
                delivery = await s.get(NotificationDeliveryRow, delivery_id)
                channel = await s.get(NotificationChannelRow, delivery.channel_id) if delivery else None
                if delivery is None or channel is None:
                    continue
                item: dict[str, Any] = {"delivery": _delivery(delivery, channel), "payload": delivery.payload}
                item["channel"] = _channel(channel)
                try:
                    item["secrets"] = self.open_secrets(channel)
                    if channel.sealed and self.box.needs_rotation(channel.sealed):
                        channel.sealed = self.box.seal(item["secrets"], _context(channel.workspace_id, channel.id))
                except SecretBoxError as exc:
                    item["secrets_error"] = str(exc)
                claimed.append(item)
        return claimed

    async def _finish(self, delivery_id: str, instance: str, **values: Any) -> bool:
        async with self.db.session() as s, s.begin():
            result = await s.execute(
                update(NotificationDeliveryRow)
                .where(NotificationDeliveryRow.id == delivery_id, NotificationDeliveryRow.claimed_by == instance)
                .values(lease_until=None, **values)
                .execution_options(synchronize_session=False)
            )
        return (cast("CursorResult[Any]", result).rowcount or 0) == 1

    async def _channel_result(self, channel_id: str, *, ok: bool, error: str | None = None) -> None:
        async with self.db.session() as s, s.begin():
            row = await s.get(NotificationChannelRow, channel_id)
            if row is None:
                return
            if ok:
                row.last_success_at, row.consecutive_failures, row.last_error = _now(), 0, None
            else:
                row.last_failure_at = _now()
                row.consecutive_failures = (row.consecutive_failures or 0) + 1
                row.last_error = (error or "")[:512]

    async def record_delivered(
        self, delivery_id: str, channel_id: str, instance: str, status_code: int | None, *, reference: str | None = None
    ) -> bool:
        done = await self._finish(
            delivery_id,
            instance,
            status="delivered",
            delivered_at=_now(),
            last_status_code=status_code,
            last_error=None,
            reference=reference[:128] if reference else None,
        )
        if done:
            await self._channel_result(channel_id, ok=True)
        return done

    async def record_retry(
        self, delivery_id: str, channel_id: str, instance: str, *, error: str, status_code: int | None, at: datetime
    ) -> bool:
        done = await self._finish(
            delivery_id,
            instance,
            status="pending",
            next_attempt_at=at,
            last_error=error[:512],
            last_status_code=status_code,
        )
        if done:
            await self._channel_result(channel_id, ok=False, error=error)
        return done

    async def record_failed(
        self,
        delivery_id: str,
        channel_id: str,
        instance: str,
        *,
        error: str,
        status_code: int | None,
        cancelled: bool = False,
    ) -> bool:
        done = await self._finish(
            delivery_id,
            instance,
            status="cancelled" if cancelled else "failed",
            last_error=error[:512],
            last_status_code=status_code,
        )
        if done and not cancelled:
            await self._channel_result(channel_id, ok=False, error=error)
        return done

    async def backlog(self) -> int:
        async with self.db.session() as s:
            return int(
                await s.scalar(
                    select(func.count())
                    .select_from(NotificationDeliveryRow)
                    .where(NotificationDeliveryRow.status.in_(("pending", "sending")))
                )
                or 0
            )

    async def purge(self, older_than: timedelta = RETENTION) -> int:
        async with self.db.session() as s, s.begin():
            result = await s.execute(
                delete(NotificationDeliveryRow).where(
                    NotificationDeliveryRow.status.in_(DONE), NotificationDeliveryRow.created_at < _now() - older_than
                )
            )
        return cast("CursorResult[Any]", result).rowcount or 0
