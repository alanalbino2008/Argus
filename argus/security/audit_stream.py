"""Forward the audit log to a SIEM as it is written (Phase 92).

A security team watches its SIEM, not each application's audit page, and an attacker who gets in
deletes local logs first. A stream sends every new audit entry to one of the workspace's Splunk,
Sentinel or webhook destinations, in order:

* a **checkpoint** (the newest entry delivered) moves only after a destination accepted an entry,
  so an outage delays entries, never loses them: they go once the destination is back;
* each entry keeps its chain hashes, so the SIEM's copy can be checked against Argus later, and its
  event id (``audit-<id>``) lets the receiver drop a duplicate after a retry;
* a workspace stream sends that workspace's entries; a platform stream (platform administrators)
  sends every entry, sign-ins and platform events included;
* one replica forwards at a time (cluster lock). ``argus_audit_stream_lag_entries`` and the
  ``ArgusAuditStreamFailing`` alert show a stream falling behind.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from argus.storage.db import AuditStreamRow

logger = logging.getLogger("argus.audit_stream")
KINDS = ("splunk", "sentinel", "webhook")  # destinations that take structured events
POLL_SECONDS = 30
BATCH = 200
LOCK = 0x4152_4755_4155_4453  # "ARGUAUDS"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()


def view(row: AuditStreamRow, newest: int | None = None) -> dict[str, Any]:
    return {
        "id": row.id, "workspace_id": row.workspace_id, "platform": bool(row.platform), "channel_id": row.channel_id,
        "last_id": row.last_id, "enabled": bool(row.enabled), "sent": row.sent, "last_sent_at": _iso(row.last_sent_at),
        "last_error": row.last_error, "failing_since": _iso(row.failing_since), "created_by": row.created_by,
        "created_at": _iso(row.created_at), "behind": max(0, newest - row.last_id) if newest is not None else None,
    }  # fmt: skip


def event_of(entry: dict[str, Any], workspace: dict[str, Any]) -> dict[str, Any]:
    """An audit entry as a notification event (what Splunk, Sentinel and webhooks receive)."""
    return {
        "type": "audit.event", "id": f"audit-{entry['id']}", "occurred_at": entry["ts"],
        "workspace": {"id": entry.get("workspace_id") or workspace.get("id"), "name": workspace.get("name") or ""},
        "message": f"{entry['action']} by {entry['actor_name']} ({entry['outcome']})",
        "audit": entry,
    }  # fmt: skip


class AuditStreams:
    def __init__(self, app: Any):
        self.app = app
        self.db = app.state.db

    async def create(
        self, *, workspace_id: str, channel_id: str, platform: bool, start: str, by: str
    ) -> dict[str, Any]:
        row = AuditStreamRow(
            id=f"aus_{secrets.token_hex(8)}", workspace_id=workspace_id, platform=platform, channel_id=channel_id,
            last_id=await self.app.state.audit.last_id() if start == "now" else 0, enabled=True, sent=0,
            created_by=by, created_at=_now(),
        )  # fmt: skip
        async with self.db.session() as s, s.begin():
            s.add(row)
        return view(row)

    async def list(self, workspace_id: str) -> list[dict[str, Any]]:
        newest = await self.app.state.audit.last_id()
        async with self.db.session() as s:
            rows = (await s.scalars(select(AuditStreamRow).where(AuditStreamRow.workspace_id == workspace_id)
                                    .order_by(AuditStreamRow.created_at))).all()  # fmt: skip
        return [view(r, newest) for r in rows]

    async def get(self, stream_id: str, workspace_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.get(AuditStreamRow, stream_id)
        return view(row) if row is not None and row.workspace_id == workspace_id else None

    async def set_enabled(self, stream_id: str, workspace_id: str, enabled: bool) -> dict[str, Any] | None:
        async with self.db.session() as s, s.begin():
            row = await s.get(AuditStreamRow, stream_id)
            if row is None or row.workspace_id != workspace_id:
                return None
            row.enabled = enabled
            return view(row)

    async def delete(self, stream_id: str, workspace_id: str) -> bool:
        async with self.db.session() as s, s.begin():
            row = await s.get(AuditStreamRow, stream_id)
            if row is None or row.workspace_id != workspace_id:
                return False
            await s.delete(row)
            return True

    # ------------------------------------------------------------------ forwarding
    async def tick(self) -> int:
        """Forward what is due on every enabled stream; returns how many entries were delivered."""
        from argus.observability import metrics

        async with self.db.session() as s:
            ids = [
                r for (r,) in (await s.execute(select(AuditStreamRow.id).where(AuditStreamRow.enabled.is_(True)))).all()
            ]
        delivered = 0
        async with self.db.cluster_lock(LOCK):
            for stream_id in ids:
                delivered += await self._forward(stream_id)
        newest = await self.app.state.audit.last_id()
        async with self.db.session() as s:
            checkpoints = [c for (c,) in (await s.execute(select(AuditStreamRow.last_id)
                                                          .where(AuditStreamRow.enabled.is_(True)))).all()]  # fmt: skip
        metrics.AUDIT_STREAM_LAG.set(max((newest - c for c in checkpoints), default=0))
        return delivered

    async def _forward(self, stream_id: str) -> int:
        from argus.observability import metrics

        state = self.app.state
        async with self.db.session() as s:
            row = await s.get(AuditStreamRow, stream_id)
        if row is None or not row.enabled:
            return 0
        channel = await state.notifications.get_channel(row.channel_id, workspace_id=row.workspace_id)
        secrets_ = await state.notifications.channel_secrets(row.channel_id, workspace_id=row.workspace_id)
        if channel is None or channel["type"] not in KINDS:
            await self._record(stream_id, row.last_id, 0, "The destination was removed or cannot take audit events")
            return 0
        entries = await state.audit.events(after_id=row.last_id, limit=BATCH,
                                           workspace_id=None if row.platform else row.workspace_id)  # fmt: skip
        if not entries:
            return 0
        workspace = await state.workspaces.get(row.workspace_id) or {"id": row.workspace_id}
        last, sent, error = row.last_id, 0, None
        for entry in entries:
            event = event_of(entry, workspace)
            try:
                result = await state.notifier.send(channel, secrets_ or {}, event, event["id"])
            except Exception as exc:  # noqa: BLE001  (a broken destination must not stop the others)
                result, error = None, f"{type(exc).__name__}"
            if result is None or not result.ok:
                error = error or (result.error if result else None) or "The destination refused the entry"
                metrics.AUDIT_STREAM_EVENTS.labels("failed").inc()
                break
            last, sent = entry["id"], sent + 1
            metrics.AUDIT_STREAM_EVENTS.labels("sent").inc()
        await self._record(stream_id, last, sent, error)
        return sent

    async def _record(self, stream_id: str, last_id: int, sent: int, error: str | None) -> None:
        async with self.db.session() as s, s.begin():
            row = await s.get(AuditStreamRow, stream_id)
            if row is None:
                return
            row.last_id = max(row.last_id, last_id)
            row.sent += sent
            if sent:
                row.last_sent_at = _now()
            row.last_error = error[:500] if error else None
            row.failing_since = (row.failing_since or _now()) if error else None

    async def run_forever(self, poll_seconds: float = POLL_SECONDS) -> None:
        while True:
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Audit stream tick failed")
            await asyncio.sleep(poll_seconds)
