"""Brand watches: lookalike domains in Certificate Transparency, per workspace."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select, update

from argus.storage.db import BrandWatchRow, Database

MAX_WATCHES = 20  # per workspace
MAX_KNOWN = 5000  # lookalike names remembered per watch
MAX_RECENT = 100  # findings kept for the page


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value: datetime | None) -> str | None:
    moment = _utc(value)
    return moment.isoformat() if moment else None


def _view(row: BrandWatchRow, *, full: bool = False) -> dict[str, Any]:
    """The watch as the API shows it; ``full`` adds what the watcher needs (every verdict and detail)."""
    data = row.data or {}
    triage = data.get("triage") or {}
    recent = [{**f, "triage": triage.get(f.get("name"))} for f in data.get("recent") or []]
    extra = {"triage": triage, "details": data.get("details") or {}} if full else {}
    return {
        **extra,
        "web_check": data.get("web_check") or "off",
        "takedowns": data.get("takedowns") or {},
        "id": row.id,
        "domain": row.domain,
        "allow": data.get("allow") or [],
        "known": len(data.get("known") or []),
        "recent": recent,
        "sources": data.get("sources") or {},
        "last_message": data.get("last_message", ""),
        "baselined": bool(data.get("baselined")),
        "cursor": int(data.get("cursor") or 0),
        "interval_hours": row.interval_hours,
        "enabled": row.enabled,
        "next_run_at": _iso(row.next_run_at),
        "last_run_at": _iso(row.last_run_at),
        "last_status": row.last_status,
        "alerts_raised": row.alerts_raised,
        "created_by": row.created_by,
        "workspace_id": row.workspace_id,
    }


class BrandWatchRepository:
    def __init__(self, db: Database):
        self.db = db

    async def count(self, workspace_id: str) -> int:
        async with self.db.session() as s:
            return int(await s.scalar(select(func.count()).where(BrandWatchRow.workspace_id == workspace_id)) or 0)

    async def find(self, workspace_id: str, domain: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.scalar(select(BrandWatchRow).where(BrandWatchRow.workspace_id == workspace_id,
                                                             BrandWatchRow.domain == domain))  # fmt: skip
        return _view(row) if row else None

    async def create(
        self, *, workspace_id: str, domain: str, allow: list[str], interval_hours: int, by: str, web_check: str = "off"
    ) -> dict[str, Any]:
        now = _now()
        row = BrandWatchRow(
            id=f"bw_{secrets.token_hex(8)}", workspace_id=workspace_id, domain=domain,
            data={"allow": allow, "known": [], "recent": [], "cursor": 0, "web_check": web_check},
            interval_hours=interval_hours,
            enabled=True, next_run_at=now, alerts_raised=0, created_by=by, created_at=now,
        )  # fmt: skip
        async with self.db.session() as s, s.begin():
            s.add(row)
        return _view(row)

    async def list_watches(self, workspace_id: str) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (await s.scalars(select(BrandWatchRow).where(BrandWatchRow.workspace_id == workspace_id)
                                    .order_by(BrandWatchRow.created_at.desc()))).all()  # fmt: skip
        return [_view(r) for r in rows]

    async def get(self, watch_id: str, workspace_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.get(BrandWatchRow, watch_id)
        return _view(row) if row is not None and row.workspace_id == workspace_id else None

    async def update(self, watch_id: str, workspace_id: str, **changes: Any) -> dict[str, Any] | None:
        """Change ``allow`` and/or ``web_check``."""
        async with self.db.session() as s, s.begin():
            row = await s.get(BrandWatchRow, watch_id)
            if row is None or row.workspace_id != workspace_id:
                return None
            row.data = {**(row.data or {}), **{k: v for k, v in changes.items() if k in ("allow", "web_check")}}
            return _view(row)

    async def put_takedown(
        self, watch_id: str, workspace_id: str | None, name: str, changes: dict[str, Any], event: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Create or change one takedown record (merging ``changes``) and add ``event`` to its history."""
        async with self.db.session() as s, s.begin():
            row = await s.get(BrandWatchRow, watch_id)
            if row is None or (workspace_id is not None and row.workspace_id != workspace_id):
                return None
            data = dict(row.data or {})
            takedowns = dict(data.get("takedowns") or {})
            record = {**(takedowns.get(name) or {"history": []}), **changes}
            record["history"] = [*record.get("history", []), {"at": _now().isoformat(), **event}][-50:]
            takedowns[name] = record
            data["takedowns"] = takedowns
            row.data = data
            return record

    async def delete(self, watch_id: str, workspace_id: str) -> bool:
        async with self.db.session() as s, s.begin():
            row = await s.get(BrandWatchRow, watch_id)
            if row is None or row.workspace_id != workspace_id:
                return False
            await s.delete(row)
            return True

    async def make_due(self, watch_id: str, workspace_id: str) -> bool:
        async with self.db.session() as s, s.begin():
            row = await s.get(BrandWatchRow, watch_id)
            if row is None or row.workspace_id != workspace_id:
                return False
            row.next_run_at = _now()
            return True

    async def due(self, now: datetime | None = None) -> list[dict[str, Any]]:
        moment = now or _now()
        async with self.db.session() as s:
            rows = (await s.scalars(select(BrandWatchRow).where(BrandWatchRow.enabled.is_(True)))).all()
        return [
            _view(r, full=True) for r in rows if (_utc(r.next_run_at) or moment) <= moment
        ]  # in Python: SQLite drops tzinfo

    async def claim(self, watch_id: str, now: datetime | None = None) -> bool:
        """Atomically take a due watch: only one replica's UPDATE still sees it due."""
        moment = now or _now()
        async with self.db.session() as s, s.begin():
            row = await s.get(BrandWatchRow, watch_id)
            if row is None:
                return False
            result = await s.execute(
                update(BrandWatchRow)
                .where(BrandWatchRow.id == watch_id, BrandWatchRow.next_run_at <= moment,
                       BrandWatchRow.enabled.is_(True))
                .values(next_run_at=moment + timedelta(hours=row.interval_hours))
                .execution_options(synchronize_session=False)
            )  # fmt: skip
        return bool(getattr(result, "rowcount", 0))

    async def first_seen(self, workspace_id: str) -> list[tuple[dict[str, Any], dict[str, str], dict[str, Any]]]:
        """Every watch of the workspace with its lookalikes, when each was first seen, and what it is."""
        async with self.db.session() as s:
            rows = (await s.scalars(select(BrandWatchRow).where(BrandWatchRow.workspace_id == workspace_id))).all()
        out = []
        for row in rows:
            data = row.data or {}
            fallback = _iso(row.last_run_at) or _iso(row.created_at) or ""
            dates = data.get("first_seen") or {}
            known = data.get("known") or []
            out.append(
                (_view(row, full=True), {k: dates.get(k, fallback) for k in known}, dict(data.get("details") or {}))
            )
        return out

    async def known(self, watch_id: str) -> list[str]:
        async with self.db.session() as s:
            row = await s.get(BrandWatchRow, watch_id)
        return list((row.data or {}).get("known") or []) if row else []

    async def record(
        self, watch_id: str, *, status: str, sources: dict[str, Any], message: str, known: list[str] | None = None,
        new: list[dict[str, Any]] | None = None, cursor: int | None = None, alerted: bool = False,
        retry_in: timedelta | None = None, triage: dict[str, dict[str, Any]] | None = None,
    ) -> None:  # fmt: skip
        async with self.db.session() as s, s.begin():
            row = await s.get(BrandWatchRow, watch_id)
            if row is None:
                return
            data = dict(row.data or {})
            if known is not None:
                data["known"] = known[-MAX_KNOWN:]
                first_seen = dict(data.get("first_seen") or {})
                stamp = _now().isoformat()
                for finding in new or []:
                    first_seen.setdefault(finding["name"], stamp)
                kept = set(data["known"])
                data["first_seen"] = {k: v for k, v in first_seen.items() if k in kept}
                details = dict(data.get("details") or {})  # what TAXII says about each lookalike
                for finding in new or []:
                    details.setdefault(
                        finding["name"], {k: finding.get(k) for k in ("technique", "detail", "severity", "display")}
                    )
                for name, verdict in (triage or {}).items():  # the current severity, for TAXII
                    if name in details:
                        details[name] = {
                            **details[name],
                            "severity": verdict["severity"],
                            "verdict": verdict["verdict"],
                        }
                data["details"] = {k: v for k, v in details.items() if k in kept}
                data["triage"] = {
                    k: v for k, v in {**(data.get("triage") or {}), **(triage or {})}.items() if k in kept
                }
            if new:
                data["recent"] = (new + list(data.get("recent") or []))[:MAX_RECENT]
            if cursor is not None:
                data["cursor"] = cursor
            if status in ("ok", "partial"):
                data["baselined"] = True  # the first run that reached a source records what exists today
            data["sources"], data["last_message"] = sources, message[:300]
            row.data = data
            row.last_run_at, row.last_status = _now(), status
            if alerted:
                row.alerts_raised = (row.alerts_raised or 0) + 1
            if retry_in is not None:  # every source failed: try again soon rather than in a day
                row.next_run_at = min(_utc(row.next_run_at) or _now(), _now() + retry_in)
