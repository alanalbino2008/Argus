"""Brand watches and the lookalike domains they found, per workspace.

A watch keeps its settings and last-run state in one small document; each lookalike it found is a row
of its own (``brand_lookalikes``) with the finding, its latest triage and its takedown, so a run
touches only the lookalikes it checks, and listing, campaigns and TAXII read only what they show.

Watches saved before that change kept every lookalike inside the watch's document; they are
converted the first time they are read (the documents are encrypted with the application's key, so
the database migration cannot do it).
"""

from __future__ import annotations

import secrets
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from argus.intel.lookalike_triage import VERDICT_LABELS
from argus.storage.db import BrandLookalikeRow, BrandWatchRow, Database

MAX_WATCHES = 20  # per workspace
MAX_KNOWN = 5000  # lookalikes remembered per watch (the oldest without a takedown go first)
MAX_RECENT = 100  # findings shown on the page
LEGACY_KEYS = ("known", "first_seen", "details", "triage", "takedowns", "recent")
OPEN_TAKEDOWN = ("drafted", "reported")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value: datetime | None) -> str | None:
    moment = _utc(value)
    return moment.isoformat() if moment else None


def _parse(value: Any) -> datetime | None:
    try:
        return _utc(datetime.fromisoformat(str(value).replace("Z", "+00:00"))) if value else None
    except ValueError:
        return None


def infra_of(triage: dict[str, Any] | None) -> dict[str, Any] | None:
    """What campaigns group on, from a triage: addresses, name servers, mail hosts, favicon and page title."""
    if not triage:
        return None
    dns, web = triage.get("dns") or {}, triage.get("web") or {}
    return {"dns": {k: list(dns.get(k) or [])[:8] for k in ("ips", "ns", "mx")},
            "web": {"favicon_sha256": web.get("favicon_sha256") or "", "title": str(web.get("title") or "")[:200]}}  # fmt: skip


def _item(row: BrandLookalikeRow) -> dict[str, Any]:
    """A lookalike as the page and the API show it: the finding, with its triage and takedown."""
    return {**(row.finding or {}), "name": row.name, "severity": row.severity, "verdict": row.verdict or "",
            "first_seen": _iso(row.first_seen_at), "triage": row.triage, "takedown": row.takedown}  # fmt: skip


def _view(row: BrandWatchRow, extras: dict[str, Any] | None = None, *, full: bool = False) -> dict[str, Any]:
    data = row.data or {}
    extras = extras or {}
    out = {
        "web_check": data.get("web_check") or "off",
        "reference_urls": data.get("reference_urls") or [],
        "references": [{"url": r["url"], "captured_at": r.get("captured_at")} for r in data.get("visual_refs") or []],
        "takedowns": extras.get("takedowns", {}),
        "id": row.id,
        "domain": row.domain,
        "allow": data.get("allow") or [],
        "known": extras.get("known", 0),
        "recent": extras.get("recent", []),
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
    if full:
        out["visual_refs"] = data.get("visual_refs") or []
    return out


class BrandWatchRepository:
    def __init__(self, db: Database):
        self.db = db

    # ------------------------------------------------------------------ conversion of old documents
    async def _convert(self, rows: Iterable[BrandWatchRow]) -> bool:
        """Move lookalikes kept inside old watch documents into rows; True when anything moved."""
        legacy = [r.id for r in rows if any(k in (r.data or {}) for k in LEGACY_KEYS)]
        if not legacy:
            return False
        async with self.db.session() as s, s.begin():
            for watch_id in legacy:
                row = await s.get(BrandWatchRow, watch_id)
                if row is None:
                    continue
                data = dict(row.data or {})
                fallback = row.last_run_at or row.created_at
                recent = {f.get("name"): f for f in data.get("recent") or [] if isinstance(f, dict)}
                details, triage = data.get("details") or {}, data.get("triage") or {}
                takedowns, dates = data.get("takedowns") or {}, data.get("first_seen") or {}
                existing = set((await s.scalars(select(BrandLookalikeRow.name).where(
                    BrandLookalikeRow.watch_id == watch_id))).all())  # fmt: skip
                for name in dict.fromkeys(data.get("known") or []):
                    if name in existing:
                        continue
                    finding = dict(recent.get(name) or {"name": name, **(details.get(name) or {})})
                    finding.pop("triage", None)
                    verdict = triage.get(name) or {}
                    record = takedowns.get(name)
                    s.add(BrandLookalikeRow(
                        id=f"bl_{secrets.token_hex(8)}", watch_id=watch_id, workspace_id=row.workspace_id, name=name,
                        first_seen_at=_parse(dates.get(name)) or fallback,
                        checked_at=_parse(verdict.get("checked_at")),
                        severity=str(verdict.get("severity") or finding.get("severity") or "medium"),
                        verdict=str(verdict.get("verdict") or finding.get("verdict") or ""),
                        technique=str(finding.get("technique") or "")[:16], display=str(finding.get("display") or name)[:253],
                        detail=str(finding.get("detail") or "")[:160],
                        takedown_status=(record or {}).get("status"), finding=finding, triage=verdict or None,
                        infra=infra_of(verdict),
                        takedown=record,
                    ))  # fmt: skip
                row.data = {k: v for k, v in data.items() if k not in LEGACY_KEYS}
        return True

    async def _watches(self, s: AsyncSession, *criteria: Any) -> list[BrandWatchRow]:
        rows = list((await s.scalars(select(BrandWatchRow).where(*criteria)
                                     .order_by(BrandWatchRow.created_at.desc()))).all())  # fmt: skip
        if await self._convert(rows):
            s.expire_all()
            rows = list((await s.scalars(select(BrandWatchRow).where(*criteria)
                                         .order_by(BrandWatchRow.created_at.desc()))).all())  # fmt: skip
        return rows

    async def _extras(self, s: AsyncSession, watch_ids: list[str]) -> dict[str, dict[str, Any]]:
        """For the page: how many lookalikes each watch knows, the most recent, and the takedowns."""
        if not watch_ids:
            return {}
        counts = dict((await s.execute(select(BrandLookalikeRow.watch_id, func.count()).where(
            BrandLookalikeRow.watch_id.in_(watch_ids)).group_by(BrandLookalikeRow.watch_id))).all())  # fmt: skip
        out: dict[str, dict[str, Any]] = {}
        for watch_id in watch_ids:
            recent = (await s.scalars(select(BrandLookalikeRow).where(BrandLookalikeRow.watch_id == watch_id)
                                      .order_by(BrandLookalikeRow.first_seen_at.desc()).limit(MAX_RECENT))).all()  # fmt: skip
            with_takedown = (await s.scalars(select(BrandLookalikeRow).where(
                BrandLookalikeRow.watch_id == watch_id, BrandLookalikeRow.takedown_status.is_not(None)))).all()  # fmt: skip
            out[watch_id] = {"known": int(counts.get(watch_id, 0)), "recent": [_item(r) for r in recent],
                             "takedowns": {r.name: r.takedown for r in with_takedown}}  # fmt: skip
        return out

    # ------------------------------------------------------------------ watches
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
            data={"allow": allow, "cursor": 0, "web_check": web_check}, interval_hours=interval_hours,
            enabled=True, next_run_at=now, alerts_raised=0, created_by=by, created_at=now,
        )  # fmt: skip
        async with self.db.session() as s, s.begin():
            s.add(row)
        return _view(row)

    async def list_watches(self, workspace_id: str) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = await self._watches(s, BrandWatchRow.workspace_id == workspace_id)
            extras = await self._extras(s, [r.id for r in rows])
        return [_view(r, extras.get(r.id)) for r in rows]

    async def get(self, watch_id: str, workspace_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            rows = await self._watches(s, BrandWatchRow.id == watch_id, BrandWatchRow.workspace_id == workspace_id)
            if not rows:
                return None
            extras = await self._extras(s, [watch_id])
        return _view(rows[0], extras.get(watch_id))

    async def update(self, watch_id: str, workspace_id: str, **changes: Any) -> dict[str, Any] | None:
        """Change ``allow``, ``web_check`` and/or ``reference_urls``."""
        async with self.db.session() as s, s.begin():
            row = await s.get(BrandWatchRow, watch_id)
            if row is None or row.workspace_id != workspace_id:
                return None
            row.data = {**(row.data or {}),
                        **{k: v for k, v in changes.items() if k in ("allow", "web_check", "reference_urls")}}  # fmt: skip
        return await self.get(watch_id, workspace_id)

    async def delete(self, watch_id: str, workspace_id: str) -> bool:
        async with self.db.session() as s, s.begin():
            row = await s.get(BrandWatchRow, watch_id)
            if row is None or row.workspace_id != workspace_id:
                return False
            await s.execute(delete(BrandLookalikeRow).where(BrandLookalikeRow.watch_id == watch_id))
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
            rows = await self._watches(s, BrandWatchRow.enabled.is_(True))
        return [_view(r, full=True) for r in rows if (_utc(r.next_run_at) or moment) <= moment]  # SQLite drops tzinfo

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

    # ------------------------------------------------------------------ lookalikes
    async def known_names(self, watch_id: str, names: Iterable[str]) -> set[str]:
        """Which of ``names`` the watch already knows."""
        wanted = list(dict.fromkeys(names))
        found: set[str] = set()
        async with self.db.session() as s:
            for i in range(0, len(wanted), 500):
                found |= set((await s.scalars(select(BrandLookalikeRow.name).where(
                    BrandLookalikeRow.watch_id == watch_id, BrandLookalikeRow.name.in_(wanted[i:i + 500])))).all())  # fmt: skip
        return found

    async def lookalikes(self, watch_id: str, names: Iterable[str]) -> dict[str, dict[str, Any]]:
        """The named lookalikes (finding, triage and takedown), by name."""
        wanted = list(dict.fromkeys(names))
        out: dict[str, dict[str, Any]] = {}
        async with self.db.session() as s:
            for i in range(0, len(wanted), 500):
                rows = (await s.scalars(select(BrandLookalikeRow).where(
                    BrandLookalikeRow.watch_id == watch_id, BrandLookalikeRow.name.in_(wanted[i:i + 500])))).all()  # fmt: skip
                out.update({r.name: _item(r) for r in rows})
        return out

    async def lookalike(self, watch_id: str, workspace_id: str, name: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.scalar(select(BrandLookalikeRow).where(BrandLookalikeRow.watch_id == watch_id,
                                                                 BrandLookalikeRow.workspace_id == workspace_id,
                                                                 BrandLookalikeRow.name == name))  # fmt: skip
        return _item(row) if row else None

    async def stale(self, watch_id: str, limit: int, exclude: Iterable[str] = ()) -> list[str]:
        """Known lookalikes checked longest ago (never-checked first)."""
        skip = set(exclude)
        async with self.db.session() as s:
            names = (await s.scalars(select(BrandLookalikeRow.name).where(BrandLookalikeRow.watch_id == watch_id)
                                     .order_by(BrandLookalikeRow.checked_at.is_not(None), BrandLookalikeRow.checked_at,
                                               BrandLookalikeRow.name)
                                     .limit(limit + len(skip)))).all()  # fmt: skip
        return [n for n in names if n not in skip][:limit]

    async def open_takedowns(self, watch_id: str) -> list[str]:
        async with self.db.session() as s:
            return list((await s.scalars(select(BrandLookalikeRow.name).where(
                BrandLookalikeRow.watch_id == watch_id, BrandLookalikeRow.takedown_status.in_(OPEN_TAKEDOWN)))).all())  # fmt: skip

    async def put_takedown(
        self, watch_id: str, workspace_id: str | None, name: str, changes: dict[str, Any], event: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Create or change one lookalike's takedown record (merging ``changes``) and add ``event`` to its history."""
        async with self.db.session() as s, s.begin():
            criteria = [BrandLookalikeRow.watch_id == watch_id, BrandLookalikeRow.name == name]
            if workspace_id is not None:
                criteria.append(BrandLookalikeRow.workspace_id == workspace_id)
            row = await s.scalar(select(BrandLookalikeRow).where(*criteria))
            if row is None:
                return None
            record = {**(row.takedown or {"history": []}), **changes}
            record["history"] = [*record.get("history", []), {"at": _now().isoformat(), **event}][-50:]
            row.takedown, row.takedown_status = record, record.get("status")
            return record

    async def first_seen(
        self, workspace_id: str, *, triage: bool = True, takedowns: bool = True
    ) -> list[tuple[dict[str, Any], dict[str, str], dict[str, Any]]]:
        """Every watch of the workspace with its lookalikes: (watch with ``triage`` and ``takedowns`` by name,
        and ``details``; first seen by name; details by name). Used by campaigns, TAXII and the metrics.

        Only what is asked for is decrypted: ``triage`` (addresses, pages) for campaigns, ``takedowns`` for
        the metrics; the rest comes from plain columns, so TAXII and the metrics stay fast at thousands of rows."""
        L = BrandLookalikeRow
        columns = [
            L.watch_id,
            L.name,
            L.first_seen_at,
            L.severity,
            L.verdict,
            L.technique,
            L.display,
            L.takedown_status,
            L.detail,
        ]
        async with self.db.session() as s:
            watches = await self._watches(s, BrandWatchRow.workspace_id == workspace_id)
            rows = (await s.execute(select(*columns, L.infra if triage else L.id, L.takedown if takedowns else L.id)
                                    .where(L.workspace_id == workspace_id).order_by(L.first_seen_at.desc()))).all()  # fmt: skip
        by_watch: dict[str, list[Any]] = {}
        for row in rows:
            by_watch.setdefault(str(row[0]), []).append(row)
        out = []
        for watch in watches:
            mine = by_watch.get(watch.id, [])
            details = {r[1]: {"technique": r[5], "display": r[6] or r[1], "detail": r[8], "severity": r[3], "verdict": r[4]}
                       for r in mine}  # fmt: skip
            view = _view(watch, {"known": len(mine)}, full=True)
            # Verdict and severity are plain columns; with ``triage`` each also carries its infrastructure.
            view["triage"] = {
                r[1]: {"verdict": r[4], "severity": r[3], "label": VERDICT_LABELS.get(r[4], r[4]),
                       **((r[9] or {}) if triage else {})}
                for r in mine if r[4]
            }  # fmt: skip
            view["takedowns"] = (
                {r[1]: r[10] for r in mine if takedowns and r[7] and r[10]}
                if takedowns
                else {r[1]: {"status": r[7]} for r in mine if r[7]}
            )
            view["details"] = details
            out.append((view, {r[1]: _iso(r[2]) or "" for r in mine}, details))
        return out

    async def record(
        self, watch_id: str, *, status: str, sources: dict[str, Any], message: str,
        new: list[dict[str, Any]] | None = None, cursor: int | None = None, alerted: bool = False,
        retry_in: timedelta | None = None, triage: dict[str, dict[str, Any]] | None = None,
        visual_refs: list[dict[str, Any]] | None = None,
    ) -> None:  # fmt: skip
        """Record a run: the lookalikes found for the first time, the triage of those checked, and the state."""
        now = _now()
        async with self.db.session() as s, s.begin():
            row = await s.get(BrandWatchRow, watch_id)
            if row is None:
                return
            triage = triage or {}
            for finding in new or []:
                verdict = triage.get(finding["name"]) or {}
                s.add(BrandLookalikeRow(
                    id=f"bl_{secrets.token_hex(8)}", watch_id=watch_id, workspace_id=row.workspace_id,
                    name=finding["name"], first_seen_at=now, checked_at=_parse(verdict.get("checked_at")),
                    severity=str(verdict.get("severity") or finding.get("severity") or "medium"),
                    verdict=str(verdict.get("verdict") or finding.get("verdict") or ""),
                    technique=str(finding.get("technique") or "")[:16],
                    display=str(finding.get("display") or finding["name"])[:253],
                    detail=str(finding.get("detail") or "")[:160], finding=finding, triage=verdict or None,
                    infra=infra_of(verdict),
                ))  # fmt: skip
            await s.flush()
            fresh = {f["name"] for f in new or []}
            stale = [name for name in triage if name not in fresh]
            for i in range(0, len(stale), 500):
                rows = (await s.scalars(select(BrandLookalikeRow).where(
                    BrandLookalikeRow.watch_id == watch_id, BrandLookalikeRow.name.in_(stale[i:i + 500])))).all()  # fmt: skip
                for item in rows:
                    verdict = triage[item.name]
                    item.triage, item.checked_at = verdict, _parse(verdict.get("checked_at")) or now
                    item.infra = infra_of(verdict)
                    item.severity, item.verdict = (
                        str(verdict.get("severity") or item.severity),
                        str(verdict.get("verdict") or ""),
                    )
            known = int(await s.scalar(select(func.count()).where(BrandLookalikeRow.watch_id == watch_id)) or 0)
            if known > MAX_KNOWN:  # forget the oldest, except those with a takedown
                oldest = (await s.scalars(select(BrandLookalikeRow.id).where(
                    BrandLookalikeRow.watch_id == watch_id, BrandLookalikeRow.takedown_status.is_(None))
                    .order_by(BrandLookalikeRow.first_seen_at).limit(known - MAX_KNOWN))).all()  # fmt: skip
                await s.execute(delete(BrandLookalikeRow).where(BrandLookalikeRow.id.in_(oldest)))
            data = dict(row.data or {})
            if cursor is not None:
                data["cursor"] = cursor
            if status in ("ok", "partial"):
                data["baselined"] = True  # the first run that reached a source records what exists today
            data["sources"], data["last_message"] = sources, message[:300]
            if visual_refs is not None:
                data["visual_refs"] = visual_refs
            row.data = data
            row.last_run_at, row.last_status = now, status
            if alerted:
                row.alerts_raised = (row.alerts_raised or 0) + 1
            if retry_in is not None:  # every source failed: try again soon rather than in a day
                row.next_run_at = min(_utc(row.next_run_at) or now, now + retry_in)
