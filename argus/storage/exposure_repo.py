"""Exposure watches and findings.

Findings are identified by the SHA-256 of a stable key (account + breach, group + victim + date...),
unique per workspace, so a check that sees the same thing again only refreshes ``last_seen_at``.
New findings and the alert announcing them are written in **one transaction**, together with the
alert's notifications (the outbox), so an alert is never lost and never sent for findings that
were not saved.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, cast

from sqlalchemy import delete, func, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError

from argus.intel.exposure import Finding, mask_email
from argus.storage.db import AlertRow, Database, ExposureFindingRow, ExposureWatchRow
from argus.storage.notification_repo import enqueue_alert

STATUSES = ("open", "resolved", "accepted")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value: datetime | None) -> str | None:
    moment = _utc(value)
    return moment.isoformat() if moment else None


def key_hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _watch(row: ExposureWatchRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "workspace_id": row.workspace_id,
        "scope": row.scope,
        "domain": row.domain or None,
        "organisation": row.organisation,
        "basis": row.basis,
        "enabled": bool(row.enabled),
        "demo": bool(row.demo),
        "interval_hours": row.interval_hours,
        "next_check_at": _iso(row.next_check_at),
        "last_checked_at": _iso(row.last_checked_at),
        "checks": row.checks or 0,
        "last_status": row.last_status,
        "last_message": row.last_message,
        "sources": row.sources or {},
        "created_at": _iso(row.created_at),
        "created_by": row.created_by,
    }


def _finding(row: ExposureFindingRow, *, reveal: bool = False) -> dict[str, Any]:
    return {
        "id": row.id,
        "watch_id": row.watch_id,
        "subject": row.subject,
        "subject_name": row.subject_name or row.subject,
        "supplier_id": row.supplier_id,
        "kind": row.kind,
        "severity": row.severity,
        "title": row.title,
        "account": row.account if reveal else None,
        "account_masked": mask_email(row.account) if row.account else None,
        "occurred_at": row.occurred_at,
        "details": row.details or {},
        "status": row.status,
        "first_seen_at": _iso(row.first_seen_at),
        "last_seen_at": _iso(row.last_seen_at),
        "resolved_at": _iso(row.resolved_at),
        "resolved_by": row.resolved_by,
        "note": row.note,
    }


class ExposureRepository:
    def __init__(self, db: Database):
        self.db = db

    # ------------------------------------------------------------------ watches
    async def create_watch(
        self,
        *,
        workspace_id: str,
        scope: str,
        by: str,
        basis: str,
        domain: str = "",
        organisation: str = "",
        interval_hours: int = 24,
        enabled: bool = True,
        demo: bool = False,
        next_check_at: datetime | None = None,
    ) -> dict[str, Any] | None:
        """The new watch, or None if this domain (or the supplier sweep) is already watched."""
        moment = _now()
        row = ExposureWatchRow(
            id=f"exw_{secrets.token_hex(8)}", workspace_id=workspace_id, scope=scope, domain=domain,
            organisation=organisation, basis=basis, enabled=enabled, demo=demo, interval_hours=interval_hours,
            next_check_at=next_check_at or moment, checks=0, created_at=moment, created_by=by,
        )  # fmt: skip
        try:
            async with self.db.session() as s, s.begin():
                s.add(row)
        except IntegrityError:
            return None
        return _watch(row)

    async def ensure_supplier_watch(self, *, workspace_id: str, by: str) -> dict[str, Any]:
        """The workspace's supplier sweep (created the first time a supplier is added)."""
        existing = await self.supplier_watch(workspace_id=workspace_id)
        if existing:
            return existing
        created = await self.create_watch(
            workspace_id=workspace_id, scope="suppliers", by=by,
            basis="Suppliers in the register: public breach and ransomware leak-site reports",
        )  # fmt: skip
        return created or cast("dict[str, Any]", await self.supplier_watch(workspace_id=workspace_id))

    async def supplier_watch(self, *, workspace_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.scalar(
                select(ExposureWatchRow).where(
                    ExposureWatchRow.workspace_id == workspace_id, ExposureWatchRow.scope == "suppliers"
                )
            )
        return _watch(row) if row else None

    async def list_watches(self, *, workspace_id: str) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (
                await s.scalars(
                    select(ExposureWatchRow)
                    .where(ExposureWatchRow.workspace_id == workspace_id)
                    .order_by(ExposureWatchRow.scope, ExposureWatchRow.domain)
                )
            ).all()
        return [_watch(r) for r in rows]

    async def get_watch(self, watch_id: str, *, workspace_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.get(ExposureWatchRow, watch_id)
        return _watch(row) if row and row.workspace_id == workspace_id else None

    async def update_watch(self, watch_id: str, *, workspace_id: str, **values: Any) -> dict[str, Any] | None:
        async with self.db.session() as s, s.begin():
            row = await s.get(ExposureWatchRow, watch_id)
            if row is None or row.workspace_id != workspace_id:
                return None
            for key, value in values.items():
                setattr(row, key, value)
            return _watch(row)

    async def delete_watch(self, watch_id: str, *, workspace_id: str) -> bool:
        async with self.db.session() as s, s.begin():
            row = await s.get(ExposureWatchRow, watch_id)
            if row is None or row.workspace_id != workspace_id:
                return False
            await s.execute(delete(ExposureFindingRow).where(ExposureFindingRow.watch_id == watch_id))
            await s.delete(row)
        return True

    # ------------------------------------------------------------------ scheduling
    async def due(self, now: datetime | None = None) -> list[dict[str, Any]]:
        moment = now or _now()
        async with self.db.session() as s:
            rows = (
                await s.scalars(
                    select(ExposureWatchRow).where(ExposureWatchRow.enabled.is_(True), ExposureWatchRow.demo.is_(False))
                )
            ).all()
        # Compare in Python: SQLite drops tzinfo.
        return [_watch(r) for r in rows if (_utc(r.next_check_at) or moment) <= moment]

    async def claim(self, watch_id: str, now: datetime | None = None) -> bool:
        """Atomically take a due watch: only one replica's UPDATE still sees it due."""
        moment = now or _now()
        async with self.db.session() as s, s.begin():
            row = await s.get(ExposureWatchRow, watch_id)
            if row is None:
                return False
            result = await s.execute(
                update(ExposureWatchRow)
                .where(
                    ExposureWatchRow.id == watch_id,
                    ExposureWatchRow.next_check_at <= moment,
                    ExposureWatchRow.enabled.is_(True),
                )
                .values(next_check_at=moment + timedelta(hours=row.interval_hours))
                .execution_options(synchronize_session=False)
            )
        return (cast("CursorResult[Any]", result).rowcount or 0) == 1

    # ------------------------------------------------------------------ findings
    async def record_check(
        self,
        watch: dict[str, Any],
        findings: list[Finding],
        *,
        status: str,
        message: str,
        sources: dict[str, Any],
        supplier_ids: dict[str, str] | None = None,
        subject_names: dict[str, str] | None = None,
        alert: Any = None,
        public_url: str | None = None,
    ) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
        """Save what a check found; returns (new findings, the alert raised for them, if any).

        ``alert(new_findings, baseline) -> dict | None`` builds the alert from the new findings;
        it is written, with its notifications, in the same transaction as the findings.
        """
        moment = _now()
        supplier_ids, subject_names = supplier_ids or {}, subject_names or {}
        by_hash = {key_hash(f.key): f for f in findings}
        new_rows: list[ExposureFindingRow] = []
        raised: dict[str, Any] | None = None
        async with self.db.session() as s, s.begin():
            row = await s.get(ExposureWatchRow, watch["id"])
            if row is None:
                return [], None
            baseline = (row.checks or 0) == 0
            existing = {}
            hashes = list(by_hash)
            for start in range(0, len(hashes), 500):
                chunk = hashes[start : start + 500]
                existing.update({
                    r.key_hash: r for r in await s.scalars(select(ExposureFindingRow).where(
                        ExposureFindingRow.workspace_id == row.workspace_id, ExposureFindingRow.key_hash.in_(chunk)))
                })  # fmt: skip
            for digest, f in by_hash.items():
                current = existing.get(digest)
                if current is not None:
                    current.last_seen_at, current.severity, current.details = moment, f.severity, f.details
                    continue
                new_rows.append(ExposureFindingRow(
                    id=f"exf_{secrets.token_hex(8)}", workspace_id=row.workspace_id, watch_id=row.id,
                    key_hash=digest, subject=f.subject, subject_name=subject_names.get(f.subject, ""),
                    supplier_id=supplier_ids.get(f.subject), kind=f.kind, severity=f.severity, title=f.title[:512],
                    account=f.account, occurred_at=(f.occurred_at or None) and str(f.occurred_at)[:32],
                    details=f.details, status="open", first_seen_at=moment, last_seen_at=moment, note="",
                ))  # fmt: skip
            s.add_all(new_rows)
            row.checks = (row.checks or 0) + (1 if status != "error" else 0)
            row.last_checked_at, row.last_status, row.last_message = moment, status, message[:512]
            row.sources = sources
            new = [_finding(r, reveal=True) for r in new_rows]
            if alert is not None and new:
                built = alert(new, baseline)
                if built is not None:
                    alert_row = AlertRow(
                        id=f"alert_{secrets.token_hex(6)}", workspace_id=row.workspace_id, monitor_id=None,
                        investigation_id="", previous_investigation_id="", target=built["target"],
                        severity=built["severity"], headline=built["headline"][:1024], summary=built["summary"],
                        created_at=moment,
                    )  # fmt: skip
                    s.add(alert_row)
                    alert_dict: dict[str, Any] = {
                        "id": alert_row.id, "workspace_id": row.workspace_id, "monitor_id": None,
                        "investigation_id": "", "previous_investigation_id": "", "target": alert_row.target,
                        "severity": alert_row.severity, "headline": alert_row.headline, "summary": alert_row.summary,
                        "created_at": _iso(moment),
                    }  # fmt: skip
                    alert_dict["notifications_queued"] = await enqueue_alert(s, alert_dict, public_url)
                    raised = alert_dict
        return [_finding(r) for r in new_rows], raised

    async def findings(
        self,
        *,
        workspace_id: str,
        status: str | None = None,
        kind: str | None = None,
        watch_id: str | None = None,
        reveal: bool = False,
        limit: int = 2000,
    ) -> list[dict[str, Any]]:
        stmt = select(ExposureFindingRow).where(ExposureFindingRow.workspace_id == workspace_id)
        if status:
            stmt = stmt.where(ExposureFindingRow.status == status)
        if kind:
            stmt = stmt.where(ExposureFindingRow.kind == kind)
        if watch_id:
            stmt = stmt.where(ExposureFindingRow.watch_id == watch_id)
        async with self.db.session() as s:
            rows = (await s.scalars(stmt.order_by(ExposureFindingRow.first_seen_at.desc()).limit(limit))).all()
        return [_finding(r, reveal=reveal) for r in rows]

    async def set_status(
        self, finding_ids: list[str], *, workspace_id: str, status: str, by: str, note: str = ""
    ) -> int:
        moment = _now()
        async with self.db.session() as s, s.begin():
            result = await s.execute(
                update(ExposureFindingRow)
                .where(ExposureFindingRow.workspace_id == workspace_id, ExposureFindingRow.id.in_(finding_ids))
                .values(
                    status=status,
                    resolved_at=None if status == "open" else moment,
                    resolved_by=None if status == "open" else by,
                    note=note[:500],
                )
                .execution_options(synchronize_session=False)
            )
        return cast("CursorResult[Any]", result).rowcount or 0

    async def open_by_subject(self, *, workspace_id: str) -> dict[str, dict[str, int]]:
        """``{domain: {kind: count}}`` of open findings (for the supplier register)."""
        async with self.db.session() as s:
            rows = (
                await s.execute(
                    select(ExposureFindingRow.subject, ExposureFindingRow.kind, func.count())
                    .where(ExposureFindingRow.workspace_id == workspace_id, ExposureFindingRow.status == "open")
                    .group_by(ExposureFindingRow.subject, ExposureFindingRow.kind)
                )
            ).all()
        out: dict[str, dict[str, int]] = {}
        for subject, kind, count in rows:
            out.setdefault(subject, {})[kind] = count
        return out

    async def purge(self, *, older_than_days: int) -> int:
        """Delete findings closed long ago (data minimisation: personal data is not kept forever)."""
        cutoff = _now() - timedelta(days=older_than_days)
        async with self.db.session() as s, s.begin():
            result = await s.execute(
                delete(ExposureFindingRow).where(
                    ExposureFindingRow.status != "open", ExposureFindingRow.resolved_at < cutoff
                )
            )
        return cast("CursorResult[Any]", result).rowcount or 0
