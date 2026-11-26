"""Per-workspace quotas: one team cannot exhaust a shared platform (Phase 100).

A platform serving several teams is only as reliable as its busiest or most careless team, or a
stolen key used in one of them. Each workspace can be held to:

* **scans per day** (every scan: by hand, scheduled monitors, playbooks), counted over the last 24 hours;
* **evidence storage** in megabytes (captures and uploads);
* **watches** (brand, fingerprint and known-details person watches together);
* **API keys** (active ones).

Defaults come from the server's settings (``ARGUS_QUOTA_*``, 0 = no limit), and a platform
administrator can set a workspace's own limits. A refused action gets ``403`` with ``"quota"`` naming
the limit (``429`` with ``Retry-After`` for scans per day). Usage and limits are shown to everyone in
the workspace (``GET /api/quota``); at 80% Settings shows a warning.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, or_, select

from argus.storage.db import (
    ApiKeyRow,
    BrandWatchRow,
    Database,
    EvidenceCaptureRow,
    EvidenceFileRow,
    FingerprintWatchRow,
    InvestigationRow,
    SubjectRow,
    WorkspaceQuotaRow,
)

RESOURCES = {
    "scans_per_day": "scans in the last 24 hours",
    "evidence_mb": "MB of evidence",
    "watches": "brand, fingerprint and person watches",
    "api_keys": "active API keys",
}
WARN_AT = 0.8
MB = 1024 * 1024


class QuotaExceeded(Exception):
    def __init__(self, resource: str, limit: int, used: float, retry_after: int | None = None):
        self.resource, self.limit, self.used, self.retry_after = resource, limit, used, retry_after
        super().__init__(f"This workspace has reached its limit of {limit} {RESOURCES[resource]} "
                         f"({used:g} used). A platform administrator can raise it.")  # fmt: skip


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Quotas:
    def __init__(self, db: Database, settings: Any):
        self.db = db
        self.settings = settings

    def defaults(self) -> dict[str, int]:
        return {r: int(getattr(self.settings, f"quota_{r}", 0) or 0) for r in RESOURCES}

    async def limits(self, workspace_id: str) -> dict[str, int]:
        async with self.db.session() as s:
            row = await s.get(WorkspaceQuotaRow, workspace_id)
        limits = self.defaults()
        for resource in RESOURCES:
            own = getattr(row, resource, None) if row else None
            if own is not None:
                limits[resource] = int(own)
        return limits

    async def set_limits(self, workspace_id: str, changes: dict[str, int | None], by: str) -> dict[str, Any]:
        """A workspace's own limits (None: back to the server default; 0: no limit)."""
        async with self.db.session() as s, s.begin():
            row = await s.get(WorkspaceQuotaRow, workspace_id)
            if row is None:
                row = WorkspaceQuotaRow(workspace_id=workspace_id, updated_at=_now(), updated_by=by)
                s.add(row)
            for resource, value in changes.items():
                if resource in RESOURCES:
                    setattr(row, resource, value)
            row.updated_at, row.updated_by = _now(), by
        return await self.usage(workspace_id)

    async def used(self, workspace_id: str, resource: str) -> float:
        async with self.db.session() as s:
            if resource == "scans_per_day":
                since = _now() - timedelta(days=1)
                return float(await s.scalar(select(func.count()).select_from(InvestigationRow).where(
                    InvestigationRow.workspace_id == workspace_id, InvestigationRow.created_at > since)) or 0)  # fmt: skip
            if resource == "evidence_mb":
                total = await s.scalar(select(func.coalesce(func.sum(EvidenceFileRow.size), 0))
                                       .join(EvidenceCaptureRow, EvidenceCaptureRow.id == EvidenceFileRow.capture_id)
                                       .where(EvidenceCaptureRow.workspace_id == workspace_id))  # fmt: skip
                return round(float(total or 0) / MB, 2)
            if resource == "watches":
                brand = await s.scalar(select(func.count()).select_from(BrandWatchRow)
                                       .where(BrandWatchRow.workspace_id == workspace_id))  # fmt: skip
                fingerprint = await s.scalar(select(func.count()).select_from(FingerprintWatchRow)
                                             .where(FingerprintWatchRow.workspace_id == workspace_id))  # fmt: skip
                people = await s.scalar(select(func.count()).select_from(SubjectRow)
                                        .where(SubjectRow.workspace_id == workspace_id, SubjectRow.watch.is_(True)))  # fmt: skip
                return float((brand or 0) + (fingerprint or 0) + (people or 0))
            now = _now()
            return float(await s.scalar(select(func.count()).select_from(ApiKeyRow).where(
                ApiKeyRow.workspace_id == workspace_id, ApiKeyRow.revoked_at.is_(None),
                or_(ApiKeyRow.expires_at.is_(None), ApiKeyRow.expires_at > now))) or 0)  # fmt: skip

    async def check(self, workspace_id: str, resource: str, adding: float = 1) -> None:
        """Raise :class:`QuotaExceeded` if ``adding`` more would go over the workspace's limit."""
        limit = (await self.limits(workspace_id))[resource]
        if not limit:
            return
        used = await self.used(workspace_id, resource)
        if used + adding > limit:
            retry = None
            if resource == "scans_per_day":
                retry = await self._next_scan_slot(workspace_id)
            raise QuotaExceeded(resource, limit, used, retry)

    async def _next_scan_slot(self, workspace_id: str) -> int:
        """Seconds until the oldest scan of the last 24 hours stops counting."""
        since = _now() - timedelta(days=1)
        async with self.db.session() as s:
            oldest = await s.scalar(select(func.min(InvestigationRow.created_at)).where(
                InvestigationRow.workspace_id == workspace_id, InvestigationRow.created_at > since))  # fmt: skip
        if oldest is None:
            return 60
        oldest = oldest if oldest.tzinfo else oldest.replace(tzinfo=timezone.utc)
        return max(60, int((oldest + timedelta(days=1) - _now()).total_seconds()) + 1)

    async def usage(self, workspace_id: str) -> dict[str, Any]:
        limits = await self.limits(workspace_id)
        out = {}
        for resource, label in RESOURCES.items():
            used = await self.used(workspace_id, resource)
            limit = limits[resource]
            share = (used / limit) if limit else None
            out[resource] = {"label": label, "used": used, "limit": limit or None,
                             "share": round(share, 3) if share is not None else None,
                             "warning": bool(share is not None and share >= WARN_AT)}  # fmt: skip
        return {"workspace_id": workspace_id, "resources": out, "defaults": self.defaults()}
