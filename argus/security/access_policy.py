"""Workspace network policy: where a workspace may be used from (Phase 93).

An organisation that only reaches Argus through its VPN or office network can say so. Every
request acting in the workspace (browser sessions and API keys alike) must then come from one of
its networks; Phase 89's per-key networks still apply on top, for keys. Platform administrators are
exempt, so a wrong policy can always be corrected.

A refused request is answered like a missing workspace (``404``), audited with the address, and
counted as ``argus_auth_failures_total{reason="workspace_network"}``. The policy is read through a
short cache (``CACHE_SECONDS``), so a change reaches every replica within half a minute.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from argus.storage.db import AccessPolicyRow, Database

CACHE_SECONDS = 30.0


class AccessPolicies:
    def __init__(self, db: Database):
        self.db = db
        self._cache: dict[str, tuple[float, list[str]]] = {}

    async def networks(self, workspace_id: str) -> list[str]:
        cached = self._cache.get(workspace_id)
        if cached and cached[0] > time.monotonic():
            return cached[1]
        async with self.db.session() as s:
            row = await s.get(AccessPolicyRow, workspace_id)
        networks = list(row.allowed_networks or []) if row else []
        self._cache[workspace_id] = (time.monotonic() + CACHE_SECONDS, networks)
        return networks

    async def get(self, workspace_id: str) -> dict[str, Any]:
        async with self.db.session() as s:
            row = await s.get(AccessPolicyRow, workspace_id)
        return {"allowed_networks": list(row.allowed_networks or []) if row else [],
                "updated_at": row.updated_at.isoformat() if row and row.updated_at else None,
                "updated_by": row.updated_by if row else None}  # fmt: skip

    async def set(self, workspace_id: str, networks: list[str], by: str) -> dict[str, Any]:
        async with self.db.session() as s, s.begin():
            row = await s.get(AccessPolicyRow, workspace_id)
            now = datetime.now(timezone.utc)
            if row is None:
                s.add(
                    AccessPolicyRow(workspace_id=workspace_id, allowed_networks=networks, updated_at=now, updated_by=by)
                )
            else:
                row.allowed_networks, row.updated_at, row.updated_by = networks, now, by
        self._cache.pop(workspace_id, None)
        return await self.get(workspace_id)
