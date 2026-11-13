"""Persistence for API keys and the tamper-evident audit log."""

from __future__ import annotations

import asyncio
import builtins
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select, update

from argus.security.auth import Principal, Role, generate_api_key, hash_api_key, key_display_prefix
from argus.storage.db import ApiKeyRow, AuditEventRow, Database

GENESIS_HASH = "0" * 64
LAST_USED_RESOLUTION = timedelta(seconds=60)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()


class ApiKeyRepository:
    def __init__(self, db: Database):
        self.db = db

    async def create(
        self, name: str, role: Role, created_by: str | None = None, plaintext: str | None = None
    ) -> tuple[dict[str, Any], str]:
        """Create a key. Returns (public record, plaintext key) - the plaintext is never stored."""
        key = plaintext or generate_api_key()
        row = ApiKeyRow(
            id=f"key_{secrets.token_hex(6)}",
            name=name,
            prefix=key_display_prefix(key),
            key_hash=hash_api_key(key),
            role=role.value,
            created_at=_now(),
            created_by=created_by,
        )
        async with self.db.session() as s, s.begin():
            s.add(row)
        return self._public(row), key

    async def authenticate(self, key: str) -> Principal | None:
        if not key:
            return None
        async with self.db.session() as s:
            row = (
                await s.execute(
                    select(ApiKeyRow).where(ApiKeyRow.key_hash == hash_api_key(key), ApiKeyRow.revoked_at.is_(None))
                )
            ).scalar_one_or_none()
            if row is None:
                return None
            last = row.last_used_at
            if last is not None and last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            if last is None or _now() - last > LAST_USED_RESOLUTION:  # avoid a write per request
                await s.execute(update(ApiKeyRow).where(ApiKeyRow.id == row.id).values(last_used_at=_now()))
                await s.commit()
        return Principal(key_id=row.id, name=row.name, role=Role(row.role))

    async def list(self) -> builtins.list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (await s.execute(select(ApiKeyRow).order_by(ApiKeyRow.created_at))).scalars().all()
        return [self._public(r) for r in rows]

    async def get(self, key_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.get(ApiKeyRow, key_id)
        return self._public(row) if row else None

    async def revoke(self, key_id: str) -> bool:
        async with self.db.session() as s, s.begin():
            result = await s.execute(
                update(ApiKeyRow)
                .where(ApiKeyRow.id == key_id, ApiKeyRow.revoked_at.is_(None))
                .values(revoked_at=_now())
            )
        return (result.rowcount or 0) > 0

    async def count_active(self, role: Role | None = None) -> int:
        stmt = select(func.count()).select_from(ApiKeyRow).where(ApiKeyRow.revoked_at.is_(None))
        if role:
            stmt = stmt.where(ApiKeyRow.role == role.value)
        async with self.db.session() as s:
            return int((await s.execute(stmt)).scalar_one())

    @staticmethod
    def _public(row: ApiKeyRow) -> dict[str, Any]:
        return {
            "id": row.id,
            "name": row.name,
            "prefix": row.prefix,
            "role": row.role,
            "created_at": _iso(row.created_at),
            "created_by": row.created_by,
            "last_used_at": _iso(row.last_used_at),
            "revoked": row.revoked_at is not None,
        }


class AuditLog:
    """Append-only audit trail where every entry includes the hash of the previous one.

    Editing or deleting any past row breaks every hash after it, so tampering is
    detectable with :meth:`verify` (the same idea as a blockchain or git history).
    Note: the chain is serialised with an in-process lock - run a single API process
    per database, or move the chain head into the database for multi-process deployments.
    """

    def __init__(self, db: Database):
        self.db = db
        self._lock = asyncio.Lock()

    @staticmethod
    def _digest(prev_hash: str, entry: dict[str, Any]) -> str:
        canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()

    @staticmethod
    def _entry(row: AuditEventRow) -> dict[str, Any]:
        return {
            "ts": row.ts,
            "actor_id": row.actor_id,
            "actor_name": row.actor_name,
            "action": row.action,
            "resource": row.resource,
            "outcome": row.outcome,
            "ip": row.ip,
            "details": row.details,
        }

    async def record(
        self,
        principal: Principal,
        action: str,
        resource: str | None = None,
        outcome: str = "success",
        ip: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        entry = {
            "ts": _now().isoformat(),
            "actor_id": principal.key_id,
            "actor_name": principal.name,
            "action": action,
            "resource": resource,
            "outcome": outcome,
            "ip": ip,
            "details": json.loads(json.dumps(details or {}, default=str)),
        }
        async with self._lock, self.db.session() as s, s.begin():
            prev = (
                await s.execute(select(AuditEventRow.hash).order_by(AuditEventRow.id.desc()).limit(1))
            ).scalar_one_or_none() or GENESIS_HASH
            s.add(AuditEventRow(**entry, prev_hash=prev, hash=self._digest(prev, entry)))

    async def list(
        self, limit: int = 100, action: str | None = None, actor_id: str | None = None
    ) -> builtins.list[dict[str, Any]]:
        stmt = select(AuditEventRow).order_by(AuditEventRow.id.desc()).limit(limit)
        if action:
            stmt = stmt.where(AuditEventRow.action == action)
        if actor_id:
            stmt = stmt.where(AuditEventRow.actor_id == actor_id)
        async with self.db.session() as s:
            rows = (await s.execute(stmt)).scalars().all()
        return [{"id": r.id, **self._entry(r), "hash": r.hash} for r in rows]

    async def verify(self) -> dict[str, Any]:
        """Recompute the whole chain; report the first entry that does not match."""
        prev = GENESIS_HASH
        checked = 0
        async with self.db.session() as s:
            result = await s.stream(select(AuditEventRow).order_by(AuditEventRow.id))
            async for row in result.scalars():
                if row.prev_hash != prev or row.hash != self._digest(prev, self._entry(row)):
                    return {"valid": False, "checked": checked, "first_invalid_id": row.id}
                prev = row.hash
                checked += 1
        return {"valid": True, "checked": checked, "first_invalid_id": None}
