"""Persistence for API keys and the tamper-evident audit log."""

from __future__ import annotations

import asyncio
import builtins
import hashlib
import ipaddress
import json
import secrets
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from typing import Any, cast

from sqlalchemy import delete, func, select, text, update
from sqlalchemy.engine import CursorResult

from argus.observability import metrics
from argus.security.auth import Principal, Role, generate_api_key, hash_api_key, key_display_prefix
from argus.storage.db import ApiKeyRow, AuditEventRow, Database, WsTicketRow

# PostgreSQL advisory-lock key serialising audit-chain appends across every replica.
AUDIT_CHAIN_LOCK = 0x4152_4755_5341_5544  # "ARGUSAUD"

GENESIS_HASH = "0" * 64
LAST_USED_RESOLUTION = timedelta(seconds=60)
STALE_AFTER = timedelta(days=90)  # a key nobody used for this long is reported
MAX_NETWORKS = 20


def clean_networks(values: Iterable[str]) -> builtins.list[str]:
    """Validated, de-duplicated CIDRs (a bare address is one host). Raises ValueError on a bad entry."""
    out: builtins.list[str] = []
    for value in values:
        text = str(value).strip()
        if not text:
            continue
        network = str(ipaddress.ip_network(text, strict=False))
        if network not in out:
            out.append(network)
    if len(out) > MAX_NETWORKS:
        raise ValueError(f"At most {MAX_NETWORKS} networks per key")
    return out


def allowed_from(networks: builtins.list[str] | None, client_ip: str | None) -> bool:
    """Whether ``client_ip`` may use a key restricted to ``networks`` (no restriction: always)."""
    if not networks:
        return True
    try:
        address = ipaddress.ip_address((client_ip or "").strip())
    except ValueError:
        return False  # an unknown origin never satisfies a restriction
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    return any(address in ipaddress.ip_network(n, strict=False) for n in networks)


def _aware(value: datetime | None) -> datetime | None:
    return value if value is None or value.tzinfo else value.replace(tzinfo=timezone.utc)


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
        self,
        name: str,
        role: Role,
        created_by: str | None = None,
        plaintext: str | None = None,
        workspace_id: str | None = None,
        expires_at: datetime | None = None,
        allowed_networks: builtins.list[str] | None = None,
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
            workspace_id=workspace_id,
            expires_at=expires_at,
            allowed_networks=clean_networks(allowed_networks or []) or None,
        )
        async with self.db.session() as s, s.begin():
            s.add(row)
        return self._public(row), key

    async def authenticate(self, key: str, client_ip: str | None = None) -> Principal | None:
        return (await self.check(key, client_ip))[0]

    async def check(self, key: str, client_ip: str | None = None) -> tuple[Principal | None, str | None]:
        """The key's principal, or None and why: ``invalid`` (unknown or revoked), ``expired``, ``network``."""
        if not key:
            return None, "invalid"
        async with self.db.session() as s:
            row = (
                await s.execute(
                    select(ApiKeyRow).where(ApiKeyRow.key_hash == hash_api_key(key), ApiKeyRow.revoked_at.is_(None))
                )
            ).scalar_one_or_none()
            if row is None:
                return None, "invalid"
            expires = _aware(row.expires_at)
            if expires is not None and expires <= _now():
                return None, "expired"
            if not allowed_from(row.allowed_networks, client_ip):
                return None, "network"
            last = row.last_used_at
            if last is not None and last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            if last is None or _now() - last > LAST_USED_RESOLUTION:  # avoid a write per request
                await s.execute(update(ApiKeyRow).where(ApiKeyRow.id == row.id).values(last_used_at=_now()))
                await s.commit()
        return Principal(key_id=row.id, name=row.name, role=Role(row.role), workspace_id=row.workspace_id), None

    async def rotate(self, key_id: str, *, overlap: timedelta, by: str | None) -> tuple[dict[str, Any], str] | None:
        """A new key with the same name, role, workspace, networks and lifetime; the old one keeps working
        for ``overlap`` (so integrations can switch without downtime), then expires."""
        now = _now()
        async with self.db.session() as s, s.begin():
            old = await s.get(ApiKeyRow, key_id)
            if old is None or old.revoked_at is not None or old.replaced_by:
                return None
            old_expiry = _aware(old.expires_at)
            if old_expiry is not None and old_expiry <= now:
                return None
            lifetime = old_expiry - _aware(old.created_at) if old_expiry and old.created_at else None  # type: ignore[operator]
            key = generate_api_key()
            new = ApiKeyRow(
                id=f"key_{secrets.token_hex(6)}", name=old.name, prefix=key_display_prefix(key),
                key_hash=hash_api_key(key), role=old.role, created_at=now, created_by=by,
                workspace_id=old.workspace_id, expires_at=now + lifetime if lifetime else None,
                allowed_networks=old.allowed_networks,
            )  # fmt: skip
            s.add(new)
            end = now + overlap
            old.expires_at = min(old_expiry, end) if old_expiry else end
            old.replaced_by = new.id
        return self._public(new), key

    async def set_networks(self, key_id: str, networks: builtins.list[str]) -> None:
        async with self.db.session() as s, s.begin():
            await s.execute(update(ApiKeyRow).where(ApiKeyRow.id == key_id).values(allowed_networks=networks or None))

    async def expiring(self, within: timedelta) -> builtins.list[dict[str, Any]]:
        """Active keys that expire within ``within`` and have not been warned about yet."""
        now = _now()
        async with self.db.session() as s:
            rows = (await s.scalars(select(ApiKeyRow).where(
                ApiKeyRow.revoked_at.is_(None), ApiKeyRow.expires_at.is_not(None),
                ApiKeyRow.expiry_warned_at.is_(None), ApiKeyRow.replaced_by.is_(None)))).all()  # fmt: skip
        return [self._public(r) for r in rows if now < (_aware(r.expires_at) or now) <= now + within]

    async def mark_warned(self, key_id: str) -> bool:
        """Claim the expiry warning for a key (only one replica sends it)."""
        stmt = update(ApiKeyRow).where(ApiKeyRow.id == key_id, ApiKeyRow.expiry_warned_at.is_(None))
        async with self.db.session() as s, s.begin():
            result = await s.execute(stmt.values(expiry_warned_at=_now()).execution_options(synchronize_session=False))
        return (cast("CursorResult[Any]", result).rowcount or 0) > 0

    async def list(self, workspace_id: str | None = None) -> builtins.list[dict[str, Any]]:
        """Keys of one workspace, or every key (platform administrators) when ``workspace_id`` is None."""
        stmt = select(ApiKeyRow).order_by(ApiKeyRow.created_at)
        if workspace_id is not None:
            stmt = stmt.where(ApiKeyRow.workspace_id == workspace_id)
        async with self.db.session() as s:
            rows = (await s.execute(stmt)).scalars().all()
        return [self._public(r) for r in rows]

    async def get(self, key_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.get(ApiKeyRow, key_id)
        return self._public(row) if row else None

    async def revoke(self, key_id: str, workspace_id: str | None = None) -> bool:
        """Revoke a key; with ``workspace_id`` only a key of that workspace can be revoked."""
        stmt = update(ApiKeyRow).where(ApiKeyRow.id == key_id, ApiKeyRow.revoked_at.is_(None))
        if workspace_id is not None:
            stmt = stmt.where(ApiKeyRow.workspace_id == workspace_id)
        async with self.db.session() as s, s.begin():
            result = await s.execute(stmt.values(revoked_at=_now()))
        return (cast("CursorResult[Any]", result).rowcount or 0) > 0

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
            "workspace_id": row.workspace_id,
            **_policy(row),
        }


def _policy(row: ApiKeyRow) -> dict[str, Any]:
    """Expiry, networks, rotation and staleness, as the API shows them."""
    now = _now()
    expires = _aware(row.expires_at)
    used = _aware(row.last_used_at) or _aware(row.created_at)
    return {
        "expires_at": _iso(expires),
        "expired": bool(expires and expires <= now),
        "expires_in_days": round((expires - now).total_seconds() / 86400, 1) if expires and expires > now else None,
        "allowed_networks": row.allowed_networks or [],
        "replaced_by": row.replaced_by,
        "stale": row.revoked_at is None and bool(used and now - used > STALE_AFTER),
    }


class AuditLog:
    """Append-only audit trail where every entry includes the hash of the previous one.

    Editing or deleting any past row breaks every hash after it, so tampering is
    detectable with :meth:`verify` (the same idea as a blockchain or git history).
    Appends are serialised in-process (asyncio lock) and, on PostgreSQL, across every
    replica with a transaction-scoped advisory lock - so concurrent writers on different
    pods can never read the same previous hash and fork the chain. (SQLite allows a single
    writer anyway and is a single-node backend.)
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
        # workspace_id joins the hashed entry only when set: entries written before workspaces
        # existed keep verifying, newer ones protect their workspace from tampering too.
        scope = {"workspace_id": row.workspace_id} if row.workspace_id else {}
        return {
            **scope,
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
        workspace_id: str | None = None,
    ) -> None:
        entry = {
            **({"workspace_id": workspace_id} if workspace_id else {}),
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
            if self.db.dialect == "postgresql":
                await s.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": AUDIT_CHAIN_LOCK})
            prev = (
                await s.execute(select(AuditEventRow.hash).order_by(AuditEventRow.id.desc()).limit(1))
            ).scalar_one_or_none() or GENESIS_HASH
            s.add(AuditEventRow(**entry, prev_hash=prev, hash=self._digest(prev, entry)))
        metrics.AUDIT_EVENTS.labels(outcome).inc()

    async def list(
        self,
        limit: int = 100,
        action: str | None = None,
        actor_id: str | None = None,
        workspace_id: str | None = None,
    ) -> builtins.list[dict[str, Any]]:
        stmt = select(AuditEventRow).order_by(AuditEventRow.id.desc()).limit(limit)
        if workspace_id is not None:
            stmt = stmt.where(AuditEventRow.workspace_id == workspace_id)
        if action:
            stmt = stmt.where(AuditEventRow.action == action)
        if actor_id:
            stmt = stmt.where(AuditEventRow.actor_id == actor_id)
        async with self.db.session() as s:
            rows = (await s.execute(stmt)).scalars().all()
        return [{"id": r.id, **self._entry(r), "hash": r.hash} for r in rows]

    async def events(self, *, after_id: int = 0, since: datetime | None = None,
                     actions: Iterable[str] = (), limit: int = 500) -> builtins.list[dict[str, Any]]:  # fmt: skip
        """Entries in order, after an id and/or since a time, of the given actions (for alerts and summaries)."""
        stmt = select(AuditEventRow).where(AuditEventRow.id > after_id).order_by(AuditEventRow.id).limit(limit)
        wanted = list(actions)
        if wanted:
            stmt = stmt.where(AuditEventRow.action.in_(wanted))
        if since is not None:
            stmt = stmt.where(AuditEventRow.ts >= since.isoformat())
        async with self.db.session() as s:
            rows = (await s.execute(stmt)).scalars().all()
        return [{"id": r.id, **self._entry(r)} for r in rows]

    async def last_id(self) -> int:
        async with self.db.session() as s:
            return int((await s.execute(select(func.max(AuditEventRow.id)))).scalar_one_or_none() or 0)

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


class TicketStore:
    """Single-use, short-lived WebSocket tickets stored in the database.

    Browsers cannot attach an Authorization header to a WebSocket handshake, and putting
    the long-lived API key in the URL would leak it into proxy logs, so the page trades its
    key for a ticket valid for seconds. Keeping tickets in the database (hashed) means a
    ticket issued by one replica can be redeemed on another behind a load balancer.
    Redemption is an atomic DELETE ... RETURNING, so a ticket can never be used twice.
    """

    def __init__(self, db: Database, ttl: float):
        self.db = db
        self.ttl = ttl

    async def issue(self, principal: Principal, workspace_id: str | None = None) -> str:
        ticket = secrets.token_urlsafe(24)
        now = _now()
        async with self.db.session() as s, s.begin():
            await s.execute(delete(WsTicketRow).where(WsTicketRow.expires_at < now))
            s.add(
                WsTicketRow(
                    ticket_hash=hashlib.sha256(ticket.encode()).hexdigest(),
                    key_id=principal.key_id,
                    name=principal.name,
                    role=principal.role.value,
                    workspace_id=workspace_id,
                    expires_at=now + timedelta(seconds=self.ttl),
                )
            )
        return ticket

    async def redeem(self, ticket: str | None) -> Principal | None:
        found = await self.redeem_for_workspace(ticket)
        return found[0] if found else None

    async def redeem_for_workspace(self, ticket: str | None) -> tuple[Principal, str | None] | None:
        """Redeem a ticket: (who, which workspace it was issued for)."""
        if not ticket:
            return None
        digest = hashlib.sha256(ticket.encode()).hexdigest()
        async with self.db.session() as s, s.begin():
            row = (
                await s.execute(
                    delete(WsTicketRow)
                    .where(WsTicketRow.ticket_hash == digest)
                    .returning(
                        WsTicketRow.key_id,
                        WsTicketRow.name,
                        WsTicketRow.role,
                        WsTicketRow.expires_at,
                        WsTicketRow.workspace_id,
                    )
                )
            ).first()
        if row is None:
            return None
        expires = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=timezone.utc)
        if expires < _now():
            return None
        return Principal(key_id=row.key_id, name=row.name, role=Role(row.role)), row.workspace_id
