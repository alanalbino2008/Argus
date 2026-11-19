"""The server's one owner, and owner console sessions (stored only as hashes)."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

from argus.storage.db import Database, OwnerRow, OwnerSessionRow

OWNER_ID = "owner"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    return value if value is None or value.tzinfo else value.replace(tzinfo=timezone.utc)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _owner(row: OwnerRow) -> dict[str, Any]:
    return {"email": row.email, "password_hash": row.password_hash, "totp_sealed": row.totp_sealed,
            "totp_last_counter": row.totp_last_counter, "recovery_left": len(row.recovery_hashes or []),
            "recovery_hashes": list(row.recovery_hashes or []), "failed": row.failed,
            "locked_until": _aware(row.locked_until), "created_at": _aware(row.created_at),
            "last_login_at": _aware(row.last_login_at)}  # fmt: skip


def _session(row: OwnerSessionRow) -> dict[str, Any]:
    return {"id": row.token_hash[:12], "stage": row.stage, "created_at": _aware(row.created_at),
            "expires_at": _aware(row.expires_at), "last_seen_at": _aware(row.last_seen_at),
            "confirmed_at": _aware(row.confirmed_at), "ip": row.ip, "user_agent": row.user_agent}  # fmt: skip


class OwnerRepository:
    def __init__(self, db: Database):
        self.db = db

    # ------------------------------------------------------------------ the owner
    async def get(self) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.get(OwnerRow, OWNER_ID)
        return _owner(row) if row else None

    async def create(self, *, email: str, password_hash: str, totp_sealed: str, recovery_hashes: list[str]) -> bool:
        """Create the owner; False if there already is one (there can only ever be one)."""
        try:
            async with self.db.session() as s, s.begin():
                if await s.get(OwnerRow, OWNER_ID) is not None:
                    return False
                s.add(OwnerRow(id=OWNER_ID, email=email.lower(), password_hash=password_hash, totp_sealed=totp_sealed,
                               totp_last_counter=-1, recovery_hashes=recovery_hashes, failed=0, created_at=_now()))  # fmt: skip
        except IntegrityError:
            return False
        return True

    async def update(self, **changes: Any) -> None:
        async with self.db.session() as s, s.begin():
            row = await s.get(OwnerRow, OWNER_ID, with_for_update=True)
            if row is not None:
                for key, value in changes.items():
                    setattr(row, key, value)

    async def failed(self, lock_after: int, lock_for: timedelta) -> bool:
        """Count a failed attempt; True if the console is now locked."""
        async with self.db.session() as s, s.begin():
            row = await s.get(OwnerRow, OWNER_ID, with_for_update=True)
            if row is None:
                return False
            row.failed += 1
            if row.failed >= lock_after:
                row.failed, row.locked_until = 0, _now() + lock_for
                return True
        return False

    async def use_counter(self, counter: int) -> bool:
        """Mark an authenticator time-step as used; False if it (or a later one) was used already."""
        async with self.db.session() as s, s.begin():
            row = await s.get(OwnerRow, OWNER_ID, with_for_update=True)
            if row is None or counter <= row.totp_last_counter:
                return False
            row.totp_last_counter = counter
        return True

    async def use_recovery(self, code_hash: str) -> bool:
        async with self.db.session() as s, s.begin():
            row = await s.get(OwnerRow, OWNER_ID, with_for_update=True)
            hashes = list(row.recovery_hashes or []) if row else []
            if row is None or code_hash not in hashes:
                return False
            hashes.remove(code_hash)
            row.recovery_hashes = hashes
        return True

    # ------------------------------------------------------------------ sessions
    async def new_session(self, stage: str, ttl: timedelta, ip: str, user_agent: str) -> str:
        token, now = secrets.token_urlsafe(32), _now()
        async with self.db.session() as s, s.begin():
            s.add(OwnerSessionRow(token_hash=token_hash(token), stage=stage, created_at=now, expires_at=now + ttl,
                                  last_seen_at=now, confirmed_at=now if stage == "full" else None, ip=ip[:64],
                                  user_agent=user_agent[:255]))  # fmt: skip
        return token

    async def session(self, token: str, idle: timedelta | None = None) -> dict[str, Any] | None:
        """A live session (not expired, not idle too long); it is kept alive by this call."""
        now = _now()
        async with self.db.session() as s, s.begin():
            row = await s.get(OwnerSessionRow, token_hash(token))
            if row is None:
                return None
            expired = (_aware(row.expires_at) or now) <= now
            idled = idle is not None and (_aware(row.last_seen_at) or now) + idle <= now
            if expired or idled:
                await s.delete(row)
                return None
            row.last_seen_at = now
            return _session(row)

    async def promote(self, token: str, ttl: timedelta) -> str | None:
        """A password-only session becomes a full one after the code: a fresh token (no fixation)."""
        now = _now()
        async with self.db.session() as s, s.begin():
            row = await s.get(OwnerSessionRow, token_hash(token))
            if row is None or row.stage != "code" or (_aware(row.expires_at) or now) <= now:
                return None
            ip, agent = row.ip, row.user_agent
            await s.delete(row)
        return await self.new_session("full", ttl, ip, agent)

    async def confirm(self, token: str) -> None:
        """A fresh authenticator code was given (for sensitive changes)."""
        async with self.db.session() as s, s.begin():
            row = await s.get(OwnerSessionRow, token_hash(token))
            if row is not None:
                row.confirmed_at = _now()

    async def end(self, token: str) -> None:
        async with self.db.session() as s, s.begin():
            await s.execute(delete(OwnerSessionRow).where(OwnerSessionRow.token_hash == token_hash(token)))

    async def sessions(self) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (await s.scalars(select(OwnerSessionRow).where(OwnerSessionRow.stage == "full")
                                    .order_by(OwnerSessionRow.last_seen_at.desc()))).all()  # fmt: skip
        now = _now()
        return [_session(r) for r in rows if (_aware(r.expires_at) or now) > now]

    async def end_all(self, except_token: str | None = None) -> int:
        keep = token_hash(except_token) if except_token else ""
        async with self.db.session() as s, s.begin():
            rows = (await s.scalars(select(OwnerSessionRow).where(OwnerSessionRow.token_hash != keep))).all()
            for row in rows:
                await s.delete(row)
        return len(rows)

    async def end_one(self, short_id: str) -> bool:
        async with self.db.session() as s, s.begin():
            rows = (await s.scalars(select(OwnerSessionRow))).all()
            match = [r for r in rows if r.token_hash.startswith(short_id) and len(short_id) >= 12]
            for row in match:
                await s.delete(row)
        return bool(match)
