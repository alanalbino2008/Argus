"""Users, browser sessions and in-flight OIDC logins."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, cast

from sqlalchemy import delete, select
from sqlalchemy.engine import CursorResult

from argus.storage.db import Database, OidcLoginRow, SessionRow, UserRow


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value: datetime | None) -> str | None:
    return _aware(value).isoformat() if value else None


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _user(row: UserRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "issuer": row.issuer,
        "subject": row.subject,
        "email": row.email,
        "name": row.name,
        "role": row.role,
        "disabled": bool(row.disabled),
        "created_at": _iso(row.created_at),
        "last_login_at": _iso(row.last_login_at),
    }


class UserRepository:
    def __init__(self, db: Database):
        self.db = db

    # ------------------------------------------------------------------ users
    async def upsert_from_login(
        self, *, issuer: str, subject: str, email: str | None, name: str | None, role: str, role_from_idp: bool
    ) -> dict[str, Any]:
        """Create the user on first login; refresh profile (and role, if the IdP owns roles) after that."""
        now = _now()
        async with self.db.session() as s, s.begin():
            row = (
                await s.execute(select(UserRow).where(UserRow.issuer == issuer, UserRow.subject == subject))
            ).scalar_one_or_none()
            if row is None:
                row = UserRow(
                    id=f"usr_{secrets.token_hex(8)}", issuer=issuer, subject=subject, email=email, name=name,
                    role=role, disabled=False, created_at=now, last_login_at=now,
                )  # fmt: skip
                s.add(row)
            else:
                row.email, row.name, row.last_login_at = email, name, now
                if role_from_idp:
                    row.role = role
            await s.flush()
            return _user(row)

    async def get(self, user_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.get(UserRow, user_id)
        return _user(row) if row else None

    async def list_users(self) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (await s.execute(select(UserRow).order_by(UserRow.created_at))).scalars().all()
        return [_user(r) for r in rows]

    async def update(self, user_id: str, *, role: str | None = None, disabled: bool | None = None) -> dict | None:
        async with self.db.session() as s, s.begin():
            row = await s.get(UserRow, user_id)
            if row is None:
                return None
            if role is not None:
                row.role = role
            if disabled is not None:
                row.disabled = disabled
                if disabled:  # signing someone out everywhere is the point of disabling them
                    await s.execute(delete(SessionRow).where(SessionRow.user_id == user_id))
            await s.flush()
            return _user(row)

    # ------------------------------------------------------------------ sessions
    async def create_session(self, user_id: str, ttl: timedelta, ip: str | None, user_agent: str | None) -> str:
        token = secrets.token_urlsafe(32)
        now = _now()
        async with self.db.session() as s, s.begin():
            await s.execute(delete(SessionRow).where(SessionRow.expires_at < now))
            s.add(
                SessionRow(
                    token_hash=_digest(token), user_id=user_id, created_at=now, expires_at=now + ttl,
                    last_seen_at=now, ip=ip, user_agent=(user_agent or "")[:256] or None,
                )
            )  # fmt: skip
        return token

    async def resolve_session(self, token: str) -> dict[str, Any] | None:
        """The active, enabled user behind a session cookie, or None."""
        now = _now()
        async with self.db.session() as s, s.begin():
            found = (
                await s.execute(
                    select(SessionRow, UserRow)
                    .join(UserRow, UserRow.id == SessionRow.user_id)
                    .where(SessionRow.token_hash == _digest(token))
                )
            ).first()
            if found is None:
                return None
            session, user = found
            if _aware(session.expires_at) <= now or user.disabled:
                return None
            if now - _aware(session.last_seen_at) > timedelta(minutes=5):  # cheap "last active", not every request
                session.last_seen_at = now
            return _user(user)

    async def delete_session(self, token: str) -> bool:
        async with self.db.session() as s, s.begin():
            result = await s.execute(delete(SessionRow).where(SessionRow.token_hash == _digest(token)))
        return (cast("CursorResult[Any]", result).rowcount or 0) > 0

    async def count_sessions(self, user_id: str) -> int:
        async with self.db.session() as s:
            rows = (await s.execute(select(SessionRow.token_hash).where(SessionRow.user_id == user_id))).all()
        return len(rows)

    # ------------------------------------------------------------------ in-flight OIDC logins
    async def start_login(self, state: str, nonce: str, code_verifier: str, return_to: str, ttl: timedelta) -> None:
        now = _now()
        async with self.db.session() as s, s.begin():
            await s.execute(delete(OidcLoginRow).where(OidcLoginRow.expires_at < now))
            s.add(
                OidcLoginRow(
                    state_hash=_digest(state), nonce=nonce, code_verifier=code_verifier, return_to=return_to,
                    expires_at=now + ttl,
                )
            )  # fmt: skip

    async def finish_login(self, state: str) -> dict[str, str] | None:
        """Atomically consume a login's state: a callback can only be completed once."""
        async with self.db.session() as s, s.begin():
            row = (
                await s.execute(
                    delete(OidcLoginRow)
                    .where(OidcLoginRow.state_hash == _digest(state))
                    .returning(
                        OidcLoginRow.nonce, OidcLoginRow.code_verifier, OidcLoginRow.return_to, OidcLoginRow.expires_at
                    )
                )
            ).first()
        if row is None or _aware(row.expires_at) <= _now():
            return None
        return {"nonce": row.nonce, "code_verifier": row.code_verifier, "return_to": row.return_to}


__all__ = ["UserRepository"]
