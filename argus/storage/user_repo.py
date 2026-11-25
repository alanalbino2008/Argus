"""Users, browser sessions and in-flight OIDC logins."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, cast

from sqlalchemy import delete, func, select
from sqlalchemy.engine import CursorResult

from argus.storage.db import Database, OidcLoginRow, SessionRow, UserRow

SESSION_ID_LENGTH = 16  # the public id of a session: a prefix of its token's SHA-256, never the token


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
            if row is None and email:
                # Provisioned over SCIM and never signed in: this first sign-in is that person (Phase 94).
                # Only such records are linked by email, so no existing account can be taken over this way.
                row = (await s.execute(select(UserRow).where(
                    UserRow.issuer == "scim", UserRow.scim_managed.is_(True), UserRow.last_login_at.is_(None),
                    func.lower(UserRow.email) == email.lower()))).scalars().first()  # fmt: skip
                if row is not None:
                    row.issuer, row.subject = issuer, subject
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

    async def has_platform_admin(self) -> bool:
        async with self.db.session() as s:
            row = (
                await s.execute(select(UserRow.id).where(UserRow.role == "admin", UserRow.disabled.is_(False)).limit(1))
            ).first()
        return row is not None

    async def find_by_email(self, email: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = (await s.execute(select(UserRow).where(UserRow.email == email.lower()))).scalars().first()
        return _user(row) if row else None

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

    async def resolve_session(self, token: str, idle: timedelta | None = None) -> dict[str, Any] | None:
        """The active, enabled user behind a session cookie, or None. A session unused for ``idle`` has ended."""
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
            quiet = now - _aware(session.last_seen_at)
            if idle and quiet > idle:  # walked away from the browser: the session ends (and goes)
                await s.delete(session)
                return None
            # A cheap "last active" (not a write per request), often enough for the idle limit to hold.
            if quiet > min(timedelta(minutes=5), (idle or timedelta(minutes=20)) / 4):
                session.last_seen_at = now
            return {**_user(user), "session_id": session.token_hash[:SESSION_ID_LENGTH]}

    async def delete_session(self, token: str) -> bool:
        async with self.db.session() as s, s.begin():
            result = await s.execute(delete(SessionRow).where(SessionRow.token_hash == _digest(token)))
        return (cast("CursorResult[Any]", result).rowcount or 0) > 0

    async def sessions(self, user_id: str) -> list[dict[str, Any]]:
        """A user's signed-in browsers, most recently active first (ids are a prefix of the token's hash)."""
        now = _now()
        async with self.db.session() as s:
            rows = (await s.scalars(select(SessionRow).where(SessionRow.user_id == user_id, SessionRow.expires_at > now)
                                    .order_by(SessionRow.last_seen_at.desc()))).all()  # fmt: skip
        return [{"id": r.token_hash[:SESSION_ID_LENGTH], "created_at": _aware(r.created_at).isoformat(),
                 "last_seen_at": _aware(r.last_seen_at).isoformat(), "expires_at": _aware(r.expires_at).isoformat(),
                 "ip": r.ip, "user_agent": r.user_agent} for r in rows]  # fmt: skip

    async def end_sessions(self, user_id: str, *, only: str | None = None, keep: str | None = None) -> int:
        """End a user's sessions: one (``only``, a session id), all but one (``keep``), or all."""
        stmt = delete(SessionRow).where(SessionRow.user_id == user_id)
        if only:
            stmt = stmt.where(SessionRow.token_hash.startswith(only, autoescape=True))
        if keep:
            stmt = stmt.where(~SessionRow.token_hash.startswith(keep, autoescape=True))
        async with self.db.session() as s, s.begin():
            result = await s.execute(stmt)
        return cast("CursorResult[Any]", result).rowcount or 0

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
