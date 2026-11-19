"""Emails to account holders (an outbox), and password reset links (account service)."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from argus.storage.db import AccountEmailRow, Database, PasswordResetRow, SubscriberAccountRow

RETRY_AFTER = (60, 300, 1800, 7200, 43200)  # seconds; then the email is given up on


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    return value if value is None or value.tzinfo else value.replace(tzinfo=timezone.utc)


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _email(r: AccountEmailRow) -> dict[str, Any]:
    sent, created = _aware(r.sent_at), _aware(r.created_at)
    return {"id": r.id, "account_id": r.account_id, "kind": r.kind, "to": r.recipient, "subject": r.subject, "status": r.status,
            "attempts": r.attempts, "error": r.last_error or None, "created_at": created.isoformat() if created else None,
            "sent_at": sent.isoformat() if sent else None}  # fmt: skip


class AccountMailRepository:
    def __init__(self, db: Database):
        self.db = db

    # ------------------------------------------------------------------ the outbox
    async def enqueue(self, *, account_id: str, kind: str, key: str, to: str, subject: str, text: str,
                      html: str) -> bool:  # fmt: skip
        """Queue an email; False if one with the same key was already queued (each is sent once)."""
        now = _now()
        try:
            async with self.db.session() as s, s.begin():
                if await s.scalar(select(AccountEmailRow.id).where(AccountEmailRow.dedupe_key == key[:255])):
                    return False
                s.add(AccountEmailRow(id=f"em_{secrets.token_hex(8)}", account_id=account_id, kind=kind[:32],
                                      dedupe_key=key[:255], recipient=to[:320], subject=subject[:255], body_text=text,
                                      body_html=html, status="pending", attempts=0, next_attempt_at=now, last_error="",
                                      created_at=now))  # fmt: skip
        except IntegrityError:  # the same email queued twice at once
            return False
        return True

    async def due(self, limit: int = 20, now: datetime | None = None) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (await s.scalars(select(AccountEmailRow).where(
                AccountEmailRow.status == "pending", AccountEmailRow.next_attempt_at <= (now or _now()))
                .order_by(AccountEmailRow.next_attempt_at).limit(limit))).all()  # fmt: skip
        return [{**_email(r), "text": r.body_text, "html": r.body_html} for r in rows]

    async def claim(self, email_id: str, attempts: int, lease: float = 300) -> bool:
        """Take an email for sending (one sender at a time, even with several servers)."""
        async with self.db.session() as s, s.begin():
            done = await s.execute(update(AccountEmailRow).where(
                AccountEmailRow.id == email_id, AccountEmailRow.status == "pending",
                AccountEmailRow.attempts == attempts).values(
                attempts=attempts + 1, next_attempt_at=_now() + timedelta(seconds=lease)))  # fmt: skip
        return bool(getattr(done, "rowcount", 0))

    async def sent(self, email_id: str) -> None:
        async with self.db.session() as s, s.begin():
            row = await s.get(AccountEmailRow, email_id)
            if row is not None:  # the text is not kept once delivered: it may hold a reset link
                row.status, row.sent_at, row.body_text, row.body_html, row.last_error = "sent", _now(), "", "", ""

    async def failed(self, email_id: str, error: str, retry: bool) -> None:
        async with self.db.session() as s, s.begin():
            row = await s.get(AccountEmailRow, email_id)
            if row is None:
                return
            row.last_error = error[:255]
            if retry and row.attempts <= len(RETRY_AFTER):
                row.next_attempt_at = _now() + timedelta(seconds=RETRY_AFTER[row.attempts - 1])
            else:
                row.status, row.body_text, row.body_html = "failed", "", ""

    async def for_account(self, account_id: str, limit: int = 50) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (await s.scalars(select(AccountEmailRow).where(AccountEmailRow.account_id == account_id)
                                    .order_by(AccountEmailRow.created_at.desc()).limit(limit))).all()  # fmt: skip
        return [_email(r) for r in rows]

    async def counts(self) -> dict[str, int]:
        async with self.db.session() as s:
            rows = (await s.execute(select(AccountEmailRow.status))).scalars().all()
        out = {"pending": 0, "sent": 0, "failed": 0}
        for status in rows:
            out[status] = out.get(status, 0) + 1
        return out

    # ------------------------------------------------------------------ reminder preference
    async def wants_reminders(self, account_id: str) -> bool:
        async with self.db.session() as s:
            value = await s.scalar(select(SubscriberAccountRow.reminder_emails).where(
                SubscriberAccountRow.id == account_id))  # fmt: skip
        return bool(value) if value is not None else False

    async def set_reminders(self, account_id: str, wanted: bool) -> bool:
        async with self.db.session() as s, s.begin():
            row = await s.get(SubscriberAccountRow, account_id)
            if row is None:
                return False
            row.reminder_emails = wanted
        return True

    # ------------------------------------------------------------------ password resets
    async def new_reset(self, account_id: str, ttl: timedelta) -> str:
        """A fresh reset token (earlier unused ones stop working). Only its hash is stored."""
        token = secrets.token_urlsafe(32)
        now = _now()
        async with self.db.session() as s, s.begin():
            await s.execute(update(PasswordResetRow).where(PasswordResetRow.account_id == account_id,
                                                           PasswordResetRow.used_at.is_(None)).values(used_at=now))  # fmt: skip
            s.add(
                PasswordResetRow(token_hash=_hash(token), account_id=account_id, expires_at=now + ttl, created_at=now)
            )
        return token

    async def use_reset(self, token: str, *, consume: bool = True) -> str | None:
        """The account a valid, unused, unexpired token belongs to; with ``consume`` the token is used up."""
        now = _now()
        async with self.db.session() as s, s.begin():
            row = await s.get(PasswordResetRow, _hash(token), with_for_update=True)
            if row is None or row.used_at is not None or (_aware(row.expires_at) or now) <= now:
                return None
            if consume:
                row.used_at = now
            return row.account_id

    async def recent_resets(self, account_id: str, within: timedelta) -> int:
        async with self.db.session() as s:
            rows = (await s.scalars(select(PasswordResetRow.token_hash).where(
                PasswordResetRow.account_id == account_id, PasswordResetRow.created_at >= _now() - within))).all()  # fmt: skip
        return len(rows)
