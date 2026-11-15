"""Subscription accounts and their devices (account service), and this installation's own state."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select

from argus.accounts.licence import PLANS
from argus.storage.db import AppStateRow, Database, SubscriberAccountRow, SubscriberDeviceRow

LOCK_AFTER = 5  # failed sign-ins in a row
LOCK_FOR = timedelta(minutes=15)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value: datetime | None) -> str | None:
    value = _aware(value)
    return value.isoformat() if value else None


def _account(row: SubscriberAccountRow, devices: int | None = None) -> dict[str, Any]:
    out = {
        "id": row.id, "email": row.email, "name": row.name, "plan": row.plan,
        "plan_label": PLANS.get(row.plan, {}).get("label", row.plan), "status": row.status,
        "valid_until": _iso(row.valid_until), "max_devices": max_devices(row),
        "billing_reference": row.billing_reference, "created_at": _iso(row.created_at),
        "last_login_at": _iso(row.last_login_at),
    }  # fmt: skip
    if devices is not None:
        out["devices"] = devices
    return out


def max_devices(row: SubscriberAccountRow) -> int:
    return int(row.max_devices or PLANS.get(row.plan, {}).get("max_devices", 1))


def _device(row: SubscriberDeviceRow) -> dict[str, Any]:
    return {"id": row.id, "device_id": row.device_id, "name": row.name, "revoked": bool(row.revoked),
            "first_seen": _iso(row.first_seen), "last_seen": _iso(row.last_seen)}  # fmt: skip


class SubscriberRepository:
    def __init__(self, db: Database):
        self.db = db

    # ------------------------------------------------------------------ accounts
    async def create(self, *, email: str, name: str, password_hash: str, plan: str, status: str,
                     valid_until: datetime) -> dict[str, Any] | None:  # fmt: skip
        """A new account, or None if the email is taken."""
        async with self.db.session() as s, s.begin():
            if await s.scalar(select(SubscriberAccountRow.id).where(SubscriberAccountRow.email == email.lower())):
                return None
            row = SubscriberAccountRow(
                id=f"acc_{secrets.token_hex(8)}", email=email.lower(), name=name, password_hash=password_hash,
                plan=plan, status=status, valid_until=valid_until, failed_logins=0, billing_reference="",
                created_at=_now(),
            )  # fmt: skip
            s.add(row)
        return _account(row)

    async def by_email(self, email: str) -> tuple[dict[str, Any], str, datetime | None] | None:
        """(account, password hash, locked until) for sign-in."""
        async with self.db.session() as s:
            row = await s.scalar(select(SubscriberAccountRow).where(SubscriberAccountRow.email == email.lower()))
        return (_account(row), row.password_hash, _aware(row.locked_until)) if row else None

    async def get(self, account_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.get(SubscriberAccountRow, account_id)
            if row is None:
                return None
            count = await s.scalar(select(func.count()).select_from(SubscriberDeviceRow).where(
                SubscriberDeviceRow.account_id == account_id, SubscriberDeviceRow.revoked.is_(False)))  # fmt: skip
        return _account(row, int(count or 0))

    async def list_accounts(self) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (
                await s.scalars(select(SubscriberAccountRow).order_by(SubscriberAccountRow.created_at.desc()))
            ).all()
        return [_account(r) for r in rows]

    async def update(self, account_id: str, **changes: Any) -> dict[str, Any] | None:
        async with self.db.session() as s, s.begin():
            row = await s.get(SubscriberAccountRow, account_id)
            if row is None:
                return None
            for key, value in changes.items():
                setattr(row, key, value)
        return await self.get(account_id)

    async def login_failed(self, account_id: str) -> None:
        async with self.db.session() as s, s.begin():
            row = await s.get(SubscriberAccountRow, account_id)
            if row is None:
                return
            row.failed_logins += 1
            if row.failed_logins >= LOCK_AFTER:
                row.locked_until, row.failed_logins = _now() + LOCK_FOR, 0

    async def login_succeeded(self, account_id: str) -> None:
        async with self.db.session() as s, s.begin():
            row = await s.get(SubscriberAccountRow, account_id)
            if row is not None:
                row.failed_logins, row.locked_until, row.last_login_at = 0, None, _now()

    # ------------------------------------------------------------------ devices
    async def attach_device(self, account_id: str, device_id: str, name: str) -> tuple[bool, list[dict[str, Any]]]:
        """Register (or re-use) a device; (False, active devices) if the plan's device limit is reached."""
        async with self.db.session() as s, s.begin():
            account = await s.get(SubscriberAccountRow, account_id)
            if account is None:
                return False, []
            existing = await s.scalar(select(SubscriberDeviceRow).where(
                SubscriberDeviceRow.account_id == account_id, SubscriberDeviceRow.device_id == device_id))  # fmt: skip
            active = (await s.scalars(select(SubscriberDeviceRow).where(
                SubscriberDeviceRow.account_id == account_id, SubscriberDeviceRow.revoked.is_(False)))).all()  # fmt: skip
            if existing is not None and not existing.revoked:
                existing.last_seen, existing.name = _now(), name or existing.name
                return True, [_device(d) for d in active]
            if len(active) >= max_devices(account):
                return False, [_device(d) for d in active]
            if existing is not None:
                existing.revoked, existing.last_seen, existing.name = False, _now(), name or existing.name
            else:
                s.add(SubscriberDeviceRow(id=f"dev_{secrets.token_hex(8)}", account_id=account_id, device_id=device_id,
                                          name=name, revoked=False, first_seen=_now(), last_seen=_now()))  # fmt: skip
        return True, []

    async def device_active(self, account_id: str, device_id: str) -> bool:
        async with self.db.session() as s, s.begin():
            row = await s.scalar(select(SubscriberDeviceRow).where(
                SubscriberDeviceRow.account_id == account_id, SubscriberDeviceRow.device_id == device_id))  # fmt: skip
            if row is None or row.revoked:
                return False
            row.last_seen = _now()
        return True

    async def devices(self, account_id: str) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (await s.scalars(select(SubscriberDeviceRow).where(SubscriberDeviceRow.account_id == account_id)
                                    .order_by(SubscriberDeviceRow.last_seen.desc()))).all()  # fmt: skip
        return [_device(r) for r in rows]

    async def revoke_device(self, account_id: str, device_id: str) -> bool:
        async with self.db.session() as s, s.begin():
            row = await s.scalar(select(SubscriberDeviceRow).where(
                SubscriberDeviceRow.account_id == account_id, SubscriberDeviceRow.device_id == device_id))  # fmt: skip
            if row is None:
                return False
            row.revoked = True
        return True


class AppStateRepository:
    """A few values about this installation, kept in its own database."""

    def __init__(self, db: Database):
        self.db = db

    async def get(self, key: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.get(AppStateRow, key)
        return dict(row.value) if row else None

    async def set(self, key: str, value: dict[str, Any]) -> None:
        async with self.db.session() as s, s.begin():
            row = await s.get(AppStateRow, key)
            if row is None:
                s.add(AppStateRow(key=key, value=value, updated_at=_now()))
            else:
                row.value, row.updated_at = value, _now()

    async def delete(self, key: str) -> None:
        async with self.db.session() as s, s.begin():
            row = await s.get(AppStateRow, key)
            if row is not None:
                await s.delete(row)
