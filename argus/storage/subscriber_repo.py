"""Subscription accounts and their devices (account service), and this installation's own state."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from argus.accounts.licence import PLANS
from argus.storage.db import (
    AppStateRow,
    BillingEventRow,
    BillingPaymentRow,
    CreditLedgerRow,
    Database,
    SubscriberAccountRow,
    SubscriberDeviceRow,
    TeamInviteRow,
)

LOCK_AFTER = 5  # failed sign-ins in a row
LOCK_FOR = timedelta(minutes=15)


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


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
        "reminder_emails": bool(row.reminder_emails if row.reminder_emails is not None else True),
        "team_id": row.team_id, "seats": int(row.seats or 1),
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


def _payment(row: BillingPaymentRow) -> dict[str, Any]:
    return {"id": row.id, "account_id": row.account_id, "kind": row.kind, "credits": row.credits,
            "amount": row.amount, "currency": row.currency, "refunded": row.refunded,
            "refund_credits_taken": row.refund_credits_taken, "dispute_id": row.dispute_id,
            "dispute_status": row.dispute_status, "dispute_credits_taken": row.dispute_credits_taken,
            "status_before_hold": row.status_before_hold, "created_at": _iso(row.created_at),
            "updated_at": _iso(row.updated_at)}  # fmt: skip


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

    async def overview(self) -> list[dict[str, Any]]:
        """Every account with what the business dashboard needs (no password hashes)."""
        async with self.db.session() as s:
            rows = (await s.scalars(select(SubscriberAccountRow))).all()
        return [{**_account(r), "locked_until": _iso(r.locked_until), "allowance_month": r.allowance_month,
                 "allowance_remaining": r.allowance_remaining, "purchased_credits": r.purchased_credits,
                 "created": _aware(r.created_at), "until": _aware(r.valid_until)} for r in rows]  # fmt: skip

    async def by_billing_reference(self, reference: str) -> dict[str, Any] | None:
        if not reference:
            return None
        async with self.db.session() as s:
            row = await s.scalar(
                select(SubscriberAccountRow).where(SubscriberAccountRow.billing_reference == reference)
            )
        return _account(row) if row else None

    async def claim_event(self, event_id: str, kind: str) -> bool:
        """Record a payment event; False if it was already recorded (applied before, or being applied)."""
        try:
            async with self.db.session() as s, s.begin():
                if await s.get(BillingEventRow, event_id) is not None:
                    return False
                s.add(BillingEventRow(id=event_id, type=kind[:64], account_id="", received_at=_now()))
        except IntegrityError:  # the same event delivered twice at once: only one gets here
            return False
        return True

    async def last_billing_event(self) -> dict[str, Any] | None:
        """The most recent Stripe event received (to show the webhook is working)."""
        async with self.db.session() as s:
            row = await s.scalar(select(BillingEventRow).order_by(BillingEventRow.received_at.desc()).limit(1))
        return {"type": row.type, "at": _iso(row.received_at)} if row else None

    async def event_done(self, event_id: str, account_id: str) -> None:
        async with self.db.session() as s, s.begin():
            row = await s.get(BillingEventRow, event_id)
            if row is not None:
                row.account_id = account_id[:32]

    async def release_event(self, event_id: str) -> None:
        """Forget an event whose handling failed, so Stripe's retry applies it."""
        async with self.db.session() as s, s.begin():
            row = await s.get(BillingEventRow, event_id)
            if row is not None:
                await s.delete(row)

    # ------------------------------------------------------------------ payments (refunds, disputes)
    async def record_payment(self, payment_id: str, account_id: str, *, kind: str, credits: int = 0, amount: int = 0,
                             currency: str = "") -> dict[str, Any]:  # fmt: skip
        """The payment, recorded once (a repeat returns what is stored)."""
        try:
            async with self.db.session() as s, s.begin():
                row = await s.get(BillingPaymentRow, payment_id)
                if row is None:
                    row = BillingPaymentRow(id=payment_id[:255], account_id=account_id, kind=kind, credits=credits,
                                            amount=amount, currency=currency[:8].upper(), refunded=0,
                                            refund_credits_taken=0, dispute_id="", dispute_status="",
                                            dispute_credits_taken=0, status_before_hold="", created_at=_now(),
                                            updated_at=_now())  # fmt: skip
                    s.add(row)
                return _payment(row)
        except IntegrityError:  # recorded by another request at the same moment
            found = await self.payment(payment_id)
            if found is None:
                raise
            return found

    async def payment(self, payment_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.get(BillingPaymentRow, payment_id)
        return _payment(row) if row else None

    async def update_payment(self, payment_id: str, **changes: Any) -> None:
        async with self.db.session() as s, s.begin():
            row = await s.get(BillingPaymentRow, payment_id)
            if row is not None:
                for key, value in changes.items():
                    setattr(row, key, value)
                row.updated_at = _now()

    async def payments(self, account_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        query = select(BillingPaymentRow).order_by(BillingPaymentRow.created_at.desc()).limit(limit)
        if account_id:
            query = query.where(BillingPaymentRow.account_id == account_id)
        async with self.db.session() as s:
            rows = (await s.scalars(query)).all()
        return [_payment(r) for r in rows]

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
    async def attach_device(self, account_id: str, device_id: str, name: str,
                            limit: int | None = None) -> tuple[bool, list[dict[str, Any]]]:  # fmt: skip
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
            if len(active) >= (limit or max_devices(account)):
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

    async def revoke_all_devices(self, account_id: str) -> int:
        """Sign every computer out (after a password reset)."""
        async with self.db.session() as s, s.begin():
            rows = (await s.scalars(select(SubscriberDeviceRow).where(
                SubscriberDeviceRow.account_id == account_id, SubscriberDeviceRow.revoked.is_(False)))).all()  # fmt: skip
            for row in rows:
                row.revoked = True
        return len(rows)

    async def revoke_device(self, account_id: str, device_id: str) -> bool:
        async with self.db.session() as s, s.begin():
            row = await s.scalar(select(SubscriberDeviceRow).where(
                SubscriberDeviceRow.account_id == account_id, SubscriberDeviceRow.device_id == device_id))  # fmt: skip
            if row is None:
                return False
            row.revoked = True
        return True


def _month(now: datetime | None = None) -> str:
    return (now or _now()).strftime("%Y-%m")


def monthly_allowance(plan: str, seats: int = 1) -> int:
    """A plan's monthly credits; a team plan's are per seat, shared by the team."""
    info = PLANS.get(plan, {})
    return int(info.get("monthly_credits", 0)) * (max(1, int(seats or 1)) if info.get("per_seat") else 1)


def _roll(row: SubscriberAccountRow, s: Any, now: datetime | None = None) -> None:
    """A new month: the plan's allowance is renewed (unused allowance does not carry over)."""
    month = _month(now)
    if row.allowance_month != month:
        row.allowance_month, row.allowance_remaining = month, monthly_allowance(row.plan, row.seats)
        s.add(CreditLedgerRow(id=f"cl_{secrets.token_hex(8)}", account_id=row.id, kind="allowance",
                              delta=row.allowance_remaining, balance_after=row.allowance_remaining + row.purchased_credits,
                              detail=f"monthly allowance {month}", created_at=_now()))  # fmt: skip


def _balance(row: SubscriberAccountRow) -> dict[str, Any]:
    return {"allowance": monthly_allowance(row.plan, row.seats), "allowance_remaining": row.allowance_remaining,
            "purchased": row.purchased_credits, "available": row.allowance_remaining + row.purchased_credits,
            "month": row.allowance_month}  # fmt: skip


class CreditRepository:
    """Argus credits: spend the monthly allowance first, then purchased credits (which never expire)."""

    def __init__(self, db: Database):
        self.db = db

    async def balance(self, account_id: str, now: datetime | None = None) -> dict[str, Any] | None:
        async with self.db.session() as s, s.begin():
            row = await s.get(SubscriberAccountRow, account_id, with_for_update=True)
            if row is None:
                return None
            _roll(row, s, now)
            return _balance(row)

    async def charge(
        self, account_id: str, amount: int, detail: str, now: datetime | None = None, used_by: str = ""
    ) -> dict[str, Any] | None:
        """Take ``amount`` credits, atomically; None (nothing taken) if there are not enough."""
        async with self.db.session() as s, s.begin():
            row = await s.get(SubscriberAccountRow, account_id, with_for_update=True)  # one charge at a time
            if row is None:
                return None
            _roll(row, s, now)
            if row.allowance_remaining + row.purchased_credits < amount:
                return None
            from_allowance = min(amount, row.allowance_remaining)
            row.allowance_remaining -= from_allowance
            row.purchased_credits -= amount - from_allowance
            s.add(CreditLedgerRow(id=f"cl_{secrets.token_hex(8)}", account_id=account_id, kind="usage", delta=-amount,
                                  balance_after=row.allowance_remaining + row.purchased_credits, detail=detail[:255],
                                  used_by=used_by[:32], created_at=_now()))  # fmt: skip
            return {**_balance(row), "charged": amount, "from_allowance": from_allowance, "used_by": used_by}

    async def refund(self, account_id: str, charge: dict[str, Any], detail: str) -> None:
        """Give back a charge whose lookup failed, to where it came from."""
        async with self.db.session() as s, s.begin():
            row = await s.get(SubscriberAccountRow, account_id, with_for_update=True)
            if row is None:
                return
            row.allowance_remaining += charge["from_allowance"]
            row.purchased_credits += charge["charged"] - charge["from_allowance"]
            s.add(CreditLedgerRow(id=f"cl_{secrets.token_hex(8)}", account_id=account_id, kind="refund",
                                  delta=charge["charged"], balance_after=row.allowance_remaining + row.purchased_credits,
                                  detail=detail[:255], used_by=str(charge.get("used_by") or "")[:32],
                                  created_at=_now()))  # fmt: skip

    async def add(self, account_id: str, amount: int, *, kind: str, detail: str) -> dict[str, Any] | None:
        """Purchased credits (or an adjustment, which may be negative but never below zero)."""
        async with self.db.session() as s, s.begin():
            row = await s.get(SubscriberAccountRow, account_id, with_for_update=True)
            if row is None:
                return None
            _roll(row, s)
            row.purchased_credits = max(0, row.purchased_credits + amount)
            s.add(CreditLedgerRow(id=f"cl_{secrets.token_hex(8)}", account_id=account_id, kind=kind, delta=amount,
                                  balance_after=row.allowance_remaining + row.purchased_credits, detail=detail[:255],
                                  created_at=_now()))  # fmt: skip
            return _balance(row)

    async def take_back(self, account_id: str, amount: int, detail: str) -> int:
        """Remove up to ``amount`` purchased credits (after a refund or dispute); how many were removed.

        Credits already spent can't be taken back: the balance never goes below zero.
        """
        if amount <= 0:
            return 0
        async with self.db.session() as s, s.begin():
            row = await s.get(SubscriberAccountRow, account_id, with_for_update=True)
            if row is None:
                return 0
            _roll(row, s)
            taken = min(amount, row.purchased_credits)
            row.purchased_credits -= taken
            s.add(CreditLedgerRow(id=f"cl_{secrets.token_hex(8)}", account_id=account_id, kind="reversal", delta=-taken,
                                  balance_after=row.allowance_remaining + row.purchased_credits, detail=detail[:255],
                                  created_at=_now()))  # fmt: skip
            return taken

    async def upgrade_allowance(self, account_id: str, old_plan: str, new_plan: str, old_seats: int = 1,
                                new_seats: int = 1) -> None:  # fmt: skip
        """A move to a bigger plan (or more seats) mid-month: the extra allowance is available straight away."""
        extra = monthly_allowance(new_plan, new_seats) - monthly_allowance(old_plan, old_seats)
        if extra <= 0:
            return
        async with self.db.session() as s, s.begin():
            row = await s.get(SubscriberAccountRow, account_id, with_for_update=True)
            if row is None:
                return
            if row.allowance_month != _month():
                _roll(row, s)  # a fresh month already gives the new plan's whole allowance
                return
            row.allowance_remaining += extra
            s.add(CreditLedgerRow(id=f"cl_{secrets.token_hex(8)}", account_id=account_id, kind="allowance", delta=extra,
                                  balance_after=row.allowance_remaining + row.purchased_credits,
                                  detail=f"upgrade to {new_plan}" + (f" ({new_seats} seats)" if new_seats > 1 else ""),
                                  created_at=_now()))  # fmt: skip

    async def since(self, start: datetime) -> list[dict[str, Any]]:
        """Every credit movement since ``start`` (for the business dashboard)."""
        async with self.db.session() as s:
            rows = (await s.scalars(select(CreditLedgerRow).where(CreditLedgerRow.created_at >= start)
                                    .order_by(CreditLedgerRow.created_at))).all()  # fmt: skip
        return [{"account_id": r.account_id, "kind": r.kind, "delta": r.delta, "detail": r.detail,
                 "used_by": r.used_by or "", "at": _aware(r.created_at)} for r in rows]  # fmt: skip

    async def ledger(self, account_id: str, limit: int = 100) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (await s.scalars(select(CreditLedgerRow).where(CreditLedgerRow.account_id == account_id)
                                    .order_by(CreditLedgerRow.created_at.desc()).limit(limit))).all()  # fmt: skip
        return [{"kind": r.kind, "delta": r.delta, "balance_after": r.balance_after, "detail": r.detail,
                 "used_by": r.used_by or "", "at": _iso(r.created_at)} for r in rows]  # fmt: skip

    async def used_by_member(self, account_id: str, start: datetime) -> dict[str, int]:
        """Credits each team member used since ``start`` (refunded lookups netted off)."""
        async with self.db.session() as s:
            rows = (await s.execute(select(CreditLedgerRow.used_by, CreditLedgerRow.delta).where(
                CreditLedgerRow.account_id == account_id, CreditLedgerRow.kind.in_(("usage", "refund")),
                CreditLedgerRow.created_at >= start))).all()  # fmt: skip
        out: dict[str, int] = {}
        for who, delta in rows:
            key = who or account_id
            out[key] = out.get(key, 0) - int(delta)
        return out


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


class TeamRepository:
    """Team plans: who belongs to which team, and the invitations (stored only as hashes)."""

    def __init__(self, db: Database):
        self.db = db

    async def members(self, team_id: str) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (await s.scalars(select(SubscriberAccountRow).where(SubscriberAccountRow.team_id == team_id)
                                    .order_by(SubscriberAccountRow.email))).all()  # fmt: skip
        return [_account(r) for r in rows]

    async def join(self, account_id: str, team_id: str, seats: int) -> bool:
        """Add a member if a seat is free (the owner holds one seat); False if the team is full."""
        async with self.db.session() as s, s.begin():
            owner = await s.get(SubscriberAccountRow, team_id, with_for_update=True)  # one join at a time
            row = await s.get(SubscriberAccountRow, account_id)
            if owner is None or row is None:
                return False
            if row.team_id == team_id:
                return True
            count = await s.scalar(select(func.count()).select_from(SubscriberAccountRow).where(
                SubscriberAccountRow.team_id == team_id))  # fmt: skip
            if int(count or 0) + 2 > seats:  # the members, the owner, and this newcomer must fit
                return False
            row.team_id = team_id
        return True

    async def leave(self, account_id: str) -> str | None:
        """Take a member off their team; the team they were on."""
        async with self.db.session() as s, s.begin():
            row = await s.get(SubscriberAccountRow, account_id)
            if row is None or not row.team_id:
                return None
            team, row.team_id = row.team_id, None
        return team

    async def invite(self, team_id: str, email: str, ttl: timedelta) -> str:
        """A fresh invitation token (an earlier open one for the same email stops working)."""
        token, now = secrets.token_urlsafe(32), _now()
        async with self.db.session() as s, s.begin():
            for row in (await s.scalars(select(TeamInviteRow).where(
                    TeamInviteRow.team_id == team_id, TeamInviteRow.email == email.lower(),
                    TeamInviteRow.accepted_at.is_(None), TeamInviteRow.cancelled.is_(False)))).all():  # fmt: skip
                row.cancelled = True
            s.add(TeamInviteRow(token_hash=_hash(token), team_id=team_id, email=email.lower(), expires_at=now + ttl,
                                cancelled=False, created_at=now))  # fmt: skip
        return token

    async def invites(self, team_id: str) -> list[dict[str, Any]]:
        """Open invitations (not accepted, cancelled or expired)."""
        now = _now()
        async with self.db.session() as s:
            rows = (await s.scalars(select(TeamInviteRow).where(
                TeamInviteRow.team_id == team_id, TeamInviteRow.accepted_at.is_(None),
                TeamInviteRow.cancelled.is_(False)).order_by(TeamInviteRow.created_at.desc()))).all()  # fmt: skip
        return [{"email": r.email, "sent_at": _iso(r.created_at), "expires_at": _iso(r.expires_at)}
                for r in rows if (_aware(r.expires_at) or now) > now]  # fmt: skip

    async def cancel_invite(self, team_id: str, email: str) -> bool:
        async with self.db.session() as s, s.begin():
            rows = (await s.scalars(select(TeamInviteRow).where(
                TeamInviteRow.team_id == team_id, TeamInviteRow.email == email.lower(),
                TeamInviteRow.accepted_at.is_(None), TeamInviteRow.cancelled.is_(False)))).all()  # fmt: skip
            for row in rows:
                row.cancelled = True
        return bool(rows)

    async def find_invite(self, token: str) -> dict[str, Any] | None:
        """An open, unexpired invitation."""
        now = _now()
        async with self.db.session() as s:
            row = await s.get(TeamInviteRow, _hash(token))
        if row is None or row.accepted_at or row.cancelled or (_aware(row.expires_at) or now) <= now:
            return None
        return {"team_id": row.team_id, "email": row.email}

    async def accept_invite(self, token: str) -> bool:
        async with self.db.session() as s, s.begin():
            row = await s.get(TeamInviteRow, _hash(token), with_for_update=True)
            if row is None or row.accepted_at or row.cancelled:
                return False
            row.accepted_at = _now()
        return True
