"""Customers' privacy rights on the account service: a copy of their data, and deleting their account.

* **A copy** (the right of access, and portability): everything held about the account, as JSON:
  profile, terms accepted, computers, plan and credits, payments, emails sent, team, and the
  security log entries about it.
* **Deleting an account**: the payment provider's customer record is deleted (which also ends
  any subscription), every computer is signed out, and the account's name, email, password,
  computers, emails, password-reset links and team invitations are erased. Payment and credit
  records stay, attached to the anonymous account id, because tax law requires them.
  A team owner must first remove their team's members (they keep their own accounts).
* **Retention**: records of sent emails, expired links and invitations go after 6 months;
  computers signed out over a year ago are forgotten.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from argus import __version__
from argus.accounts import stripe_billing as stripe

logger = logging.getLogger("argus.privacy")
EMAILS_KEPT = timedelta(days=180)
SIGNED_OUT_DEVICES_KEPT = timedelta(days=365)
PURGE_EVERY = 24 * 3600
EMAIL_FIELDS = ("kind", "subject", "status", "created_at", "sent_at")


class PrivacyError(Exception):
    """A request that can't be done as asked (the message says why, for people)."""


async def export(app: Any, account_id: str) -> dict[str, Any]:
    state = app.state
    account = await state.subscribers.get(account_id) or {}
    audit = [e for e in await state.audit.list(limit=5000) if e.get("resource") == account_id]
    team = None
    if account.get("team_id") or await state.teams.members(account_id):
        owner_id = account.get("team_id") or account_id
        team = {"team_owner": owner_id == account_id,
                "members": [m["email"] for m in await state.teams.members(owner_id)] if owner_id == account_id else None}  # fmt: skip
    mails = await state.account_mail.for_account(account_id, limit=10_000)
    return {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "service": "Argus account service",
        "argus_version": __version__,
        "note": "Your cases are not here: they stay on your own computer (Argus Personal).",
        "account": {k: v for k, v in account.items() if k != "billing_reference"},
        "payment_provider_customer": bool(account.get("billing_reference")),
        "computers": await state.subscribers.devices(account_id),
        "credits": await state.credits.balance(account_id),
        "credit_history": await state.credits.ledger(account_id, limit=10_000),
        "payments": await state.subscribers.payments(account_id, limit=10_000),
        "emails_sent": [{k: m.get(k) for k in EMAIL_FIELDS} for m in mails],
        "team": team,
        "security_log": [{k: e.get(k) for k in ("ts", "action", "outcome", "ip", "details")} for e in audit],
    }


async def delete_account(app: Any, account: dict[str, Any]) -> None:
    state, settings = app.state, app.state.settings
    if await state.teams.members(account["id"]):
        raise PrivacyError("Remove your team's members first (Settings → Team): their accounts are theirs to keep")
    if account.get("billing_reference") and stripe.enabled(settings):
        try:  # deleting the customer also cancels every subscription straight away
            await stripe.call(settings, "DELETE", f"/v1/customers/{account['billing_reference']}")
        except stripe.BillingError as exc:
            raise PrivacyError(
                f"The payment provider couldn't be updated, so nothing was deleted: {exc.detail}"
            ) from exc
    if account.get("team_id"):
        await state.teams.leave(account["id"])
    await state.subscribers.erase(account["id"])
    logger.info("Account %s deleted at its holder's request", account["id"])


async def purge(app: Any, now: datetime | None = None) -> dict[str, int]:
    now = now or datetime.now(timezone.utc)
    return await app.state.subscribers.purge(emails_before=now - EMAILS_KEPT,
                                             devices_before=now - SIGNED_OUT_DEVICES_KEPT)  # fmt: skip


async def run_forever(app: Any) -> None:
    await asyncio.sleep(120)
    while True:
        try:
            removed = await purge(app)
            if any(removed.values()):
                logger.info("Retention: removed %s", removed)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Retention clean-up failed")
        await asyncio.sleep(PURGE_EVERY)
