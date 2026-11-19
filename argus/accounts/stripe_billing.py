"""Payments with Stripe: subscriptions to Argus plans, and Argus credit packs.

**Card details never touch Argus.** Customers pay on Stripe's own pages (Stripe Checkout) and
manage their subscription in Stripe's customer portal. The account service only:

1. asks Stripe for a checkout page for a plan or a credit pack, for an account it knows;
2. hears back from Stripe (a *webhook*) when something happens: a payment, a renewal, a failed
   payment, a cancellation; and updates the account's plan, status, paid-until date or credits.

**Webhooks are verified.** Each one carries a signature made with a secret only Stripe and the
account service know (``ARGUS_STRIPE_WEBHOOK_SECRET``), over the exact message and its time.
Anything unsigned, altered or older than five minutes is refused, and each event is applied once
only, however often Stripe re-sends it.

**What a customer can buy** is fixed by the operator: the plans' Stripe price ids and the credit
packs (``ARGUS_STRIPE_PRICE_PERSONAL``, ``ARGUS_STRIPE_PRICE_PROFESSIONAL``,
``ARGUS_STRIPE_CREDIT_PACKS`` such as ``500=price_123,2000=price_456``). Prices are set in Stripe
and shown as Stripe has them.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from typing import Any

import aiohttp

from argus.core.settings import Settings

TOLERANCE = 300  # seconds: older signed events are refused (replays)
# Stripe subscription status -> Argus account status
STATUS = {"active": "active", "trialing": "trialing", "past_due": "past_due", "unpaid": "past_due",
          "incomplete": "past_due", "canceled": "cancelled", "incomplete_expired": "cancelled", "paused": "cancelled"}  # fmt: skip


class BillingError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


# ---------------------------------------------------------------------------- what can be bought
def plan_prices(settings: Settings) -> dict[str, str]:
    """Plan -> Stripe price id, for the plans the operator has priced."""
    return {plan: price for plan, price in (("byok", settings.stripe_price_byok),
                                            ("personal", settings.stripe_price_personal),
                                            ("professional", settings.stripe_price_professional),
                                            ("business", settings.stripe_price_business)) if price}  # fmt: skip


def credit_packs(settings: Settings) -> dict[int, str]:
    """Credits -> Stripe price id, from ``500=price_123,2000=price_456``."""
    packs: dict[int, str] = {}
    for part in (settings.stripe_credit_packs or "").split(","):
        credits, _, price = part.strip().partition("=")
        if credits.strip().isdigit() and price.strip() and int(credits) > 0:
            packs[int(credits)] = price.strip()
    return packs


def plan_for_price(settings: Settings, price_id: str | None) -> str | None:
    return next((plan for plan, price in plan_prices(settings).items() if price == price_id), None)


def enabled(settings: Settings) -> bool:
    return bool(settings.stripe_secret_key and settings.stripe_secret_key.get_secret_value())


# ---------------------------------------------------------------------------- talking to Stripe
def _form(data: dict[str, Any], prefix: str = "") -> list[tuple[str, str]]:
    """Stripe's form encoding: nested keys as ``a[b][0][c]``."""
    out: list[tuple[str, str]] = []
    for key, value in data.items():
        name = f"{prefix}[{key}]" if prefix else str(key)
        if isinstance(value, dict):
            out += _form(value, name)
        elif isinstance(value, list):
            for i, item in enumerate(value):
                out += _form(item, f"{name}[{i}]") if isinstance(item, dict) else [(f"{name}[{i}]", str(item))]
        elif value is not None:
            out.append((name, "true" if value is True else "false" if value is False else str(value)))
    return out


async def call(settings: Settings, method: str, path: str, data: dict[str, Any] | None = None, *,
               idempotency_key: str | None = None) -> dict[str, Any]:  # fmt: skip
    if not enabled(settings):
        raise BillingError(503, "Payments are not set up on this account service")
    key = settings.stripe_secret_key.get_secret_value() if settings.stripe_secret_key else ""
    headers = {"Authorization": f"Bearer {key}"}
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key  # a retried request never creates two of anything
    url = settings.stripe_api_url.rstrip("/") + path
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as http, http.request(
            method, url, data=_form(data or {}) if method != "GET" else None,
            params=_form(data or {}) if method == "GET" else None, headers=headers,
        ) as resp:  # fmt: skip
            body = await resp.json(content_type=None)
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
        raise BillingError(503, "Stripe could not be reached; try again shortly") from exc
    if resp.status >= 400:
        message = (body.get("error") or {}).get("message") if isinstance(body, dict) else None
        raise BillingError(502, f"Stripe refused the request: {message or resp.status}")
    return body if isinstance(body, dict) else {}


# ---------------------------------------------------------------------------- webhooks
def verify_event(payload: bytes, header: str, secret: str, now: float | None = None) -> dict[str, Any]:
    """The event, if ``header`` (Stripe-Signature) proves Stripe sent ``payload`` recently."""
    parts: dict[str, list[str]] = {}
    for item in (header or "").split(","):
        key, _, value = item.strip().partition("=")
        parts.setdefault(key, []).append(value)
    try:
        stamp = int(parts.get("t", [""])[0])
    except ValueError as exc:
        raise BillingError(400, "Missing or malformed signature") from exc
    expected = hmac.new(secret.encode(), f"{stamp}.".encode() + payload, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(expected, sig) for sig in parts.get("v1", [])):
        raise BillingError(400, "The signature does not match")
    if abs((now if now is not None else time.time()) - stamp) > TOLERANCE:
        raise BillingError(400, "The event is too old (a replay?)")
    try:
        event = json.loads(payload)
    except ValueError as exc:
        raise BillingError(400, "The event is not valid JSON") from exc
    if not isinstance(event, dict) or not event.get("id") or not event.get("type"):
        raise BillingError(400, "Not a Stripe event")
    return event


def sign(payload: bytes, secret: str, stamp: int | None = None) -> str:
    """A Stripe-Signature header for ``payload`` (for tests and local trials)."""
    stamp = int(time.time()) if stamp is None else stamp
    return f"t={stamp},v1=" + hmac.new(secret.encode(), f"{stamp}.".encode() + payload, hashlib.sha256).hexdigest()


def period_end(subscription: dict[str, Any]) -> datetime | None:
    """When the paid period ends (newer API versions keep it on the subscription's items)."""
    stamp = subscription.get("current_period_end")
    if not stamp:
        items = (subscription.get("items") or {}).get("data") or []
        stamp = items[0].get("current_period_end") if items else None
    if subscription.get("status") == "canceled" and subscription.get("ended_at"):
        stamp = subscription["ended_at"]
    return datetime.fromtimestamp(int(stamp), tz=timezone.utc) if stamp else None


def subscription_quantity(subscription: dict[str, Any]) -> int:
    """Seats paid for (a team plan's quantity)."""
    items = (subscription.get("items") or {}).get("data") or []
    try:
        return max(1, int(items[0].get("quantity") or 1)) if items else 1
    except (TypeError, ValueError):
        return 1


def subscription_price(subscription: dict[str, Any]) -> str | None:
    items = (subscription.get("items") or {}).get("data") or []
    return ((items[0].get("price") or {}).get("id")) if items else None
