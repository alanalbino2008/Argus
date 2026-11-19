"""Payments on the account service: subscribe, buy credits, manage billing, and Stripe's webhook.

* ``GET  /api/billing/catalogue``: what can be bought, at Stripe's prices (no sign-in needed);
* ``POST /api/billing/checkout``: a Stripe payment page for a plan or a credit pack, for the
  account holding the licence sent;
* ``POST /api/billing/portal``: Stripe's billing page for that account (card, invoices, cancel);
* ``POST /api/billing/webhook``: Stripe reports payments, renewals, failed payments and
  cancellations. Signed, applied once each, and recorded in the audit log.

What a payment changes:

| Event | Effect on the account |
|---|---|
| subscription paid or renewed | plan from the price, status ``active``, paid until the period's end |
| payment failed | ``past_due``: still fully usable while Stripe retries (a grace period) |
| cancelled | stays usable to the end of the period already paid, then read-only |
| credit pack paid | the credits are added (purchased credits never expire) |
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from argus.accounts import stripe_billing as stripe
from argus.api.account_routes import SERVICE, _licence_account, _service
from argus.api.deps import audit

router = APIRouter(prefix="/api/billing", tags=["billing"])
GRACE = timedelta(days=7)  # a failed renewal keeps working at least this long while Stripe retries
LOCAL_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1"}
_prices: dict[str, tuple[float, dict[str, Any] | None]] = {}  # price id -> (fetched at, price)


class CheckoutRequest(BaseModel):
    licence: str = Field(max_length=8192)
    item: str = Field(max_length=64, pattern=r"^(plan:(personal|professional)|credits:\d{1,7})$")
    return_url: str = Field(default="", max_length=500)


class PortalRequest(BaseModel):
    licence: str = Field(max_length=8192)
    return_url: str = Field(default="", max_length=500)


def _settings(request: Request) -> Any:
    _service(request)  # the account service must be on
    return request.app.state.settings


def _error(exc: stripe.BillingError) -> HTTPException:
    return HTTPException(status_code=exc.status, detail=exc.detail)


def _return_url(request: Request, asked: str) -> str:
    """Where Stripe sends the customer back: Argus Personal on their own computer, or the operator's page."""
    configured = request.app.state.settings.billing_return_url
    if asked:
        parts = urlsplit(asked)
        allowed = {urlsplit(configured).netloc} if configured else set()
        if parts.scheme in ("http", "https") and (parts.hostname in LOCAL_HOSTS or parts.netloc in allowed):
            return asked
        raise HTTPException(status_code=422, detail="That return address is not allowed")
    if configured:
        return configured
    raise HTTPException(status_code=422, detail="No return address: set ARGUS_BILLING_RETURN_URL")


async def _price(settings: Any, price_id: str) -> dict[str, Any] | None:
    """A price as Stripe has it (cached ten minutes); None if Stripe can't say."""
    cached = _prices.get(price_id)
    if cached and time.monotonic() - cached[0] < 600:
        return cached[1]
    try:
        raw = await stripe.call(settings, "GET", f"/v1/prices/{price_id}")
    except stripe.BillingError:
        return cached[1] if cached else None
    recurring = raw.get("recurring") or {}
    price = {"amount": raw.get("unit_amount"), "currency": str(raw.get("currency") or "").upper(),
             "interval": recurring.get("interval")}  # fmt: skip
    _prices[price_id] = (time.monotonic(), price)
    return price


# ---------------------------------------------------------------------------- customers
@router.get("/catalogue")
async def billing_catalogue(request: Request):
    """The plans and credit packs on sale, with their prices."""
    return await _catalogue(request)


@router.post("/catalogue")
async def billing_catalogue_for_account(request: Request):
    """The same, plus whether the account sending its licence can open Manage billing."""
    return await _catalogue(request)


async def _catalogue(request: Request) -> dict[str, Any]:
    settings = _settings(request)
    if not stripe.enabled(settings):
        return {"enabled": False, "plans": [], "credit_packs": []}
    from argus.accounts.licence import PLANS

    plans = [{"item": f"plan:{plan}", "plan": plan, "label": PLANS[plan]["label"],
              "monthly_credits": PLANS[plan].get("monthly_credits", 0), "max_devices": PLANS[plan].get("max_devices", 1),
              "price": await _price(settings, price)} for plan, price in stripe.plan_prices(settings).items()]  # fmt: skip
    has_billing = False
    if request.method == "POST":  # from Argus Personal, with the licence: can this account manage billing?
        try:
            token = str((await request.json() or {}).get("licence") or "")
        except ValueError:
            token = ""
        if token:
            _payload, account, _private = await _licence_account(request, token)
            has_billing = account["billing_reference"].startswith("cus_")
    packs = [{"item": f"credits:{credits}", "credits": credits, "price": await _price(settings, price)}
             for credits, price in sorted(stripe.credit_packs(settings).items())]  # fmt: skip
    return {"enabled": True, "plans": plans, "credit_packs": packs, "has_billing": has_billing}


@router.post("/checkout")
async def checkout(body: CheckoutRequest, request: Request):
    """A Stripe payment page for a plan or a credit pack. Works for lapsed accounts too (to renew)."""
    settings = _settings(request)
    if not stripe.enabled(settings):
        raise HTTPException(status_code=503, detail="Payments are not set up on this account service")
    _payload, account, _private = await _licence_account(request, body.licence)
    if account["status"] == "suspended":
        raise HTTPException(status_code=403, detail="This account is suspended: contact support")
    kind, _, what = body.item.partition(":")
    back = _return_url(request, body.return_url)
    customer = account["billing_reference"] if account["billing_reference"].startswith("cus_") else ""
    session: dict[str, Any] = {
        "client_reference_id": account["id"], "metadata": {"account_id": account["id"]},
        "success_url": back + ("&" if "?" in back else "?") + "billing=done",
        "cancel_url": back + ("&" if "?" in back else "?") + "billing=cancelled",
    }  # fmt: skip
    session.update({"customer": customer} if customer else {"customer_email": account["email"]})
    if kind == "plan":
        price = stripe.plan_prices(settings).get(what)
        if not price:
            raise HTTPException(status_code=404, detail="That plan is not on sale")
        if customer and account["status"] in ("active", "past_due") and account["plan"] != "trial":
            raise HTTPException(
                status_code=409, detail="You already have a subscription: use Manage billing to change it"
            )
        session.update(mode="subscription", line_items=[{"price": price, "quantity": 1}],
                       subscription_data={"metadata": {"account_id": account["id"]}})  # fmt: skip
    else:
        price = stripe.credit_packs(settings).get(int(what))
        if not price:
            raise HTTPException(status_code=404, detail="That credit pack is not on sale")
        session.update(mode="payment", line_items=[{"price": price, "quantity": 1}],
                       metadata={"account_id": account["id"], "credits": what})  # fmt: skip
        if not customer:
            session["customer_creation"] = "always"  # so Manage billing can show the receipt later
    try:
        page = await stripe.call(settings, "POST", "/v1/checkout/sessions", session)
    except stripe.BillingError as exc:
        raise _error(exc) from exc
    await audit(request, SERVICE, "billing.checkout", account["id"], details={"item": body.item})
    return {"url": page.get("url"), "id": page.get("id")}


@router.post("/portal")
async def portal(body: PortalRequest, request: Request):
    """Stripe's billing page for this account: card, invoices, change plan or cancel."""
    settings = _settings(request)
    _payload, account, _private = await _licence_account(request, body.licence)
    if not account["billing_reference"].startswith("cus_"):
        raise HTTPException(status_code=404, detail="Nothing has been bought on this account yet")
    try:
        page = await stripe.call(settings, "POST", "/v1/billing_portal/sessions",
                                 {"customer": account["billing_reference"],
                                  "return_url": _return_url(request, body.return_url)})  # fmt: skip
    except stripe.BillingError as exc:
        raise _error(exc) from exc
    return {"url": page.get("url")}


# ---------------------------------------------------------------------------- Stripe's webhook
@router.post("/webhook")
async def webhook(request: Request):
    """Stripe reports a payment, renewal, failure or cancellation. Signed; each event applied once."""
    settings = _settings(request)
    secret = settings.stripe_webhook_secret.get_secret_value() if settings.stripe_webhook_secret else ""
    if not secret:
        raise HTTPException(status_code=503, detail="The Stripe webhook secret is not configured")
    payload = await request.body()
    if len(payload) > 1_000_000:
        raise HTTPException(status_code=413, detail="Too large")
    try:
        event = stripe.verify_event(payload, request.headers.get("stripe-signature", ""), secret)
    except stripe.BillingError as exc:
        raise _error(exc) from exc
    repo = request.app.state.subscribers
    key = settings.stripe_secret_key.get_secret_value() if settings.stripe_secret_key else ""
    if event.get("livemode") is True and key.startswith("sk_test_"):
        raise HTTPException(status_code=400, detail="A live event sent to a test-mode account service")
    if not await repo.claim_event(str(event["id"]), str(event["type"])):
        return {"received": True, "duplicate": True}
    try:
        account_id = await _apply(request, event)
    except stripe.BillingError as exc:
        await repo.release_event(str(event["id"]))  # Stripe retries; the retry applies it
        raise HTTPException(status_code=503, detail=exc.detail) from exc
    except Exception:
        await repo.release_event(str(event["id"]))
        raise
    await repo.event_done(str(event["id"]), account_id or "")
    return {"received": True, "applied": bool(account_id)}


async def _account_for(request: Request, obj: dict[str, Any]) -> dict[str, Any] | None:
    repo = request.app.state.subscribers
    account_id = (obj.get("metadata") or {}).get("account_id") or obj.get("client_reference_id")
    account = await repo.get(str(account_id)) if account_id else None
    customer = obj.get("customer")
    if account is None and isinstance(customer, str):
        account = await repo.by_billing_reference(customer)
    if account is not None and isinstance(customer, str) and customer and account["billing_reference"] != customer:
        account = await repo.update(account["id"], billing_reference=customer)
    return account


async def _apply(request: Request, event: dict[str, Any]) -> str | None:
    """Apply one event; the account changed, or None if the event is not one Argus acts on."""
    kind, obj = event["type"], (event.get("data") or {}).get("object") or {}
    if kind in ("checkout.session.completed", "checkout.session.async_payment_succeeded"):
        account = await _account_for(request, obj)
        if account is None:
            return None
        if obj.get("mode") == "payment" and obj.get("payment_status") == "paid":
            return await _credits_paid(request, account, obj, event)
        if obj.get("mode") == "subscription" and isinstance(obj.get("subscription"), str):
            subscription = await stripe.call(
                request.app.state.settings, "GET", f"/v1/subscriptions/{obj['subscription']}"
            )
            return await _subscription(request, account, subscription, event)
        return account["id"]
    if kind.startswith("customer.subscription."):
        account = await _account_for(request, obj)
        if account is None:
            return None
        settings, current = request.app.state.settings, obj
        if kind != "customer.subscription.deleted" and obj.get("id"):
            # events can arrive out of order: act on the subscription as it is now
            current = await stripe.call(settings, "GET", f"/v1/subscriptions/{obj['id']}")
        elif isinstance(obj.get("customer"), str):
            # an old subscription ended: if the customer has a newer one, that one counts
            live = await stripe.call(settings, "GET", "/v1/subscriptions", {"customer": obj["customer"], "limit": 10})
            ongoing = [s for s in live.get("data") or [] if s.get("id") != obj.get("id")
                       and s.get("status") in ("active", "trialing", "past_due", "unpaid")]  # fmt: skip
            current = ongoing[0] if ongoing else obj
        return await _subscription(request, account, current, event)
    return None


async def _credits_paid(request: Request, account: dict[str, Any], obj: dict[str, Any], event: dict[str, Any]) -> str:
    credits = str((obj.get("metadata") or {}).get("credits") or "")
    if not credits.isdigit() or not 0 < int(credits) <= 10_000_000:
        return account["id"]
    await request.app.state.credits.add(account["id"], int(credits), kind="purchase",
                                        detail=f"credit pack {credits} ({obj.get('id', '')})")  # fmt: skip
    await audit(request, SERVICE, "billing.credits_purchased", account["id"],
                details={"credits": int(credits), "event": event["id"]})  # fmt: skip
    await request.app.state.mailer.notify(account, "credits_added", str(obj.get("id") or event["id"]),
                                          credits=int(credits))  # fmt: skip
    return str(account["id"])


async def _subscription(request: Request, account: dict[str, Any], sub: dict[str, Any], event: dict[str, Any]) -> str:
    settings = request.app.state.settings
    status = stripe.STATUS.get(str(sub.get("status")), "past_due")
    changes: dict[str, Any] = {"status": status}
    plan = stripe.plan_for_price(settings, stripe.subscription_price(sub))
    if plan:
        changes["plan"] = plan
    until = stripe.period_end(sub)
    now = datetime.now(timezone.utc)
    if status == "past_due":
        until = max(until or now, now + GRACE)  # keep working while the payment is retried
    elif status == "cancelled":
        until = min(until or now, now)
    if until:
        changes["valid_until"] = until
    repo = request.app.state.subscribers
    updated = await repo.update(account["id"], **changes)
    if plan and plan != account["plan"]:
        await request.app.state.credits.upgrade_allowance(account["id"], account["plan"], plan)
    await audit(request, SERVICE, "billing.subscription", account["id"],
                details={"event": event["type"], "status": status, "plan": (updated or account)["plan"],
                         "valid_until": until.isoformat() if until else None})  # fmt: skip
    await _tell(request, account, updated or account, sub)
    return str(account["id"])


async def _tell(request: Request, before: dict[str, Any], after: dict[str, Any], sub: dict[str, Any]) -> None:
    """The email this change deserves, if any (each sent once, however often Stripe repeats itself)."""
    mailer = request.app.state.mailer
    sid, period = str(sub.get("id") or "sub"), (after.get("valid_until") or "")[:10]
    was_paying = before["status"] in ("active", "past_due") and before["plan"] != "trial"
    if after["status"] == "cancelled":
        if was_paying or before["status"] == "trialing":
            await mailer.notify(after, "subscription_ended", sid)
        return
    if after["status"] == "past_due" and before["status"] != "past_due":
        await mailer.notify(after, "payment_failed", f"{sid}:{period}")
    elif after["status"] == "active" and before["status"] == "past_due":
        await mailer.notify(after, "payment_recovered", f"{sid}:{period}")
    elif after["status"] in ("active", "trialing") and not was_paying:
        await mailer.notify(after, "subscription_started", sid)
    elif after["plan"] != before["plan"] and was_paying:
        await mailer.notify(after, "plan_changed", f"{sid}:{after['plan']}:{period}")
    if sub.get("cancel_at_period_end") and after["status"] in ("active", "trialing", "past_due"):
        await mailer.notify(after, "cancellation_scheduled", f"{sid}:{period}")
