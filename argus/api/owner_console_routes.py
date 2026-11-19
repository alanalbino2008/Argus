"""The owner console: health, settings, plan allowances, admin keys and the activity log.

Every endpoint needs the owner's full session (password and authenticator code). Every change
also needs a code given within the last 10 minutes, and is recorded in the audit log (secrets
never are: only which setting changed).
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import formatdate
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import text

from argus import __version__
from argus.accounts import business
from argus.accounts import stripe_billing as stripe
from argus.accounts.owner import box as owner_box
from argus.api.deps import audit
from argus.api.owner_routes import OWNER, require_owner
from argus.core import runtime_config

router = APIRouter(prefix="/api/owner/console", tags=["owner"])
BACKGROUND = {"account-emails": "Customer emails", "owner-config-sync": "Settings sync",
              "notification-dispatcher": "Notifications", "monitor-scheduler": "Scheduled scans"}  # fmt: skip


class ConfigChange(BaseModel):
    values: dict[str, Any] = Field(default_factory=dict)  # a value, or null to go back to the deployment's


class PlansChange(BaseModel):
    plans: dict[str, dict[str, Any]]


class TestEmail(BaseModel):
    to: str = Field(default="", max_length=320)


# ---------------------------------------------------------------------------- overview and health
def _check(name: str, status: str, detail: str, fix: str = "") -> dict[str, str]:
    return {"name": name, "status": status, "detail": detail, "fix": fix}


async def _health(request: Request) -> list[dict[str, str]]:
    app, s = request.app, request.app.state.settings
    checks = []
    started = time.monotonic()
    try:
        async with app.state.db.session() as session:
            await session.execute(text("SELECT 1"))
        engine = "PostgreSQL" if "postgres" in (s.database_url or "") else "SQLite"
        checks.append(_check("Database", "ok", f"{engine}, answering in {int((time.monotonic() - started) * 1000)} ms"))
    except Exception as exc:  # noqa: BLE001 - shown, not raised
        checks.append(_check("Database", "error", f"Not answering ({type(exc).__name__})", "Check the database server"))
    public = (s.public_url or "").strip()
    checks.append(_check("Public address", "ok" if public.startswith("https://") else "warn" if public else "error",
                         public or "Not set", "" if public.startswith("https://") else
                         "Set ARGUS_PUBLIC_URL to this server's https:// address: licences and email links use it"))  # fmt: skip
    if s.account_service_enabled:
        checks.append(_check("Account service", "ok" if s.licence_signing_key else "error",
                             "Signing licences" if s.licence_signing_key else "No licence signing key",
                             "" if s.licence_signing_key else "Set ARGUS_LICENCE_SIGNING_KEY"))  # fmt: skip
    else:
        checks.append(_check("Account service", "off", "This server doesn't run the Argus account service",
                             "Set ARGUS_ACCOUNT_SERVICE_ENABLED=true on the server that sells Argus"))  # fmt: skip
    checks.append(_check("Encryption", "ok" if owner_box(s).available else "error",
                         "Secrets are stored encrypted" if owner_box(s).available else "No encryption key"))  # fmt: skip
    # payments
    if stripe.enabled(s):
        mode = "test mode (no real money)" if s.stripe_secret_key and s.stripe_secret_key.get_secret_value().startswith(
            "sk_test_") else "live"  # fmt: skip
        plans = stripe.plan_prices(s)
        checks.append(_check("Payments", "ok" if plans else "warn", f"Stripe, {mode}; {len(plans)} plan(s) on sale",
                             "" if plans else "Add your plans' price ids under Payments"))  # fmt: skip
        hook = await app.state.subscribers.last_billing_event()
        if not s.stripe_webhook_secret:
            checks.append(_check("Stripe webhook", "error", "No signing secret: payments won't switch plans on",
                                 "Add the webhook signing secret under Payments"))  # fmt: skip
        else:
            checks.append(_check("Stripe webhook", "ok" if hook else "warn",
                                 f"Last event: {hook['type']} at {hook['at'][:16].replace('T', ' ')}" if hook else
                                 "No event received yet", "" if hook else
                                 f"In Stripe, add the endpoint {public or 'https://<this server>'}/api/billing/webhook"))  # fmt: skip
    else:
        checks.append(
            _check("Payments", "off", "Not set up: customers can't pay yet", "Add your Stripe keys under Payments")
        )
    # email
    if s.smtp_host:
        counts = await app.state.account_mail.counts()
        status = "error" if counts["failed"] else "warn" if counts["pending"] > 20 else "ok"
        checks.append(_check("Email", status, f"{s.smtp_host}: {counts['sent']} sent, {counts['pending']} waiting, "
                                              f"{counts['failed']} failed", "Use Send test email to check it"))  # fmt: skip
    else:
        checks.append(_check("Email", "off", "Not set up: no welcome, payment or password emails",
                             "Add your mail server under Email"))  # fmt: skip
    running = {t.get_name() for t in asyncio.all_tasks() if not t.done()}
    for task, label in BACKGROUND.items():
        if task == "account-emails" and not s.account_service_enabled:
            continue
        if task == "monitor-scheduler" and not s.monitors_enabled:
            continue
        if task == "notification-dispatcher" and not s.notifications_enabled:
            continue
        checks.append(_check(f"Background: {label}", "ok" if task in running else "error",
                             "Running" if task in running else "Stopped", "" if task in running else "Restart the server"))  # fmt: skip
    return checks


@router.get("/overview")
async def console_overview(request: Request):
    """Health checks, the business at a glance, and recent activity."""
    await require_owner(request)
    s = request.app.state.settings
    summary = None
    if s.account_service_enabled:
        accounts = await request.app.state.subscribers.overview()
        ledger = await request.app.state.credits.since(datetime.now(timezone.utc) - timedelta(days=30))
        summary = business.summary(accounts, ledger, plan_prices={}, pack_prices={}, days=30, trial_days=s.trial_days,
                                   payments=await request.app.state.subscribers.payments(limit=10_000))  # fmt: skip
    return {"version": __version__, "health": await _health(request),
            "business": {"customers": summary["customers"], "attention": len(summary["attention"])} if summary else None,
            "activity": await request.app.state.audit.list(limit=15)}  # fmt: skip


@router.post("/test-email")
async def console_test_email(request: Request, body: TestEmail | None = None):
    """Send a test email (to you, unless another address is given)."""
    session = await require_owner(request)
    s = request.app.state.settings
    owner = await request.app.state.owner.get() or {}
    to = (body.to.strip() if body else "") or owner.get("email", "")
    if not s.smtp_host:
        raise HTTPException(status_code=409, detail="Set up the mail server first")
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = s.account_email_from or s.smtp_from, to, "Argus test email"
    msg["Date"] = formatdate(localtime=False)
    msg.set_content("This is a test from your Argus owner console. If you can read it, email works.")
    result = await request.app.state.mailer.transport.send_email(msg)
    await audit(request, OWNER, "owner.test_email", to, "success" if result.ok else "failure",
                {"session": session["id"]})  # fmt: skip
    if not result.ok:
        raise HTTPException(status_code=502, detail=f"Not sent: {result.error}")
    return {"sent": True, "to": to}


async def _price_exists(settings: Any, price: str) -> bool:
    try:
        await stripe.call(settings, "GET", f"/v1/prices/{price}")
    except stripe.BillingError:
        return False
    return True


@router.post("/test-stripe")
async def console_test_stripe(request: Request):
    """Check the Stripe key works (reads your prices; changes nothing)."""
    await require_owner(request)
    s = request.app.state.settings
    try:
        await stripe.call(s, "GET", "/v1/prices", {"limit": 1})
    except stripe.BillingError as exc:
        raise HTTPException(status_code=502, detail=exc.detail) from exc
    prices = stripe.plan_prices(s)
    found: list[str] = []
    missing: list[str] = []
    for plan, price in prices.items():
        (found if await _price_exists(s, price) else missing).append(plan)
    return {"ok": not missing, "plans_found": found, "plans_missing": missing}


# ---------------------------------------------------------------------------- settings
async def _stored(request: Request) -> dict[str, Any] | None:
    return await request.app.state.app_state.get(runtime_config.STATE_KEY)


@router.get("/config")
async def console_config(request: Request):
    await require_owner(request)
    s = request.app.state.settings
    return {"sections": runtime_config.SECTIONS, "settings": runtime_config.describe(s, await _stored(request)),
            "encryption": owner_box(s).available}  # fmt: skip


@router.put("/config")
async def console_config_save(body: ConfigChange, request: Request):
    """Save settings; they apply at once. A value of null goes back to the deployment's."""
    await require_owner(request, fresh=True)
    s = request.app.state.settings
    box = owner_box(s)
    try:
        stored = runtime_config.updated(await _stored(request), body.values, box)
    except runtime_config.ConfigError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if body.values.get("admin_keys_allowed") is False and await request.app.state.owner.get() is None:
        raise HTTPException(status_code=409, detail="Set up the owner first")
    await request.app.state.app_state.set(runtime_config.STATE_KEY, stored)
    runtime_config.apply(s, stored, box)
    await audit(request, OWNER, "owner.config", "settings",
                details={"changed": sorted(body.values), "reset": sorted(k for k, v in body.values.items() if v is None)})  # fmt: skip
    return {"settings": runtime_config.describe(s, stored)}


@router.get("/plans")
async def console_plans(request: Request):
    await require_owner(request)
    return {"plans": runtime_config.plans_view()}


@router.put("/plans")
async def console_plans_save(body: PlansChange, request: Request):
    """Change each plan's monthly credits and computers (applies at once; licences at their next renewal)."""
    await require_owner(request, fresh=True)
    s = request.app.state.settings
    try:
        stored = runtime_config.updated_plans(await _stored(request), body.plans)
    except runtime_config.ConfigError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    await request.app.state.app_state.set(runtime_config.STATE_KEY, stored)
    runtime_config.apply(s, stored, owner_box(s))
    await audit(request, OWNER, "owner.plans", "plans", details={"plans": body.plans})
    return {"plans": runtime_config.plans_view()}


# ---------------------------------------------------------------------------- admin keys and the log
@router.get("/keys")
async def console_keys(request: Request):
    """Every API key on the server (only their names and first characters)."""
    await require_owner(request)
    return {
        "keys": await request.app.state.keys.list(),
        "admin_keys_allowed": request.app.state.settings.admin_keys_allowed,
    }


@router.post("/keys/{key_id}/revoke")
async def console_revoke_key(key_id: str, request: Request):
    await require_owner(request, fresh=True)
    if not await request.app.state.keys.revoke(key_id):
        raise HTTPException(status_code=404, detail="No such key, or already revoked")
    await audit(request, OWNER, "key.revoke", key_id)
    return {"revoked": True}


@router.get("/activity")
async def console_activity(request: Request, limit: int = Query(100, ge=1, le=500),
                           action: str = Query("", max_length=64)):  # fmt: skip
    await require_owner(request)
    return {"events": await request.app.state.audit.list(limit=limit, action=action or None)}
