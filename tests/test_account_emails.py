"""Emails to account holders: welcome, payments, reminders (with unsubscribe), password resets."""

from __future__ import annotations

import asyncio
import smtplib
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

import pytest

from argus.accounts import emails
from tests import test_billing
from tests.test_accounts import GOOD_PHRASE, PRIVATE, sign_in
from tests.test_billing import SECRET, deliver, event, subscription

fake_stripe = test_billing.fake_stripe  # the same stand-in for Stripe


@pytest.fixture
def service(make_client, fake_stripe, monkeypatch):
    from argus.api import account_routes, billing_routes
    from argus.security.ratelimit import SlidingWindowLimiter

    for name, limit in (("_per_ip", 500), ("_signups", 50), ("_resets_per_ip", 50)):
        monkeypatch.setattr(account_routes, name, SlidingWindowLimiter(limit=limit, window=3600))
    monkeypatch.setattr(billing_routes, "_prices", {})
    c = make_client(account_service_enabled="true", licence_signing_key=PRIVATE, account_signup_enabled="true",
                    public_url="http://testserver", monitors_enabled="false", stripe_secret_key="sk_test_argus",
                    stripe_webhook_secret=SECRET, stripe_api_url=fake_stripe.url,
                    stripe_price_personal="price_personal", stripe_price_professional="price_pro",
                    stripe_credit_packs="500=price_c500", smtp_host="smtp.test", smtp_from="argus@argus.test",
                    support_email="help@argus.test")  # fmt: skip
    outbox: list = []
    monkeypatch.setattr(c.app.state.mailer.transport, "_send_mail", outbox.append)
    c.outbox = outbox
    return c


def flush(c, timeout: float = 10.0):
    """Send whatever is due now, and wait until every email being sent has been delivered.

    The server's own mail loop also sends: queuing an email wakes it, so an email can be claimed
    and mid-send there (in a worker thread) when this runs. send_due then skips it as taken, so
    counting the outbox straight away would race that delivery (seen on PostgreSQL in CI).
    """
    from sqlalchemy import func, select

    from argus.storage.db import AccountEmailRow

    async def in_flight() -> int:
        # Claimed (attempts > 0), not yet resolved, and not waiting for a retry after an error.
        async with c.app.state.db.session() as s:
            query = select(func.count()).where(
                AccountEmailRow.status == "pending", AccountEmailRow.attempts > 0, AccountEmailRow.last_error == ""
            )
            return int(await s.scalar(query) or 0)

    async def settle() -> None:
        deadline = time.monotonic() + timeout
        while True:
            await c.app.state.mailer.send_due()
            if not await in_flight() or time.monotonic() > deadline:
                return
            await asyncio.sleep(0.05)

    c.portal.call(settle)


def signup(c, email="jane@example.org", name="Jane"):
    created = c.post("/api/accounts/signup", json={"email": email, "password": GOOD_PHRASE, "name": name})
    assert created.status_code == 201
    return created.json()


def kinds(c, account_id):
    return [m["subject"] for m in reversed(c.get(f"/api/accounts/{account_id}").json()["emails"])]


def test_the_wording():
    account = {"id": "acc_1", "name": "<b>Jane</b>", "plan": "personal", "plan_label": "Personal",
               "valid_until": "2026-12-03T10:00:00+00:00"}  # fmt: skip
    for kind in ("welcome", "trial_ending", "trial_ended", "subscription_started", "plan_changed", "payment_failed",
                 "payment_recovered", "cancellation_scheduled", "subscription_ended", "password_changed"):  # fmt: skip
        subject, text, html = emails.render(kind, account, support="help@argus.test")
        assert subject and "Hello <b>Jane</b>," in text and "&lt;b&gt;Jane&lt;/b&gt;" in html and "<b>Jane" not in html
        assert "help@argus.test" in text
    assert "3 December 2026" in emails.render("trial_ending", account)[1]
    _s, text, html = emails.render("trial_ending", account, unsubscribe="https://a.test/u?x=1&y=2")
    assert "Unsubscribe: https://a.test/u?x=1&y=2" in text and 'href="https://a.test/u?x=1&amp;y=2"' in html
    _s, text, html = emails.render(
        "password_reset", account, link="https://a.test/reset-password#token=abc", minutes=60
    )
    assert "https://a.test/reset-password#token=abc" in text and "Choose a new password" in html
    assert emails.render("credits_added", account, credits=500)[0] == "500 Argus credits added"
    token = emails.unsubscribe_token("key", "acc_1")
    assert emails.unsubscribe_ok("key", "acc_1", token) and not emails.unsubscribe_ok("key", "acc_2", token)
    with pytest.raises(ValueError, match="Unknown email"):
        emails.render("nonsense", account)


def test_welcome_and_payment_emails(service, fake_stripe):
    c = service
    acc = signup(c)["id"]
    flush(c)
    welcome = c.outbox[0]
    assert welcome["To"] == "jane@example.org" and welcome["Subject"] == "Welcome to Argus"
    assert welcome["Reply-To"] == "help@argus.test" and welcome["Auto-Submitted"] == "auto-generated"
    assert "free trial until" in welcome.get_body(("plain",)).get_content()
    assert welcome.get_body(("html",)) is not None and "List-Unsubscribe" not in welcome  # not a reminder

    sub = subscription(account_id=acc)
    fake_stripe.subscriptions["sub_1"] = sub
    deliver(c, event("customer.subscription.created", sub))
    deliver(c, event("customer.subscription.updated", sub))  # Stripe repeating itself: no second email
    fake_stripe.subscriptions["sub_1"] = subscription(status="past_due", account_id=acc)
    deliver(c, event("customer.subscription.updated", fake_stripe.subscriptions["sub_1"]))
    fake_stripe.subscriptions["sub_1"] = subscription(account_id=acc, cancel_at_period_end=True)
    deliver(c, event("customer.subscription.updated", fake_stripe.subscriptions["sub_1"]))
    ended = subscription(status="canceled", account_id=acc, ended_at=int(datetime.now(timezone.utc).timestamp()))
    fake_stripe.subscriptions["sub_1"] = ended
    deliver(c, event("customer.subscription.deleted", ended))
    paid = {"id": "cs_9", "mode": "payment", "payment_status": "paid", "customer": "cus_1",
            "metadata": {"account_id": acc, "credits": "500"}}  # fmt: skip
    deliver(c, event("checkout.session.completed", paid))
    flush(c)
    assert kinds(c, acc) == [
        "Welcome to Argus", "Thank you: your Argus Personal plan is active",
        "Action needed: your Argus payment didn't go through", "Your Argus payment went through",
        "Your Argus subscription is cancelled", "Your Argus subscription has ended", "500 Argus credits added",
    ]  # fmt: skip
    assert len(c.outbox) == 7
    detail = c.get(f"/api/accounts/{acc}").json()["emails"]
    assert all(m["status"] == "sent" for m in detail) and "text" not in detail[0]


def test_trial_reminders_and_unsubscribing(service):
    c = service
    acc = signup(c)["id"]
    mailer = c.app.state.mailer
    soon = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
    c.patch(f"/api/accounts/{acc}", json={"valid_until": soon})
    assert c.portal.call(mailer.sweep) == 1
    assert c.portal.call(mailer.sweep) == 0  # once per trial
    flush(c)
    reminder = c.outbox[-1]
    assert reminder["Subject"] == "Your Argus trial ends soon"
    link = reminder["List-Unsubscribe"].strip("<>")
    assert link in reminder.get_body(("plain",)).get_content()
    query = parse_qs(urlsplit(link).query)
    assert c.get("/api/accounts/emails/unsubscribe", params={"a": acc, "t": "0" * 32}).status_code == 400
    page = c.get("/api/accounts/emails/unsubscribe", params={"a": query["a"][0], "t": query["t"][0]})
    assert page.status_code == 200 and "get reminder emails any more" in page.text
    assert c.get(f"/api/accounts/{acc}").json()["reminder_emails"] is False
    c.patch(f"/api/accounts/{acc}", json={"valid_until": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()})
    assert c.portal.call(mailer.sweep) == 0  # unsubscribed: no "trial ended" reminder
    other = signup(c, "sam@example.org", "Sam")["id"]
    c.patch(
        f"/api/accounts/{other}", json={"valid_until": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()}
    )
    assert c.portal.call(mailer.sweep) == 1
    one_click = parse_qs(urlsplit(mailer.unsubscribe_url(other)).query)
    assert c.post("/api/accounts/emails/unsubscribe", params={"a": other, "t": one_click["t"][0]}).status_code == 200
    assert "account.reminders_off" in [e["action"] for e in c.get("/api/audit?limit=50").json()]


def test_forgotten_password(service):
    c = service
    acc = signup(c)["id"]
    old = sign_in(c).json()["licence"]
    flush(c)
    sent_before = len(c.outbox)
    same = "If an account uses that email"
    nobody = c.post("/api/accounts/password-reset", json={"email": "nobody@example.org"})
    assert nobody.status_code == 202 and same in nobody.json()["detail"]
    asked = c.post("/api/accounts/password-reset", json={"email": "Jane@Example.org"})
    assert asked.status_code == 202 and same in asked.json()["detail"]
    flush(c)
    assert len(c.outbox) == sent_before + 1  # only the real account got one
    body = c.outbox[-1].get_body(("plain",)).get_content()
    link = next(line for line in body.splitlines() if "/reset-password#token=" in line)
    assert link.startswith("http://testserver/reset-password#token=")
    token = link.split("#token=", 1)[1]
    assert c.get(f"/api/accounts/{acc}").json()["emails"][0]["status"] == "sent"  # the link isn't kept

    page = c.get("/reset-password")
    assert (
        page.status_code == 200 and "Reset your password" in page.text and page.headers["cache-control"] == "no-store"
    )
    weak = c.post("/api/accounts/password-reset/confirm", json={"token": token, "password": "short"})
    assert weak.status_code == 422  # the link still works after a weak try
    new = "a brand new pass phrase"
    done = c.post("/api/accounts/password-reset/confirm", json={"token": token, "password": new})
    assert done.status_code == 200
    again = c.post("/api/accounts/password-reset/confirm", json={"token": token, "password": "another pass phrase"})
    assert again.status_code == 400  # single use
    assert c.post("/api/accounts/refresh", json={"licence": old}).status_code == 401  # every computer signed out
    assert sign_in(c).status_code == 401 and sign_in(c, password=new).status_code == 200
    flush(c)
    assert c.outbox[-1]["Subject"] == "Your Argus password was changed"
    for _ in range(4):
        c.post("/api/accounts/password-reset", json={"email": "jane@example.org"})
    flush(c)
    resets = [m for m in c.outbox if m["Subject"] == "Reset your Argus password"]
    assert len(resets) == 3  # at most three links an hour: no flooding the inbox
    actions = [e["action"] for e in c.get("/api/audit?limit=100").json()]
    assert {"account.password_reset_requested", "account.password_reset"} <= set(actions)


def test_a_mail_server_that_is_down(service, monkeypatch):
    c = service
    transport = c.app.state.mailer.transport

    def down(message):
        raise ConnectionRefusedError

    monkeypatch.setattr(transport, "_send_mail", down)
    acc = signup(c)["id"]
    flush(c)
    first = c.get(f"/api/accounts/{acc}").json()["emails"][0]
    assert first["status"] == "pending" and first["attempts"] == 1 and "mail server" in first["error"]

    def refuse(message):
        raise smtplib.SMTPRecipientsRefused({"jane@example.org": (550, b"no such user")})

    monkeypatch.setattr(transport, "_send_mail", refuse)
    c.portal.call(c.app.state.account_mail.due)  # not due yet: waits a minute before retrying
    later = datetime.now(timezone.utc) + timedelta(minutes=2)
    due = c.portal.call(c.app.state.account_mail.due, 20, later)
    assert [d["id"] for d in due] == [first["id"]]


def test_without_email_configured(make_client, monkeypatch):
    from argus.api import account_routes
    from argus.security.ratelimit import SlidingWindowLimiter

    monkeypatch.setattr(account_routes, "_signups", SlidingWindowLimiter(limit=50, window=3600))
    c = make_client(account_service_enabled="true", licence_signing_key=PRIVATE, account_signup_enabled="true",
                    public_url="http://testserver", monitors_enabled="false")  # fmt: skip
    acc = signup(c)["id"]
    assert c.get(f"/api/accounts/{acc}").json()["emails"] == []
    r = c.post("/api/accounts/password-reset", json={"email": "jane@example.org"})
    assert r.status_code == 503 and "contact support" in r.json()["detail"]
