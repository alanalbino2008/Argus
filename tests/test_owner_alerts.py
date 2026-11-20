"""Owner alerts: problems (and their fixes) emailed once, business events, the daily summary."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from argus.api import owner_console_routes
from argus.api.account_routes import SERVICE
from tests.test_billing import fake_stripe  # noqa: F401 - the stand-in for Stripe
from tests.test_owner_console import OWNER, clock, console, set_up, sign_in  # noqa: F401 - fixtures

NOON = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def checks(monkeypatch):
    """The health checks, as the test sets them."""
    current = {"Database": ("ok", "answering"), "Email": ("ok", "sending")}

    async def health(_app):
        return [{"name": n, "status": s, "detail": d, "fix": "Do this" if s == "error" else ""}
                for n, (s, d) in current.items()]  # fmt: skip

    monkeypatch.setattr(owner_console_routes, "health", health)
    return current


def tick(c, now):
    return c.portal.call(c.app.state.owner_alerts.tick, now)


def record(c, action, resource, details=None):
    c.portal.call(lambda: c.app.state.audit.record(SERVICE, action, resource, details=details))


def mail(c):
    return [(m["Subject"], m.get_body(("plain",)).get_content()) for m in c.outbox]


def test_problems_and_fixes(console, checks):  # noqa: F811
    c = console
    assert tick(c, NOON) == []  # all well: nothing to say
    checks["Email"] = ("error", "The mail server refuses the password")
    sent = tick(c, NOON + timedelta(minutes=5))
    assert [s["subject"] for s in sent] == ["Problem: Email"]
    subject, body = mail(c)[-1]
    assert subject == "[Argus owner] Problem: Email" and "refuses the password" in body and "Do this" in body
    assert c.outbox[-1]["To"] == OWNER and "If this wasn't you" not in body
    assert tick(c, NOON + timedelta(minutes=10)) == []  # said once, not every few minutes
    checks["Database"] = ("error", "Not answering")
    assert [s["subject"] for s in tick(c, NOON + timedelta(minutes=15))] == ["Problem: Database"]
    reminder = tick(c, NOON + timedelta(hours=25))
    assert reminder and reminder[0]["subject"] == "2 problems need attention"  # a daily reminder while it lasts
    checks["Email"] = ("ok", "sending")
    checks["Database"] = ("warn", "slow")
    fixed = tick(c, NOON + timedelta(hours=26))
    assert [s["subject"] for s in fixed] == ["Fixed: Database, Email"]
    checks["Email"] = ("warn", "20 waiting")
    assert tick(c, NOON + timedelta(hours=27)) == []  # warnings stay in the console
    history = c.app.state.owner_alerts
    assert c.portal.call(history.history)[0]["subject"] == "Fixed: Database, Email"


def test_payments_and_new_customers(console, checks):  # noqa: F811
    c = console
    record(c, "billing.dispute_opened", "acc-old", {"reason": "fraudulent"})
    assert tick(c, NOON) == []  # the first round starts from now: nothing from before
    made = c.portal.call(lambda: c.app.state.subscribers.create(email="jane@agency.example", name="Jane",
                                                                  password_hash="x", plan="trial", status="trialing",
                                                                  valid_until=NOON + timedelta(days=14)))  # fmt: skip
    acc = made["id"]
    for action, details in (
        ("billing.dispute_opened", {"reason": "fraudulent"}),
        ("billing.subscription", {"status": "past_due", "plan": "professional"}),
        ("billing.subscription", {"status": "past_due", "plan": "professional"}),  # Stripe repeats itself
        ("billing.subscription", {"status": "active", "plan": "professional"}),
        ("billing.subscription", {"status": "active", "plan": "professional"}),  # renewals aren't new customers
        ("account.signup", {}),
    ):
        record(c, action, acc, details)
    subjects = [s["subject"] for s in tick(c, NOON + timedelta(minutes=5))]
    assert subjects == ["Payment disputed by jane@agency.example", "Payment failed: jane@agency.example",
                        "New customer: jane@agency.example (professional)"]  # fmt: skip
    record(c, "billing.subscription", acc, {"status": "past_due", "plan": "x"})
    assert tick(c, NOON + timedelta(days=1)) == []  # one failed-payment email per customer every few days
    record(c, "billing.subscription", acc, {"status": "past_due", "plan": "x"})
    assert [s["subject"] for s in tick(c, NOON + timedelta(days=4))] == ["Payment failed: jane@agency.example"]

    settings = c.app.state.settings
    settings.owner_alert_payments = False
    record(c, "billing.dispute_opened", acc, {})
    assert tick(c, NOON + timedelta(days=5)) == []
    settings.owner_alert_payments = True
    settings.owner_alerts_enabled = False
    record(c, "billing.dispute_lost", acc, {})
    assert tick(c, NOON + timedelta(days=6)) == []
    settings.owner_alerts_enabled = True
    assert [s["subject"] for s in tick(c, NOON + timedelta(days=6))] == ["Dispute lost: jane@agency.example"]


def test_the_daily_summary(console, checks):  # noqa: F811
    c = console
    settings = c.app.state.settings
    settings.owner_daily_summary, settings.owner_summary_hour = True, 9
    tick(c, NOON.replace(hour=8))
    record(c, "account.signup", "a1")
    checks["Backups"] = ("warn", "No backup for 3 days")
    assert tick(c, NOON.replace(hour=8, minute=30)) == []  # not before the chosen hour
    sent = tick(c, NOON.replace(hour=9, minute=2))
    assert sent[0]["subject"] == "Daily summary, 2026-11-20"
    body = "\n".join(sent[0]["lines"])
    assert "New accounts: 1" in body and "1 thing(s) to check" in body and "No backup for 3 days" in body
    assert tick(c, NOON.replace(hour=15)) == []  # once a day


def test_in_the_owner_console(console, clock, checks):  # noqa: F811
    c = console
    secret, _codes = set_up(c, clock)
    sign_in(c, clock, secret)
    view = c.get("/api/owner/console/alerts").json()
    assert view["enabled"] and view["to"] == OWNER and view["email_ready"] and view["history"] == []
    r = c.post("/api/owner/console/alerts/test")
    assert r.status_code == 200 and r.json()["detail"] == f"Sent to {OWNER}"
    assert mail(c)[-1][0] == "[Argus owner] Test alert"
    sections = {s["section"] for s in c.get("/api/owner/console/config").json()["settings"]}
    assert "alerts" in sections


def test_backups_and_disk_in_the_health_checks(console, clock):  # noqa: F811
    c = console
    secret, _codes = set_up(c, clock)
    sign_in(c, clock, secret)
    names = {h["name"]: h for h in c.get("/api/owner/console/overview").json()["health"]}
    assert "Backups" in names
    if c.app.state.backups.available:
        assert names["Backups"]["status"] == "warn" and "Disk space" in names
    else:
        assert names["Backups"]["status"] == "ok" and "provider" in names["Backups"]["detail"]
