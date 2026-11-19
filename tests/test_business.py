"""The operator's business dashboard: customers, revenue, sign-ups, credits and attention."""

from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone

from argus.accounts import business
from tests import test_billing
from tests.test_billing import account, deliver, event, subscription

fake_stripe, service = test_billing.fake_stripe, test_billing.service  # the same fixtures

NOW = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)


def acc(i, plan="personal", status="active", *, created=30, until=20, locked=None, allowance=(None, 0, 0)):
    month, left, bought = allowance
    return {"id": f"acc_{i}", "email": f"p{i}@example.org", "name": "", "plan": plan, "status": status,
            "valid_until": (NOW + timedelta(days=until)).isoformat(), "until": NOW + timedelta(days=until),
            "created": NOW - timedelta(days=created), "created_at": (NOW - timedelta(days=created)).isoformat(),
            "locked_until": locked, "allowance_month": month or "", "allowance_remaining": left,
            "purchased_credits": bought, "billing_reference": ""}  # fmt: skip


def test_the_figures():
    accounts = [
        acc(1),
        acc(2),
        acc(3, "professional"),
        acc(4, "personal", "past_due"),
        acc(5, "trial", "trialing", created=2, until=2),  # trial ends in two days
        acc(6, "trial", "trialing", created=40, until=-3),  # trial ended without paying
        acc(7, "personal", "cancelled", until=-1),
        acc(8, "trial", "trialing", created=1, until=13, locked=(NOW + timedelta(minutes=5)).isoformat()),
        acc(9, "professional", allowance=("2026-11", 0, 0)),  # paying, out of credits
    ]
    at = NOW - timedelta(days=2)
    ledger = [
        {"account_id": "acc_1", "kind": "usage", "delta": -5, "detail": "companies_house/officers", "at": at},
        {"account_id": "acc_1", "kind": "refund", "delta": 1, "detail": "companies_house/search failed", "at": at},
        {"account_id": "acc_3", "kind": "usage", "delta": -20, "detail": "ai/report", "at": at},
        {"account_id": "acc_3", "kind": "purchase", "delta": 500, "detail": "credit pack 500 (cs_1)", "at": at},
        {"account_id": "acc_2", "kind": "purchase", "delta": 500, "detail": "credit pack 500 (cs_2)", "at": at},
        {"account_id": "acc_2", "kind": "usage", "delta": -9, "detail": "web_search/search", "at": NOW - timedelta(days=60)},
        {"account_id": "acc_2", "kind": "allowance", "delta": 500, "detail": "monthly allowance", "at": at},
    ]  # fmt: skip
    prices = {"personal": {"amount": 1500, "currency": "GBP", "interval": "month"},
              "professional": {"amount": 46800, "currency": "GBP", "interval": "year"}}  # fmt: skip
    out = business.summary(accounts, ledger, plan_prices=prices, pack_prices={500: {"amount": 1000, "currency": "GBP"}},
                           days=30, trial_days=14, now=NOW)  # fmt: skip
    c = out["customers"]
    assert (c["accounts"], c["paying"], c["trialing"], c["past_due"], c["cancelled"]) == (9, 5, 3, 1, 1)
    assert c["plans"] == {"personal": 3, "professional": 2}
    # 3 x 15.00 a month + 2 x (468.00 a year = 39.00 a month)
    assert out["mrr"] == {"amount": 3 * 1500 + 2 * 3900, "currency": "GBP", "complete": True,
                          "by_plan": [{"plan": "personal", "customers": 3, "seats": 3, "monthly": 4500, "currency": "GBP"},
                                      {"plan": "professional", "customers": 2, "seats": 2, "monthly": 7800,
                                       "currency": "GBP"}]}  # fmt: skip
    credits = out["credits"]
    assert credits["by_source"] == [{"source": "ai", "label": "AI analyst", "credits": 20},
                                    {"source": "companies_house", "label": "UK Companies House", "credits": 4}]  # fmt: skip
    assert credits["used"] == 24 and credits["bought"] == 1000  # the 60-day-old search is outside the period
    assert credits["pack_sales"] == [{"credits": 500, "sold": 2, "currency": "GBP", "revenue": 2000}]
    assert [t["id"] for t in credits["top_accounts"]] == ["acc_3", "acc_1"]
    why = {a["id"]: a["why"] for a in out["attention"]}
    assert why == {"acc_4": "payment failing", "acc_5": "trial ends soon", "acc_6": "trial ended without paying",
                   "acc_8": "locked after wrong passwords", "acc_9": "out of credits"}  # fmt: skip
    weeks = out["signups"]["weeks"]
    assert len(weeks) == 12 and sum(w["accounts"] for w in weeks) == 9  # all joined within 12 weeks
    assert out["signups"]["trials_finished"] == 7 and out["signups"]["converted"] == 6
    team = [acc(20, "business"), acc(21, "trial", "trialing", created=1, until=-1)]
    team[0]["seats"], team[1]["team_id"] = 4, "acc_20"
    with_team = business.summary(accounts + team, [], plan_prices={**prices, "business": {"amount": 1200, "currency": "GBP",
                                 "interval": "month"}}, pack_prices={}, days=30, trial_days=14, now=NOW)  # fmt: skip
    assert with_team["mrr"]["amount"] == 3 * 1500 + 2 * 3900 + 4 * 1200  # every team seat counts
    assert with_team["customers"]["team_members"] == 1 and with_team["customers"]["team_seats"] == 4
    assert "acc_21" not in {a["id"] for a in with_team["attention"]}  # a member's own trial doesn't matter
    no_prices = business.summary(accounts, [], plan_prices={}, pack_prices={}, days=30, trial_days=14, now=NOW)
    assert no_prices["mrr"]["complete"] is False and no_prices["mrr"]["currency"] is None


def test_the_dashboard_endpoints(service, fake_stripe):
    c = service
    licence, acc_id = account(c)
    fake_stripe.subscriptions["sub_1"] = subscription(account_id=acc_id)
    deliver(c, event("customer.subscription.created", fake_stripe.subscriptions["sub_1"]))
    c.post("/api/accounts/signup", json={"email": "=cmd|evil@example.org", "password": "correct horse battery"})
    c.post("/api/connect/balance", json={"licence": licence})
    c.post(f"/api/accounts/{acc_id}/credits", json={"amount": 25, "kind": "adjustment", "detail": "goodwill"})

    summary = c.get("/api/business/summary?days=30").json()
    assert summary["payments_enabled"] and summary["customers"]["paying"] == 1
    assert summary["mrr"]["amount"] == 1500 and summary["mrr"]["currency"] == "GBP"
    assert c.get("/api/business/summary?days=3").status_code == 422

    found = c.get("/api/business/accounts?q=jane").json()
    assert found["total"] == 1 and found["accounts"][0]["id"] == acc_id
    assert "password_hash" not in str(found) and "created" not in found["accounts"][0]
    assert c.get("/api/business/accounts?status=trialing").json()["total"] == 1
    assert c.get("/api/business/accounts?plan=personal&status=active").json()["total"] == 1
    assert c.get("/api/business/accounts?status=bogus").status_code == 422

    sheet = c.get("/api/business/accounts.csv")
    assert sheet.status_code == 200 and sheet.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(sheet.text)))
    assert {r["email"] for r in rows} == {"jane@example.org", "'=cmd|evil@example.org"}  # no formula injection
    assert "business.export_accounts" in [e["action"] for e in c.get("/api/audit?limit=50").json()]


def test_only_platform_admins_on_an_account_service(service):
    key = service.post("/api/keys", json={"name": "ana", "role": "analyst"}).json()["key"]
    for path in ("/api/business/summary", "/api/business/accounts", "/api/business/accounts.csv"):
        assert service.get(path, headers={"Authorization": f"Bearer {key}"}).status_code == 403
    assert service.get("/api/auth/config").json()["account_service"] is True


def test_not_on_other_installations(client):
    assert client.get("/api/business/summary").status_code == 404  # not an account service
    assert client.get("/api/auth/config").json()["account_service"] is False
