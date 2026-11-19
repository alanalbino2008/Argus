"""Refunds and disputes (chargebacks): credits taken back, accounts put on hold and restored."""

from __future__ import annotations

from tests import test_account_emails, test_billing
from tests.test_accounts import GOOD_PHRASE, sign_in
from tests.test_billing import deliver, event, subscription

fake_stripe, service = test_billing.fake_stripe, test_account_emails.service  # same fixtures (with email)
flush = test_account_emails.flush


def setup(c, fake_stripe):
    acc = c.post("/api/accounts/signup", json={"email": "jane@example.org", "password": GOOD_PHRASE}).json()["id"]
    sub = subscription(account_id=acc)
    fake_stripe.subscriptions["sub_1"] = sub
    deliver(c, event("customer.subscription.created", sub))
    return acc


def buy(c, acc, pi, credits=500, amount=1000):
    paid = {"id": f"cs_{pi}", "mode": "payment", "payment_status": "paid", "customer": "cus_1",
            "payment_intent": pi, "amount_total": amount, "currency": "gbp",
            "metadata": {"account_id": acc, "credits": str(credits)}}  # fmt: skip
    assert deliver(c, event("checkout.session.completed", paid)).json()["applied"]


def purchased(c, acc):
    return c.get(f"/api/accounts/{acc}/credits").json()["purchased"]


def charge(pi, *, refunded=0, amount=1000, customer="cus_1", cid=None):
    return {"id": cid or f"ch_{pi}", "object": "charge", "payment_intent": pi, "customer": customer,
            "amount": amount, "amount_refunded": refunded, "currency": "gbp", "refunded": refunded >= amount}  # fmt: skip


def test_refunding_credit_packs(service, fake_stripe):
    c = service
    acc = setup(c, fake_stripe)
    buy(c, acc, "pi_1")
    assert purchased(c, acc) == 500
    assert deliver(c, event("charge.refunded", charge("pi_1", refunded=500))).json()["applied"]
    assert purchased(c, acc) == 250  # half the money back: half the credits
    deliver(c, event("charge.refunded", charge("pi_1", refunded=500)))  # the same refund again: nothing more
    assert purchased(c, acc) == 250
    deliver(c, event("charge.refunded", charge("pi_1", refunded=1000)))
    assert purchased(c, acc) == 0

    buy(c, acc, "pi_2")
    c.post(f"/api/accounts/{acc}/credits", json={"amount": -400, "kind": "adjustment", "detail": "spent"})
    deliver(c, event("charge.refunded", charge("pi_2", refunded=1000)))
    assert purchased(c, acc) == 0  # never below zero
    entries = [e for e in c.get("/api/audit?limit=100").json() if e["action"] == "billing.refund"]
    assert entries[0]["details"]["credits_taken"] == 100 and entries[0]["details"]["already_spent"] == 400
    ledger = c.get(f"/api/accounts/{acc}/credits").json()["ledger"]
    assert [e["delta"] for e in ledger if e["kind"] == "reversal"] == [-100, -250, -250]
    assert c.get(f"/api/accounts/{acc}").json()["status"] == "active"  # a refund doesn't end the subscription
    flush(c)
    assert sum(m["Subject"] == "Your Argus refund" for m in c.outbox) == 3
    refund_mail = next(m for m in c.outbox if m["Subject"] == "Your Argus refund").get_body(("plain",)).get_content()
    assert "5.00 GBP" in refund_mail and "250 credits" in refund_mail


def test_refunding_a_subscription_payment(service, fake_stripe):
    c = service
    acc = setup(c, fake_stripe)
    r = deliver(c, event("charge.refunded", charge("pi_sub", refunded=1500, amount=1500)))
    assert r.json()["applied"] and c.get(f"/api/accounts/{acc}").json()["status"] == "active"
    payments = c.get(f"/api/accounts/{acc}").json()["payments"]
    assert payments[0]["kind"] == "subscription" and payments[0]["refunded"] == 1500
    stranger = deliver(c, event("charge.refunded", charge("pi_x", refunded=100, customer="cus_unknown")))
    assert stranger.json()["applied"] is False


def test_a_dispute_won(service, fake_stripe):
    c = service
    acc = setup(c, fake_stripe)
    licence = sign_in(c).json()["licence"]
    buy(c, acc, "pi_3")
    dispute = {"id": "dp_1", "object": "dispute", "charge": "ch_pi_3", "payment_intent": "pi_3", "amount": 1000,
               "currency": "gbp", "reason": "fraudulent", "status": "needs_response"}  # fmt: skip
    assert deliver(c, event("charge.dispute.created", dispute)).json()["applied"]
    got = c.get(f"/api/accounts/{acc}").json()
    assert got["status"] == "suspended" and purchased(c, acc) == 0
    assert c.post("/api/accounts/refresh", json={"licence": licence}).status_code == 403  # read-only, cases kept
    # Stripe carries on reporting the subscription meanwhile: the hold stays
    deliver(c, event("customer.subscription.updated", fake_stripe.subscriptions["sub_1"]))
    assert c.get(f"/api/accounts/{acc}").json()["status"] == "suspended"
    summary = c.get("/api/business/summary").json()
    assert {"id": acc, "why": "payment disputed"}.items() <= next(
        a for a in summary["attention"] if a["id"] == acc
    ).items()
    assert summary["refunds_and_disputes"]["disputes_open"] == 1

    deliver(c, event("charge.dispute.closed", {**dispute, "status": "won"}))
    got = c.get(f"/api/accounts/{acc}").json()
    assert got["status"] == "active" and purchased(c, acc) == 500
    assert c.post("/api/accounts/refresh", json={"licence": licence}).status_code == 200
    flush(c)
    subjects = [m["Subject"] for m in c.outbox]
    assert "Your Argus account is on hold" in subjects and "Your Argus account is active again" in subjects
    actions = [e["action"] for e in c.get("/api/audit?limit=100").json()]
    assert {"billing.dispute_opened", "billing.dispute_won"} <= set(actions)


def test_a_dispute_lost_and_an_unknown_charge(service, fake_stripe):
    c = service
    acc = setup(c, fake_stripe)
    fake_stripe.charges["ch_9"] = charge("pi_9", cid="ch_9", amount=1500)  # a subscription payment Argus never saw
    dispute = {"id": "dp_9", "object": "dispute", "charge": "ch_9", "amount": 1500, "currency": "gbp",
               "reason": "unrecognized", "status": "needs_response"}  # fmt: skip
    assert deliver(c, event("charge.dispute.created", dispute)).json()["applied"]
    assert c.get(f"/api/accounts/{acc}").json()["status"] == "suspended"
    deliver(c, event("charge.dispute.closed", {**dispute, "status": "lost"}))
    assert c.get(f"/api/accounts/{acc}").json()["status"] == "suspended"  # the operator decides
    why = {a["id"]: a["why"] for a in c.get("/api/business/summary").json()["attention"]}
    assert why[acc].startswith("dispute lost")
    c.patch(f"/api/accounts/{acc}", json={"status": "active"})  # the operator lifts the hold
    assert acc not in {a["id"] for a in c.get("/api/business/summary").json()["attention"]}
    assert "billing.dispute_lost" in [e["action"] for e in c.get("/api/audit?limit=100").json()]
    gone = {"id": "dp_0", "charge": "ch_missing", "amount": 100, "currency": "gbp", "status": "needs_response"}
    assert deliver(c, event("charge.dispute.created", gone)).status_code == 503  # Stripe will retry
