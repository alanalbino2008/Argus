"""Payments: Stripe checkout for plans and credit packs, the billing page, and Stripe's webhook."""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

import pytest

from argus.accounts import licence as lic
from argus.accounts import stripe_billing as stripe
from argus.core.settings import Settings
from tests.test_accounts import GOOD_PHRASE, PRIVATE, PUBLIC, FakeAccountService, FakeHandler, sign_in

SECRET = "whsec_test_secret"
PERIOD_END = int((datetime.now(timezone.utc) + timedelta(days=30)).timestamp())


# ---------------------------------------------------------------------------- a stand-in for Stripe
class FakeStripe(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        self.calls: list[tuple[str, str, dict, dict]] = []  # method, path, form, headers
        self.subscriptions: dict[str, dict] = {}
        self.charges: dict[str, dict] = {}
        super().__init__(("127.0.0.1", 0), StripeHandler)
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"


class StripeHandler(BaseHTTPRequestHandler):
    def _record(self, form):
        self.server.calls.append((self.command, urlsplit(self.path).path, form, dict(self.headers)))

    def do_GET(self):
        s, path = self.server, urlsplit(self.path)
        form = dict(parse_qsl(path.query))
        self._record(form)
        if self.headers.get("Authorization") != "Bearer sk_test_argus":
            return self._send(401, {"error": {"message": "Invalid API key"}})
        if path.path.startswith("/v1/prices/"):
            pid = path.path.rsplit("/", 1)[1]
            amounts = {"price_personal": (1500, "month"), "price_pro": (4900, "month"), "price_c500": (1000, None)}
            if pid not in amounts:
                return self._send(404, {"error": {"message": "No such price"}})
            amount, interval = amounts[pid]
            return self._send(200, {"id": pid, "unit_amount": amount, "currency": "gbp",
                                    "recurring": {"interval": interval} if interval else None})  # fmt: skip
        if path.path.startswith("/v1/subscriptions/"):
            sub = s.subscriptions.get(path.path.rsplit("/", 1)[1])
            return self._send(200, sub) if sub else self._send(404, {"error": {"message": "No such subscription"}})
        if path.path == "/v1/prices":
            return self._send(200, {"object": "list", "data": []})
        if path.path.startswith("/v1/charges/"):
            charge = s.charges.get(path.path.rsplit("/", 1)[1])
            return self._send(200, charge) if charge else self._send(404, {"error": {"message": "No such charge"}})
        if path.path == "/v1/subscriptions":
            subs = [x for x in s.subscriptions.values() if x["customer"] == form.get("customer")]
            return self._send(200, {"data": subs})
        return self._send(404, {"error": {"message": "nope"}})

    def do_POST(self):
        form = dict(parse_qsl(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()))
        self._record(form)
        if self.path == "/v1/checkout/sessions":
            return self._send(200, {"id": "cs_test_1", "url": "https://checkout.stripe.com/c/pay/cs_test_1"})
        if self.path == "/v1/billing_portal/sessions":
            return self._send(200, {"url": "https://billing.stripe.com/p/session/test_1"})
        return self._send(404, {"error": {"message": "nope"}})

    def _send(self, status, payload):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


@pytest.fixture
def fake_stripe():
    s = FakeStripe()
    yield s
    s.shutdown()


@pytest.fixture
def service(make_client, fake_stripe, monkeypatch):
    from argus.api import account_routes, billing_routes
    from argus.security.ratelimit import SlidingWindowLimiter

    monkeypatch.setattr(account_routes, "_per_ip", SlidingWindowLimiter(limit=200, window=60))
    monkeypatch.setattr(account_routes, "_signups", SlidingWindowLimiter(limit=50, window=3600))
    monkeypatch.setattr(billing_routes, "_prices", {})
    return make_client(account_service_enabled="true", licence_signing_key=PRIVATE, account_signup_enabled="true",
                       public_url="http://testserver", monitors_enabled="false", stripe_secret_key="sk_test_argus",
                       stripe_webhook_secret=SECRET, stripe_api_url=fake_stripe.url,
                       stripe_price_personal="price_personal", stripe_price_professional="price_pro",
                       stripe_credit_packs="500=price_c500, 2000=price_c2000, junk")  # fmt: skip


def event(kind, obj, *, eid=None):
    return {"id": eid or f"evt_{time.time_ns()}", "type": kind, "livemode": False, "data": {"object": obj}}


def deliver(c, evt, *, secret=SECRET, stamp=None):
    body = json.dumps(evt).encode()
    return c.post("/api/billing/webhook", content=body,
                  headers={"Stripe-Signature": stripe.sign(body, secret, stamp), "Content-Type": "application/json"})  # fmt: skip


def subscription(sid="sub_1", status="active", price="price_personal", customer="cus_1", account_id=None, **extra):
    return {"id": sid, "object": "subscription", "status": status, "customer": customer,
            "metadata": {"account_id": account_id} if account_id else {},
            "items": {"data": [{"price": {"id": price}, "current_period_end": PERIOD_END}]}, **extra}  # fmt: skip


# ---------------------------------------------------------------------------- the pieces
def test_webhook_signatures():
    body = b'{"id": "evt_1", "type": "invoice.paid"}'
    now = time.time()
    assert stripe.verify_event(body, stripe.sign(body, SECRET), SECRET)["id"] == "evt_1"
    for header, why in (("", "malformed"), (stripe.sign(body, "whsec_other"), "does not match"),
                        (stripe.sign(body + b" ", SECRET), "does not match"),
                        (stripe.sign(body, SECRET, int(now) - 600), "too old")):  # fmt: skip
        with pytest.raises(stripe.BillingError, match=why):
            stripe.verify_event(body, header, SECRET, now)
    # Stripe may sign with two secrets while one is being rotated
    both = stripe.sign(body, SECRET) + "," + stripe.sign(body, "whsec_other").split(",")[1]
    assert stripe.verify_event(body, both, SECRET)["type"] == "invoice.paid"


def test_what_is_on_sale_and_how_stripe_is_spoken_to():
    settings = Settings(stripe_price_personal="price_a", stripe_credit_packs="500=price_b,x=price_c,0=price_d,2000=")
    assert stripe.plan_prices(settings) == {"personal": "price_a"} and stripe.credit_packs(settings) == {500: "price_b"}
    assert stripe.plan_for_price(settings, "price_a") == "personal" and stripe.plan_for_price(settings, "x") is None
    form = stripe._form({"mode": "subscription", "line_items": [{"price": "p", "quantity": 1}],
                         "metadata": {"account_id": "acc_1"}, "skip": None, "flag": True})  # fmt: skip
    assert form == [("mode", "subscription"), ("line_items[0][price]", "p"), ("line_items[0][quantity]", "1"),
                    ("metadata[account_id]", "acc_1"), ("flag", "true")]  # fmt: skip
    old_api = {"current_period_end": PERIOD_END, "status": "active"}
    assert (
        stripe.period_end(old_api)
        == stripe.period_end(subscription())
        == datetime.fromtimestamp(PERIOD_END, tz=timezone.utc)
    )
    assert not stripe.enabled(settings)


# ---------------------------------------------------------------------------- the account service
def account(c):
    c.post("/api/accounts/signup", json={"email": "jane@example.org", "password": GOOD_PHRASE, "name": "Jane"})
    licence = sign_in(c).json()["licence"]
    return licence, lic.verify(licence, lic.load_public_key(PUBLIC))["sub"]


def test_subscribing_renewing_failing_and_cancelling(service, fake_stripe):
    c = service
    catalogue = c.get("/api/billing/catalogue").json()
    assert catalogue["enabled"] and [p["plan"] for p in catalogue["plans"]] == ["personal", "professional"]
    assert catalogue["plans"][0]["price"] == {"amount": 1500, "currency": "GBP", "interval": "month"}
    assert [p["credits"] for p in catalogue["credit_packs"]] == [500, 2000]
    assert catalogue["credit_packs"][1]["price"] is None  # Stripe doesn't know it: shown without a price
    licence, acc = account(c)

    back = "http://127.0.0.1:8000/"
    page = c.post("/api/billing/checkout", json={"licence": licence, "item": "plan:personal", "return_url": back})
    assert page.status_code == 200 and page.json()["url"].startswith("https://checkout.stripe.com/")
    _method, _path, form, _headers = next(x for x in fake_stripe.calls if x[1] == "/v1/checkout/sessions")
    assert form["mode"] == "subscription" and form["line_items[0][price]"] == "price_personal"
    assert form["client_reference_id"] == acc and form["subscription_data[metadata][account_id]"] == acc
    assert form["customer_email"] == "jane@example.org" and form["success_url"] == back + "?billing=done"
    assert "card" not in json.dumps(form)  # Argus never handles card details
    for bad in ({"item": "plan:enterprise"}, {"item": "credits:999"}, {"item": "plan:personal", "return_url": "https://evil.test/"}):  # fmt: skip
        assert c.post("/api/billing/checkout", json={"licence": licence, "return_url": back, **bad}).status_code in (
            404,
            422,
        )
    assert c.post("/api/billing/checkout", json={"licence": "forged", "item": "plan:personal"}).status_code == 401

    # Stripe: the checkout completed, the subscription is active
    fake_stripe.subscriptions["sub_1"] = subscription(account_id=acc)
    unsigned = c.post("/api/billing/webhook", content=b"{}", headers={"Stripe-Signature": "t=1,v1=00"})
    assert unsigned.status_code == 400
    done = event("checkout.session.completed", {"id": "cs_test_1", "mode": "subscription", "customer": "cus_1",
                                                "subscription": "sub_1", "client_reference_id": acc,
                                                "metadata": {"account_id": acc}}, eid="evt_paid")  # fmt: skip
    assert deliver(c, done).json() == {"received": True, "applied": True}
    assert deliver(c, done).json()["duplicate"] is True  # re-sent: applied once only
    got = c.get(f"/api/accounts/{acc}").json()
    assert (got["plan"], got["status"], got["billing_reference"]) == ("personal", "active", "cus_1")
    assert got["valid_until"].startswith(datetime.fromtimestamp(PERIOD_END, tz=timezone.utc).date().isoformat())
    renewed = lic.verify(c.post("/api/accounts/refresh", json={"licence": licence}).json()["licence"],
                         lic.load_public_key(PUBLIC))  # fmt: skip
    assert renewed["plan"] == "personal" and renewed["status"] == "active"
    already = c.post(
        "/api/billing/checkout", json={"licence": licence, "item": "plan:professional", "return_url": back}
    )
    assert already.status_code == 409 and "Manage billing" in already.json()["detail"]
    portal = c.post("/api/billing/portal", json={"licence": licence, "return_url": back}).json()
    assert portal["url"].startswith("https://billing.stripe.com/")
    assert c.post("/api/billing/catalogue", json={"licence": licence}).json()["has_billing"] is True

    # an upgrade mid-month: the bigger allowance is there straight away
    balance = lambda: c.post("/api/connect/balance", json={"licence": licence}).json()["credits"]  # noqa: E731
    assert balance()["allowance_remaining"] == 500
    fake_stripe.subscriptions["sub_1"] = subscription(price="price_pro", account_id=acc)
    deliver(c, event("customer.subscription.updated", subscription(account_id=acc)))  # stale copy: Stripe's now wins
    got = c.get(f"/api/accounts/{acc}").json()
    assert got["plan"] == "professional"
    assert balance()["allowance_remaining"] == 2000 and balance()["allowance"] == 2000

    # a renewal payment fails: still usable while Stripe retries
    fake_stripe.subscriptions["sub_1"] = subscription(status="past_due", price="price_pro", account_id=acc)
    deliver(c, event("customer.subscription.updated", fake_stripe.subscriptions["sub_1"]))
    got = c.get(f"/api/accounts/{acc}").json()
    until = datetime.fromisoformat(got["valid_until"])
    assert got["status"] == "past_due" and until >= datetime.now(timezone.utc) + timedelta(days=6)

    # cancelled at the end of the period: Stripe sends "deleted" when the period is over
    ended = subscription(status="canceled", price="price_pro", account_id=acc, ended_at=int(time.time()))
    fake_stripe.subscriptions["sub_1"] = ended
    deliver(c, event("customer.subscription.deleted", ended))
    got = c.get(f"/api/accounts/{acc}").json()
    assert got["status"] == "cancelled" and datetime.fromisoformat(got["valid_until"]) <= datetime.now(timezone.utc)
    refreshed = lic.verify(c.post("/api/accounts/refresh", json={"licence": licence}).json()["licence"],
                           lic.load_public_key(PUBLIC))  # fmt: skip
    assert lic.access(refreshed)[0] == "read_only"  # cases readable and exportable; new work waits

    # subscribing again later works (no longer subscribed)
    again = c.post("/api/billing/checkout", json={"licence": licence, "item": "plan:personal", "return_url": back})
    assert again.status_code == 200
    _m, _p, form, _h = [x for x in fake_stripe.calls if x[1] == "/v1/checkout/sessions"][-1]
    assert form["customer"] == "cus_1" and "customer_email" not in form
    actions = [e["action"] for e in c.get("/api/audit?limit=100").json()]
    assert {"billing.checkout", "billing.subscription"} <= set(actions)
    assert all(h.get("Authorization") == "Bearer sk_test_argus" for *_x, h in fake_stripe.calls)


def test_an_old_subscription_ending_does_not_cancel_a_new_one(service, fake_stripe):
    c = service
    _licence, acc = account(c)
    fake_stripe.subscriptions["sub_new"] = subscription("sub_new", account_id=acc)
    deliver(c, event("customer.subscription.created", fake_stripe.subscriptions["sub_new"]))
    old = subscription("sub_old", status="canceled", account_id=acc, ended_at=int(time.time()))
    fake_stripe.subscriptions["sub_old"] = old
    deliver(c, event("customer.subscription.deleted", old))
    assert c.get(f"/api/accounts/{acc}").json()["status"] == "active"


def test_buying_credits(service, fake_stripe):
    c = service
    licence, acc = account(c)
    page = c.post("/api/billing/checkout", json={"licence": licence, "item": "credits:500",
                                                 "return_url": "http://localhost:8000/"})  # fmt: skip
    assert page.status_code == 200
    _m, _p, form, _h = [x for x in fake_stripe.calls if x[1] == "/v1/checkout/sessions"][-1]
    assert form["mode"] == "payment" and form["metadata[credits]"] == "500" and form["customer_creation"] == "always"
    balance = lambda: c.post("/api/connect/balance", json={"licence": licence}).json()["credits"]  # noqa: E731
    start = balance()["purchased"]
    unpaid = event("checkout.session.completed", {"id": "cs_2", "mode": "payment", "payment_status": "unpaid",
                                                  "customer": "cus_9", "metadata": {"account_id": acc, "credits": "500"}})  # fmt: skip
    deliver(c, unpaid)
    assert balance()["purchased"] == start  # a bank transfer still pending: nothing yet
    paid = event("checkout.session.async_payment_succeeded",
                 {**unpaid["data"]["object"], "payment_status": "paid"}, eid="evt_credits")  # fmt: skip
    assert deliver(c, paid).json()["applied"] is True
    assert deliver(c, paid).json()["duplicate"] is True
    assert balance()["purchased"] == start + 500  # added exactly once
    assert c.get(f"/api/accounts/{acc}").json()["billing_reference"] == "cus_9"
    assert "billing.credits_purchased" in [e["action"] for e in c.get("/api/audit?limit=50").json()]


def test_payments_off_and_events_that_do_not_apply(make_client, service):
    c = service
    other = deliver(c, event("invoice.created", {"id": "in_1"}))
    assert other.json() == {"received": True, "applied": False}
    stranger = deliver(c, event("customer.subscription.deleted", subscription("sub_x", customer="cus_unknown")))
    assert stranger.json()["applied"] is False


def test_without_stripe_configured(make_client):
    c = make_client(account_service_enabled="true", licence_signing_key=PRIVATE, account_signup_enabled="true",
                    public_url="http://testserver", monitors_enabled="false")  # fmt: skip
    assert c.get("/api/billing/catalogue").json() == {"enabled": False, "plans": [], "credit_packs": []}
    assert c.post("/api/billing/webhook", content=b"{}").status_code == 503
    licence, _acc = account(c)
    r = c.post("/api/billing/checkout", json={"licence": licence, "item": "plan:personal",
                                              "return_url": "http://localhost/"})  # fmt: skip
    assert r.status_code == 503 and "not set up" in r.json()["detail"]


# ---------------------------------------------------------------------------- Argus Personal
class BillingAccountHandler(FakeHandler):
    def do_POST(self):
        if not self.path.startswith("/api/billing/"):
            return super().do_POST()
        s = self.server
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        s.calls.append((self.path, body))
        if self.path == "/api/billing/catalogue":
            return self._send(200, {"enabled": True, "has_billing": bool(body.get("licence")),
                                    "plans": [{"item": "plan:personal", "plan": "personal"}], "credit_packs": []})  # fmt: skip
        if self.path == "/api/billing/checkout":
            return self._send(200, {"url": "https://checkout.stripe.com/c/pay/cs_1"})
        return self._send(200, {"url": "https://billing.stripe.com/p/session/1"})


@pytest.fixture
def personal(make_client):
    accounts = FakeAccountService()
    accounts.RequestHandlerClass = BillingAccountHandler
    c = make_client(edition="personal", account_server_url=accounts.url, licence_public_key=PUBLIC,
                    monitors_enabled="false", capture_browser="off")  # fmt: skip
    c.headers["Origin"] = "http://testserver"
    yield c, accounts
    accounts.shutdown()


def test_paying_from_argus_personal(personal):
    c, accounts = personal
    assert c.post("/api/personal/billing/checkout", json={"item": "plan:personal"}).status_code == 401
    c.post("/api/personal/sign-in", json={"email": "jane@example.org", "password": GOOD_PHRASE})
    assert c.get("/api/personal/billing").json()["has_billing"] is True
    page = c.post("/api/personal/billing/checkout", json={"item": "plan:personal"})
    assert page.status_code == 200 and page.json()["url"].startswith("https://checkout.stripe.com/")
    path, sent = accounts.calls[-1]
    assert path == "/api/billing/checkout" and sent["return_url"] == "http://testserver/" and sent["licence"]
    assert c.post("/api/personal/billing/checkout", json={"item": "plan:anything"}).status_code == 422
    cross = c.post("/api/personal/billing/portal", headers={"Origin": "https://evil.test"})
    assert cross.status_code == 403
    assert c.post("/api/personal/billing/portal").json()["url"].startswith("https://billing.stripe.com/")
    # a lapsed subscription can still pay (the billing pages are not behind the read-only gate)
    accounts.account = {**accounts.account, "status": "cancelled"}
    assert c.post("/api/personal/refresh").json()["access"] == "read_only"
    assert c.post("/api/personal/billing/checkout", json={"item": "plan:personal"}).status_code == 200
