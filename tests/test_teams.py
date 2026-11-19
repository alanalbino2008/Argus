"""Team plans: seats, invitations, joining, shared credits, and members following the team's plan."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from argus.accounts import connectors, teams
from argus.accounts import licence as lic
from argus.storage.subscriber_repo import monthly_allowance
from tests import test_billing
from tests.test_account_emails import flush
from tests.test_accounts import GOOD_PHRASE, PRIVATE, PUBLIC
from tests.test_billing import SECRET, deliver, event, subscription
from tests.test_companies import FakeCompaniesHouse

fake_stripe = test_billing.fake_stripe  # the same stand-in for Stripe


@pytest.fixture
def service(make_client, fake_stripe, monkeypatch):
    from argus.api import account_routes, billing_routes, connect_routes, team_routes
    from argus.security.ratelimit import SlidingWindowLimiter

    for module, name in ((account_routes, "_per_ip"), (account_routes, "_signups"), (connect_routes, "_per_account"),
                         (team_routes, "_joins"), (team_routes, "_invites")):  # fmt: skip
        monkeypatch.setattr(module, name, SlidingWindowLimiter(limit=500, window=3600))
    monkeypatch.setattr(billing_routes, "_prices", {})
    ch = FakeCompaniesHouse()
    monkeypatch.setitem(connectors.BASES, "companies_house", ch.url)
    c = make_client(account_service_enabled="true", licence_signing_key=PRIVATE, account_signup_enabled="true",
                    public_url="http://testserver", monitors_enabled="false", stripe_secret_key="sk_test_argus",
                    stripe_webhook_secret=SECRET, stripe_api_url=fake_stripe.url, stripe_price_business="price_business", stripe_price_business_setup="price_setup",
                    stripe_price_personal="price_personal", smtp_host="smtp.test", companies_house_api_key="k")  # fmt: skip
    c.outbox = []
    monkeypatch.setattr(c.app.state.mailer.transport, "_send_mail", c.outbox.append)
    yield c
    ch.shutdown()


def sign_in(c, email, password=GOOD_PHRASE, device="device-0123456789abcdef"):
    r = c.post("/api/accounts/token", json={"email": email, "password": password, "device_id": device})
    return r


def payload(licence):
    return lic.verify(licence, lic.load_public_key(PUBLIC))


def link_for(c, email):
    flush(c)
    message = [m for m in c.outbox if m["To"] == email][-1]
    body = message.get_body(("plain",)).get_content()
    return next(line for line in body.splitlines() if "/join-team#token=" in line).split("#token=", 1)[1]


def owner_with_team(c, fake_stripe, seats=3):
    c.post("/api/accounts/signup", json={"email": "olivia@agency.example", "password": GOOD_PHRASE, "name": "Olivia"})
    licence = sign_in(c, "olivia@agency.example").json()["licence"]
    acc = payload(licence)["sub"]
    page = c.post("/api/billing/checkout", json={"licence": licence, "item": "plan:business", "seats": seats,
                                                 "return_url": "http://localhost:8000/"})  # fmt: skip
    assert page.status_code == 200
    form = [x for x in fake_stripe.calls if x[1] == "/v1/checkout/sessions"][-1][2]
    assert (
        form["line_items[0][quantity]"] == str(seats) and form["line_items[0][adjustable_quantity][enabled]"] == "true"
    )
    sub = subscription(price="price_business", account_id=acc)
    sub["items"]["data"][0]["quantity"] = seats
    fake_stripe.subscriptions["sub_1"] = sub
    deliver(c, event("customer.subscription.created", sub))
    return acc, licence


def test_the_rules():
    assert monthly_allowance("business", 3) == 3000 and monthly_allowance("personal", 3) == 500
    owner = {"id": "acc_o", "plan": "business", "team_id": None}
    assert teams.is_owner(owner) and teams.pool_id({"id": "acc_m", "team_id": "acc_o"}) == "acc_o"
    assert teams.device_limit({"id": "m", "team_id": "acc_o"}) == 2 and teams.device_limit(owner) is None


def test_a_team_from_start_to_finish(service, fake_stripe):
    c = service
    acc, licence = owner_with_team(c, fake_stripe)
    got = c.get(f"/api/accounts/{acc}").json()
    assert (got["plan"], got["seats"], got["status"]) == ("business", 3, "active")
    assert c.post("/api/connect/balance", json={"licence": licence}).json()["credits"]["allowance"] == 3000

    invite = lambda email: c.post("/api/teams/invite", json={"licence": licence, "email": email})  # noqa: E731
    assert invite("olivia@agency.example").status_code == 409  # already on it
    assert invite("bob@agency.example").status_code == 200
    assert invite("bob@agency.example").status_code == 200  # sent again: the first link stops working
    assert invite("carol@agency.example").status_code == 200
    full = invite("dan@agency.example")
    assert full.status_code == 409 and "seats" in full.json()["detail"]  # 3 seats: owner + 2 invited
    status = c.post("/api/teams/status", json={"licence": licence}).json()
    assert status["role"] == "owner" and status["used"] == 1 and [i["email"] for i in status["invites"]] == [
        "carol@agency.example", "bob@agency.example"]  # fmt: skip

    # Bob is new to Argus: he chooses a password and joins
    flush(c)
    bob_links = [m for m in c.outbox if m["To"] == "bob@agency.example"]
    assert len(bob_links) == 2 and "Olivia invited you" in bob_links[0]["Subject"]
    old = bob_links[0].get_body(("plain",)).get_content().split("#token=", 1)[1].split()[0]
    assert c.post("/api/teams/join/info", json={"token": old}).status_code == 400  # replaced by the second
    token = link_for(c, "bob@agency.example")
    info = c.post("/api/teams/join/info", json={"token": token}).json()
    assert info == {"team": "Olivia", "email": "bob@agency.example", "has_account": False}
    assert c.post("/api/teams/join", json={"token": token, "password": "short"}).status_code == 422
    joined = c.post("/api/teams/join", json={"token": token, "password": "bobs own pass phrase", "name": "Bob"})
    assert joined.status_code == 200
    assert c.post("/api/teams/join", json={"token": token, "password": "bobs own pass phrase"}).status_code == 400
    assert c.get("/join-team").status_code == 200

    # Bob signs in on his own computer: the team's plan, paid-until and shared credits
    bob_licence = sign_in(c, "bob@agency.example", "bobs own pass phrase", "device-bbbbbbbbbbbbbbbb").json()["licence"]
    bob = payload(bob_licence)
    assert (bob["plan"], bob["status"]) == ("business", "active") and bob["valid_until"] == got["valid_until"]
    balance = c.post("/api/connect/balance", json={"licence": bob_licence}).json()
    assert balance["shared_with_team"] and balance["credits"]["allowance"] == 3000
    r = c.post("/api/connect/companies_house", json={"licence": bob_licence, "operation": "company",
                                                     "params": {"number": "01234567"}})  # fmt: skip
    assert r.status_code == 200 and r.json()["credits"]["available"] == 2999  # from the team's pool
    status = c.post("/api/teams/status", json={"licence": licence}).json()
    people = {m["email"]: m["credits_this_month"] for m in status["members"]}
    assert people == {"olivia@agency.example": 0, "bob@agency.example": 1}  # who used how much, never what
    assert c.post("/api/teams/status", json={"licence": bob_licence}).json() == {
        "role": "member", "team": "Olivia", "owner_email": "olivia@agency.example", "active": True}  # fmt: skip
    for path, body in (("/api/teams/invite", {"email": "x@y.org"}), ("/api/teams/remove", {"member_id": acc})):
        assert c.post(path, json={"licence": bob_licence, **body}).status_code == 403  # members can't manage
    member_buy = c.post("/api/billing/checkout", json={"licence": bob_licence, "item": "plan:personal",
                                                       "return_url": "http://localhost/"})  # fmt: skip
    assert member_buy.status_code == 409

    # the team's payment fails: everyone keeps working while it's retried; it ends: everyone read-only
    fake_stripe.subscriptions["sub_1"]["status"] = "canceled"
    fake_stripe.subscriptions["sub_1"]["ended_at"] = int(datetime.now(timezone.utc).timestamp())
    deliver(c, event("customer.subscription.deleted", fake_stripe.subscriptions["sub_1"]))
    after = payload(c.post("/api/accounts/refresh", json={"licence": bob_licence}).json()["licence"])
    assert after["status"] == "cancelled" and lic.access(after)[0] == "read_only"
    flush(c)
    subjects = [m["Subject"] for m in c.outbox]
    assert "Bob joined your Argus team" in subjects
    assert not any("trial" in s.lower() for s in subjects if s)  # members get no trial reminders
    actions = [e["action"] for e in c.get("/api/audit?limit=100").json()]
    assert {"team.invite", "team.join"} <= set(actions)


def test_existing_accounts_removing_and_leaving(service, fake_stripe):
    c = service
    _acc, licence = owner_with_team(c, fake_stripe, seats=4)
    for email in ("sam@agency.example", "pat@agency.example"):
        c.post("/api/accounts/signup", json={"email": email, "password": GOOD_PHRASE})
    # Pat already pays for her own plan: joining would make her pay twice
    pat = payload(sign_in(c, "pat@agency.example", device="device-pppppppppppppppp").json()["licence"])["sub"]
    c.patch(f"/api/accounts/{pat}", json={"plan": "personal", "status": "active",
                                          "valid_until": (datetime.now(timezone.utc) + timedelta(days=20)).isoformat()})  # fmt: skip
    c.post("/api/teams/invite", json={"licence": licence, "email": "pat@agency.example"})
    pat_token = link_for(c, "pat@agency.example")
    refused = c.post("/api/teams/join", json={"token": pat_token, "password": GOOD_PHRASE})
    assert refused.status_code == 409 and "pay twice" in refused.json()["detail"]

    c.post("/api/teams/invite", json={"licence": licence, "email": "sam@agency.example"})
    token = link_for(c, "sam@agency.example")
    assert c.post("/api/teams/join/info", json={"token": token}).json()["has_account"] is True
    assert c.post("/api/teams/join", json={"token": token, "password": "wrong pass phrase"}).status_code == 401
    assert c.post("/api/teams/join", json={"token": token, "password": GOOD_PHRASE}).status_code == 200
    sam_licence = sign_in(c, "sam@agency.example", device="device-ssssssssssssssss").json()["licence"]
    sam = payload(sam_licence)["sub"]
    assert payload(sam_licence)["plan"] == "business"

    removed = c.post("/api/teams/remove", json={"licence": licence, "member_id": sam})
    assert removed.status_code == 200
    back = payload(c.post("/api/accounts/refresh", json={"licence": sam_licence}).json()["licence"])
    assert back["plan"] == "trial"  # back to his own account as it was
    assert c.post("/api/teams/remove", json={"licence": licence, "member_id": sam}).status_code == 404

    c.post("/api/teams/invite", json={"licence": licence, "email": "sam@agency.example"})
    c.post("/api/teams/join", json={"token": link_for(c, "sam@agency.example"), "password": GOOD_PHRASE})
    assert c.post("/api/teams/leave", json={"licence": sam_licence}).status_code == 200
    assert c.post("/api/teams/leave", json={"licence": sam_licence}).status_code == 404
    flush(c)
    subjects = [m["Subject"] for m in c.outbox]
    assert "You're no longer on an Argus team" in subjects and any("left your Argus team" in s for s in subjects)

    # Business page: the team (4 seats) and Pat's own plan; members aren't counted as trials
    summary = c.get("/api/business/summary").json()["customers"]
    assert summary["paying"] == 2 and summary["team_seats"] == 4 and summary["plans"] == {"business": 1, "personal": 1}
    assert c.get("/api/business/accounts?plan=business").json()["total"] == 1


def test_more_seats_mid_month(service, fake_stripe):
    c = service
    acc, licence = owner_with_team(c, fake_stripe, seats=2)
    balance = lambda: c.post("/api/connect/balance", json={"licence": licence}).json()["credits"]  # noqa: E731
    assert balance()["allowance_remaining"] == 2000
    more = subscription(price="price_business", account_id=acc)
    more["items"]["data"][0]["quantity"] = 5
    fake_stripe.subscriptions["sub_1"] = more
    deliver(c, event("customer.subscription.updated", more))
    assert c.get(f"/api/accounts/{acc}").json()["seats"] == 5 and balance()["allowance_remaining"] == 5000


# ---------------------------------------------------------------------------- Argus Personal
class TeamAccountHandler(test_billing.BillingAccountHandler):
    def do_POST(self):
        if not self.path.startswith("/api/teams/"):
            return super().do_POST()
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        self.server.calls.append((self.path, body))
        if self.path == "/api/teams/status":
            return self._send(200, {"role": "owner", "seats": 3, "used": 1, "pending": 0, "members": [], "invites": []})
        return self._send(200, {"detail": "done"})


@pytest.fixture
def personal(make_client):
    accounts = test_billing.FakeAccountService()
    accounts.RequestHandlerClass = TeamAccountHandler
    c = make_client(edition="personal", account_server_url=accounts.url, licence_public_key=PUBLIC,
                    monitors_enabled="false", capture_browser="off")  # fmt: skip
    c.headers["Origin"] = "http://testserver"
    yield c, accounts
    accounts.shutdown()


def test_managing_the_team_from_argus_personal(personal):
    c, accounts = personal
    assert c.get("/api/personal/team").status_code == 401
    c.post("/api/personal/sign-in", json={"email": "jane@example.org", "password": GOOD_PHRASE})
    assert c.get("/api/personal/team").json()["role"] == "owner"
    assert c.post("/api/personal/team/invite", json={"email": "bob@agency.example"}).status_code == 200
    assert accounts.calls[-1] == ("/api/teams/invite", {"licence": accounts.calls[-1][1]["licence"],
                                                        "email": "bob@agency.example"})  # fmt: skip
    assert c.post("/api/personal/team/remove", json={"member_id": "acc_1"}).status_code == 200
    assert c.post("/api/personal/team/leave").status_code == 200
    cross = c.post("/api/personal/team/invite", json={"email": "x@y.org"}, headers={"Origin": "https://evil.test"})
    assert cross.status_code == 403  # another website can't manage the team
    assert "team.invite" in [e["action"] for e in c.get("/api/audit?limit=20").json()]
