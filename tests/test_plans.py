"""Plans: what each includes (enforced from the licence), your own API keys, and Business accounts."""

from __future__ import annotations

import pytest

from argus.accounts import features, own_keys
from argus.accounts import licence as lic
from argus.accounts.connect_client import anthropic_key, own_key
from argus.storage.subscriber_repo import monthly_allowance
from tests import test_teams
from tests.test_account_emails import flush
from tests.test_accounts import GOOD_PHRASE, PUBLIC, FakeAccountService

fake_stripe, service = test_teams.fake_stripe, test_teams.service  # the same fixtures
owner_with_team, payload, sign_in = test_teams.owner_with_team, test_teams.payload, test_teams.sign_in


def test_what_each_plan_includes():
    assert monthly_allowance("byok") == 0 and lic.PLANS["byok"]["max_devices"] == 1
    assert features.plan_features({"plan": "personal", "features": []}) == set()
    assert features.plan_features({"plan": "professional"}) == {"monitoring", "branded_reports", "playbooks"}
    assert "team" in features.plan_features({"plan": "business"}) and not features.plan_features(None)
    assert (
        features.needed("/api/monitors") == "monitoring" and features.needed("/api/cases/c1/playbooks") == "playbooks"
    )
    assert features.needed("/api/reports/branding") == "branded_reports" and features.needed("/api/cases") is None
    message = features.upgrade_message("monitoring")
    assert "Professional and Business plans" in message and "Free trial" not in message
    token = lic.issue({"id": "a", "email": "a@b.test", "plan": "byok", "status": "active",
                       "valid_until": "2099-01-01T00:00:00+00:00"}, device_id="d" * 16, issuer="x",
                      private=lic.load_private_key(test_teams.PRIVATE), offline_days=14)  # fmt: skip
    assert payload(token)["features"] == [] and payload(token)["plan_label"] == "Bring your own keys"


# ---------------------------------------------------------------------------- Argus Personal enforces the plan
@pytest.fixture
def personal(make_client):
    accounts = FakeAccountService()
    c = make_client(edition="personal", account_server_url=accounts.url, licence_public_key=PUBLIC,
                    monitors_enabled="false", capture_browser="off", encryption_key="k" * 40)  # fmt: skip
    c.headers["Origin"] = "http://testserver"
    yield c, accounts
    own_keys._keys.clear()
    accounts.shutdown()


def on_plan(c, accounts, plan):
    accounts.account = {**accounts.account, "plan": plan}
    c.post("/api/personal/sign-in", json={"email": "jane@example.org", "password": GOOD_PHRASE})
    c.post("/api/personal/refresh")


def test_a_personal_plan_without_professional_features(personal):
    c, accounts = personal
    on_plan(c, accounts, "personal")
    status = c.get("/api/personal/status").json()
    assert status["features"] == {"monitoring": False, "branded_reports": False, "playbooks": False, "team": False}
    case = c.post("/api/cases", json={"title": "Story", "purpose": "Checking a story", "confirmed": True}).json()
    for method, path, body in (("post", "/api/monitors", {"target": "example.com"}),
                               ("post", f"/api/cases/{case['id']}/playbooks", {"playbook": "person"}),
                               ("put", "/api/reports/branding", {"name": "Acme"}),
                               ("post", f"/api/cases/{case['id']}/watches", {"platform": "github"})):  # fmt: skip
        r = getattr(c, method)(path, json=body)
        assert r.status_code == 403 and r.json()["upgrade"] is True and "Professional" in r.json()["detail"], path
    assert c.get("/api/monitors").status_code == 200  # what exists stays readable
    assert c.post("/api/cases", json={"title": "Two", "purpose": "Another story", "confirmed": True}).status_code == 201
    assert c.portal.call(c.app.state.scheduler.tick) == []  # scheduled scans pause
    assert features.allows("monitoring") is False


def test_professional_gets_them(personal):
    c, accounts = personal
    on_plan(c, accounts, "professional")
    assert c.get("/api/personal/status").json()["features"]["playbooks"] is True
    case = c.post("/api/cases", json={"title": "Story", "purpose": "Checking a story", "confirmed": True}).json()
    r = c.post(f"/api/cases/{case['id']}/playbooks", json={"playbook": "nonsense"})
    assert r.status_code != 403  # reaches the playbook itself (which refuses the unknown name)


def test_your_own_api_keys(personal):
    c, accounts = personal
    on_plan(c, accounts, "byok")
    listing = c.get("/api/personal/keys").json()["keys"]
    assert {k["provider"] for k in listing} == {"companies_house", "web_search", "anthropic"}
    assert not any(k["set"] for k in listing)
    assert c.put("/api/personal/keys/companies_house", json={"key": "has spaces in it"}).status_code == 422
    assert c.put("/api/personal/keys/nonsense", json={"key": "abcdefgh1234"}).status_code == 422
    saved = c.put("/api/personal/keys/companies_house", json={"key": "ch-key-0123456789abcd"}).json()["keys"]
    row = next(k for k in saved if k["provider"] == "companies_house")
    assert row["set"] and row["ends_with"] == "abcd" and "ch-key" not in str(saved)  # never shown back
    c.put("/api/personal/keys/anthropic", json={"key": "sk-ant-api03-0123456789"})
    assert own_key("companies_house") == "ch-key-0123456789abcd" and anthropic_key() == "sk-ant-api03-0123456789"
    stored = c.portal.call(c.app.state.app_state.get, "own_keys")
    assert "ch-key" not in str(stored)  # encrypted on disk
    own_keys._keys.clear()
    c.portal.call(own_keys.load, c.app.state.app_state, c.app.state.secret_box)  # as at the next start
    assert own_key("companies_house") == "ch-key-0123456789abcd"
    assert "ch-key" not in str(accounts.calls)  # never sent to the account service
    assert c.delete("/api/personal/keys/companies_house").status_code == 200 and own_key("companies_house") == ""
    assert c.delete("/api/personal/keys/companies_house").status_code == 404
    cross = c.put(
        "/api/personal/keys/web_search", json={"key": "abcdefgh1234"}, headers={"Origin": "https://evil.test"}
    )
    assert cross.status_code == 403
    assert "settings.own_key_set" in [e["action"] for e in c.get("/api/audit?limit=20").json()]


def test_keys_need_an_encryption_key(make_client):
    accounts = FakeAccountService()
    try:
        c = make_client(edition="personal", account_server_url=accounts.url, licence_public_key=PUBLIC,
                        monitors_enabled="false", capture_browser="off")  # fmt: skip
        c.headers["Origin"] = "http://testserver"
        c.post("/api/personal/sign-in", json={"email": "jane@example.org", "password": GOOD_PHRASE})
        r = c.put("/api/personal/keys/companies_house", json={"key": "abcdefgh1234"})
        assert r.status_code == 503 and "encryption key" in r.json()["detail"]
    finally:
        accounts.shutdown()


# ---------------------------------------------------------------------------- Business
def test_business_checkout_and_catalogue(service, fake_stripe):
    c = service
    owner_with_team(c, fake_stripe)
    form = [x for x in fake_stripe.calls if x[1] == "/v1/checkout/sessions"][-1][2]
    assert form["line_items[1][price]"] == "price_setup" and form["line_items[1][quantity]"] == "1"  # one-off set-up
    plans = {p["plan"]: p for p in c.get("/api/billing/catalogue").json()["plans"]}
    assert plans["business"]["per_seat"] and "team" in plans["business"]["features"]
    assert plans["personal"]["features"] == []


def test_the_owner_creates_accounts(service, fake_stripe):
    c = service
    _acc, licence = owner_with_team(c, fake_stripe, seats=4)
    made = c.post("/api/teams/add", json={"licence": licence, "email": "nina@agency.example", "name": "Nina"})
    assert made.status_code == 200 and made.json()["created"] is True
    flush(c)
    mail = [m for m in c.outbox if m["To"] == "nina@agency.example"][-1]
    assert mail["Subject"] == "Olivia created an Argus account for you"
    body = mail.get_body(("plain",)).get_content()
    token = next(line for line in body.splitlines() if "/reset-password#token=" in line).split("#token=", 1)[1]
    assert sign_in(c, "nina@agency.example", "anything at all").status_code == 401  # no usable password yet
    chosen = c.post("/api/accounts/password-reset/confirm", json={"token": token, "password": "ninas own pass phrase"})
    assert chosen.status_code == 200
    nina_licence = sign_in(c, "nina@agency.example", "ninas own pass phrase", "device-nnnnnnnnnnnnnnnn").json()[
        "licence"
    ]
    assert payload(nina_licence)["plan"] == "business" and "team" in payload(nina_licence)["features"]
    flush(c)
    to_nina = [m["Subject"] for m in c.outbox if m["To"] == "nina@agency.example"]
    assert "Your Argus password was changed" not in to_nina  # her first password, not a change

    c.post("/api/accounts/signup", json={"email": "omar@agency.example", "password": GOOD_PHRASE})
    existing = c.post("/api/teams/add", json={"licence": licence, "email": "omar@agency.example"})
    assert existing.json()["invited"] is True  # an existing account is invited, never taken over
    assert [i["email"] for i in c.post("/api/teams/status", json={"licence": licence}).json()["invites"]] == [
        "omar@agency.example"]  # fmt: skip

    nina = payload(nina_licence)["sub"]
    out = c.post("/api/teams/sign-out-member", json={"licence": licence, "member_id": nina})
    assert out.status_code == 200 and "1 computer" in out.json()["detail"]
    assert c.post("/api/accounts/refresh", json={"licence": nina_licence}).status_code == 401  # lost laptop: locked out
    assert c.post("/api/teams/add", json={"licence": nina_licence, "email": "x@agency.example"}).status_code == 403
    actions = [e["action"] for e in c.get("/api/audit?limit=100").json()]
    assert {"team.add_member", "team.sign_out_member"} <= set(actions)
