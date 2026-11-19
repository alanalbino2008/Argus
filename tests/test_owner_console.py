"""The owner console: one owner, password + authenticator code, and settings changed live."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest

from argus.accounts import stripe_billing
from argus.accounts.licence import PLANS
from argus.core import runtime_config
from argus.security import totp
from tests.conftest import ADMIN_KEY
from tests.test_accounts import PRIVATE
from tests.test_billing import fake_stripe  # noqa: F401 - the stand-in for Stripe

OWNER = "owner@argus.test"
PASSWORD = "the owners long pass phrase"


class Clock:
    """Authenticator codes are per 30 seconds and never accepted twice: tests move time on."""

    def __init__(self):
        self.now = datetime.now(timezone.utc).timestamp()

    def code(self, secret):
        self.now += 31
        return totp.code_at(secret, totp.now_counter(self.now))


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(totp.time, "time", lambda: c.now)
    return c


@pytest.fixture
def console(make_client, monkeypatch, fake_stripe):  # noqa: F811
    from argus.api import owner_routes
    from argus.security.ratelimit import SlidingWindowLimiter

    monkeypatch.setattr(owner_routes, "_attempts", SlidingWindowLimiter(limit=1000, window=600))
    c = make_client(account_service_enabled="true", licence_signing_key=PRIVATE, public_url="http://testserver",
                    monitors_enabled="false", owner_email=OWNER, smtp_host="smtp.test", stripe_api_url=fake_stripe.url)  # fmt: skip
    c.headers["Origin"] = "http://testserver"
    c.outbox = []
    monkeypatch.setattr(c.app.state.mailer.transport, "_send_mail", c.outbox.append)
    yield c
    runtime_config.apply(c.app.state.settings, None, runtime_config_box(c))  # plans back to their defaults


def runtime_config_box(c):
    from argus.accounts.owner import box

    return box(c.app.state.settings)


def anonymous(c):
    """The same browser without the admin API key the test client normally carries."""
    c.headers.pop("Authorization", None)
    return c


def set_up(c, clock):
    anonymous(c)
    start = c.post("/api/owner/setup/start", json={"email": OWNER, "setup_key": ADMIN_KEY})
    assert start.status_code == 200 and start.json()["qr_svg"].startswith("<svg")
    secret = start.json()["secret"]
    done = c.post("/api/owner/setup/finish", json={"email": OWNER, "setup_key": ADMIN_KEY, "password": PASSWORD,
                                                   "code": clock.code(secret)})  # fmt: skip
    assert done.status_code == 200
    return secret, done.json()["recovery_codes"]


def sign_in(c, clock, secret):
    assert c.post("/api/owner/login", json={"email": OWNER, "password": PASSWORD}).json()["stage"] == "code"
    assert c.post("/api/owner/verify", json={"code": clock.code(secret)}).status_code == 200


def test_authenticator_codes(clock):
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert totp.code_at(secret, 1) == "287082"  # RFC 6238's test key, 6 digits
    code = totp.code_at(secret, totp.now_counter(clock.now))
    counter = totp.verify(secret, code)
    assert counter is not None and totp.verify(secret, code, last_counter=counter) is None  # never twice
    assert totp.verify(secret, "12345") is None and totp.verify(secret, "abcdef") is None
    assert totp.provisioning_uri("ABC", "me@x.org").startswith("otpauth://totp/Argus%3Ame%40x.org?secret=ABC")


def test_setting_up_the_owner(console, clock):
    c = anonymous(console)
    assert c.get("/api/owner/state").json() == {"configured": True, "owner_exists": False, "stage": None,
                                                "encryption": True, "email": None}  # fmt: skip
    bad = [{"email": "someone@else.test", "setup_key": ADMIN_KEY}, {"email": OWNER, "setup_key": "argus_wrong"}]
    for body in bad:
        assert c.post("/api/owner/setup/start", json=body).status_code == 403
    cross = c.post("/api/owner/setup/start", json={"email": OWNER, "setup_key": ADMIN_KEY},
                   headers={"Origin": "https://evil.test"})  # fmt: skip
    assert cross.status_code == 403
    secret = c.post("/api/owner/setup/start", json={"email": OWNER, "setup_key": ADMIN_KEY}).json()["secret"]
    weak = c.post("/api/owner/setup/finish", json={"email": OWNER, "setup_key": ADMIN_KEY, "password": "short",
                                                   "code": clock.code(secret)})  # fmt: skip
    assert weak.status_code == 422
    wrong = c.post("/api/owner/setup/finish", json={"email": OWNER, "setup_key": ADMIN_KEY, "password": PASSWORD,
                                                    "code": "000000"})  # fmt: skip
    assert wrong.status_code == 422
    secret, codes = set_up(c, clock)
    assert len(codes) == 10 and len(set(codes)) == 10
    state = c.get("/api/owner/state").json()
    assert state["stage"] == "full" and state["email"] == OWNER
    assert c.post("/api/owner/setup/start", json={"email": OWNER, "setup_key": ADMIN_KEY}).status_code == 409  # once
    assert "argus_owner" in c.cookies
    assert any("set up" in m["Subject"] for m in c.outbox)


def test_no_owner_email_means_no_console(make_client):
    c = anonymous(make_client(monitors_enabled="false"))
    c.headers["Origin"] = "http://testserver"
    assert c.get("/api/owner/state").json()["configured"] is False
    assert c.post("/api/owner/setup/start", json={"email": OWNER, "setup_key": ADMIN_KEY}).status_code == 403


def test_signing_in_and_lock_out(console, clock):
    c = console
    secret, codes = set_up(c, clock)
    c.post("/api/owner/logout")
    assert c.get("/api/owner/console/overview").status_code == 401
    assert c.post("/api/owner/verify", json={"code": clock.code(secret)}).status_code == 401  # password first
    assert c.post("/api/owner/login", json={"email": OWNER, "password": "wrong pass phrase!"}).status_code == 401
    assert c.post("/api/owner/login", json={"email": "x@y.test", "password": PASSWORD}).status_code == 401
    c.post("/api/owner/login", json={"email": OWNER, "password": PASSWORD})
    assert c.get("/api/owner/console/overview").status_code == 401  # the password alone opens nothing
    good = clock.code(secret)
    assert c.post("/api/owner/verify", json={"code": good}).status_code == 200
    c.post("/api/owner/logout")
    c.post("/api/owner/login", json={"email": OWNER, "password": PASSWORD})
    assert c.post("/api/owner/verify", json={"code": good}).status_code == 401  # a code works only once
    assert c.post("/api/owner/verify", json={"code": codes[0]}).json()["used_recovery_code"] is True
    c.post("/api/owner/logout")
    c.post("/api/owner/login", json={"email": OWNER, "password": PASSWORD})
    assert c.post("/api/owner/verify", json={"code": codes[0]}).status_code == 401  # recovery codes too
    for _ in range(4):  # 1 wrong since the last success; 4 more make five in a row
        c.post("/api/owner/login", json={"email": OWNER, "password": "wrong pass phrase!"})
    locked = c.post("/api/owner/login", json={"email": OWNER, "password": PASSWORD})
    assert locked.status_code == 423  # even the right password waits
    assert any("locked" in m["Subject"] for m in c.outbox) and any("New sign-in" in m["Subject"] for m in c.outbox)
    actions = [e["action"] for e in c.app.state.audit and c.portal.call(c.app.state.audit.list, 100)]
    assert {"owner.setup", "owner.sign_in", "owner.sign_in_failed"} <= set(actions)


def test_settings_change_live(console, clock, fake_stripe):  # noqa: F811
    c = console
    secret, _codes = set_up(c, clock)
    settings = c.app.state.settings
    config = c.get("/api/owner/console/config").json()
    row = next(s for s in config["settings"] if s["name"] == "stripe_secret_key")
    assert row["set"] is False and "value" not in row
    bad = c.put("/api/owner/console/config", json={"values": {"stripe_secret_key": "not a key"}})
    assert bad.status_code == 422 and "Stripe secret key" in bad.json()["detail"]
    saved = c.put("/api/owner/console/config", json={"values": {
        "stripe_secret_key": "sk_test_argus", "stripe_price_personal": "price_personal", "trial_days": 21,
        "account_signup_enabled": True, "support_email": "help@argus.test"}})  # fmt: skip
    assert saved.status_code == 200
    rows = {r["name"]: r for r in saved.json()["settings"]}
    assert rows["stripe_secret_key"] == {
        **rows["stripe_secret_key"],
        "set": True,
        "ends_with": "rgus",
        "source": "console",
    }
    assert "sk_test_argus" not in saved.text  # never shown back
    assert stripe_billing.enabled(settings) and settings.trial_days == 21 and settings.account_signup_enabled
    stored = c.portal.call(c.app.state.app_state.get, runtime_config.STATE_KEY)
    assert "sk_test_argus" not in str(stored)  # encrypted at rest
    audit = c.portal.call(c.app.state.audit.list, 50, "owner.config")
    assert "sk_test_argus" not in str(audit) and "stripe_secret_key" in str(audit)
    assert c.post("/api/owner/console/test-stripe").json() == {
        "ok": True,
        "plans_found": ["personal"],
        "plans_missing": [],
    }
    assert c.post("/api/owner/console/test-email").json()["to"] == OWNER
    back = c.put("/api/owner/console/config", json={"values": {"trial_days": None}})  # the deployment's again
    assert back.status_code == 200 and settings.trial_days == 14

    plans = c.put("/api/owner/console/plans", json={"plans": {"personal": {"monthly_credits": 750, "max_devices": 3}}})
    assert (
        plans.status_code == 200
        and PLANS["personal"]["monthly_credits"] == 750
        and PLANS["personal"]["max_devices"] == 3
    )
    assert c.put("/api/owner/console/plans", json={"plans": {"personal": {"monthly_credits": -5}}}).status_code == 422

    # sensitive changes need a code from the last 10 minutes
    async def age_sessions():
        from sqlalchemy import update

        from argus.storage.db import OwnerSessionRow

        async with c.app.state.db.session() as s, s.begin():
            await s.execute(
                update(OwnerSessionRow).values(confirmed_at=datetime.now(timezone.utc) - timedelta(hours=1))
            )

    c.portal.call(age_sessions)
    stale = c.put("/api/owner/console/config", json={"values": {"trial_days": 30}})
    assert stale.status_code == 401 and stale.headers["x-argus-confirm"] == "code"
    assert c.post("/api/owner/confirm", json={"code": clock.code(secret)}).status_code == 200
    assert c.put("/api/owner/console/config", json={"values": {"trial_days": 30}}).status_code == 200


def test_health_and_the_main_app(console, clock):
    c = console
    set_up(c, clock)
    overview = c.get("/api/owner/console/overview").json()
    names = {h["name"]: h for h in overview["health"]}
    assert names["Database"]["status"] == "ok" and names["Payments"]["status"] == "off"
    assert names["Email"]["status"] == "ok" and names["Background: Customer emails"]["status"] == "ok"
    assert overview["business"]["customers"]["accounts"] == 0
    # the owner's session opens the main app as its administrator, with no API key
    assert c.get("/api/accounts").status_code == 200 and c.get("/api/me").json()["name"] == "owner"
    # "only me": API keys can no longer administer
    c.put("/api/owner/console/config", json={"values": {"admin_keys_allowed": False}})
    with_key = c.get("/api/accounts", headers={"Authorization": f"Bearer {ADMIN_KEY}"})  # a key wins over the cookie
    assert with_key.status_code == 403 and "owner" in with_key.json()["detail"]
    keys = c.get("/api/owner/console/keys").json()["keys"]
    assert keys and keys[0]["name"] == "bootstrap-admin"
    assert c.post(f"/api/owner/console/keys/{keys[0]['id']}/revoke").status_code == 200
    # with the owner set up, no admin key is ever recreated
    from argus.api.server import _install_bootstrap_key

    c.portal.call(_install_bootstrap_key, c.app, c.app.state.settings)
    assert c.portal.call(c.app.state.keys.count_active) == 0


def test_the_owners_own_security(console, clock):
    c = console
    secret, _codes = set_up(c, clock)
    sec = c.get("/api/owner/security").json()
    assert sec["email"] == OWNER and sec["recovery_left"] == 10 and sec["sessions"][0]["current"] is True
    new_codes = c.post("/api/owner/recovery-codes").json()["recovery_codes"]
    assert len(new_codes) == 10
    bad = c.post("/api/owner/password", json={"current": "not it at all", "new": "another long pass phrase"})
    assert bad.status_code == 401
    changed = c.post("/api/owner/password", json={"current": PASSWORD, "new": "another long pass phrase"})
    assert changed.status_code == 200
    started = c.post("/api/owner/authenticator/start").json()
    new_secret = started["secret"]
    assert c.post("/api/owner/authenticator/finish", json={"code": "000000"}).status_code == 422
    assert c.post("/api/owner/authenticator/finish", json={"code": clock.code(new_secret)}).status_code == 200
    c.post("/api/owner/logout")
    c.post("/api/owner/login", json={"email": OWNER, "password": "another long pass phrase"})
    assert c.post("/api/owner/verify", json={"code": clock.code(secret)}).status_code == 401  # the old phone
    assert c.post("/api/owner/verify", json={"code": clock.code(new_secret)}).status_code == 200


def test_not_in_argus_personal(make_client):
    c = make_client(edition="personal", monitors_enabled="false", capture_browser="off")
    assert c.get("/api/owner/state").status_code in (401, 404)  # never reachable on someone's own computer
