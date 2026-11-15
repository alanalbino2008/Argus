"""Argus accounts: signed licences, the account service, and Argus Personal's licence gate."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from argus.accounts import licence as lic
from argus.accounts.passwords import hash_password, verify_password, weakness

PRIVATE, PUBLIC = lic.generate_keypair()
OTHER_PRIVATE, _OTHER_PUBLIC = lic.generate_keypair()
NOW = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)
GOOD_PHRASE = "correct horse battery"  # a test account's pass phrase
ACCOUNT = {"id": "acc_1", "email": "jane@example.org", "name": "Jane", "plan": "personal", "status": "active",
           "valid_until": (NOW + timedelta(days=30)).isoformat()}  # fmt: skip


def token(account=ACCOUNT, *, device="device-0123456789abcdef", issuer="https://accounts.test", key=PRIVATE,
          offline_days=14, now=NOW):  # fmt: skip
    return lic.issue(account, device_id=device, issuer=issuer, private=lic.load_private_key(key),
                     offline_days=offline_days, now=now)  # fmt: skip


# ---------------------------------------------------------------------------- licences
def test_licences_cannot_be_forged_or_edited():
    public = lic.load_public_key(PUBLIC)
    payload = lic.verify(token(), public, issuer="https://accounts.test")
    assert (
        payload["plan"] == "personal" and payload["plan_label"] == "Personal" and payload["device"].startswith("device")
    )
    prefix, body, signature = token().split(".")
    import base64

    edited = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    edited["valid_until"] = "2099-01-01T00:00:00+00:00"  # someone gives themselves 70 more years
    forged_body = base64.urlsafe_b64encode(json.dumps(edited).encode()).rstrip(b"=").decode()
    for bad, why in ((f"{prefix}.{forged_body}.{signature}", "signature"), (token(key=OTHER_PRIVATE), "signature"),
                     ("hello", "not an Argus licence"), (f"argus9.{body}.{signature}", "newer format")):  # fmt: skip
        with pytest.raises(lic.LicenceError, match=why):
            lic.verify(bad, public)
    with pytest.raises(lic.LicenceError, match="different account service"):
        lic.verify(token(issuer="https://evil.test"), public, issuer="https://accounts.test")
    with pytest.raises(lic.LicenceError, match="base64"):
        lic.load_private_key("not a key")


def test_what_a_licence_allows():
    public = lic.load_public_key(PUBLIC)
    ok = lic.verify(token(), public)
    assert lic.access(ok, NOW) == ("full", "")
    assert lic.access(None, NOW)[0] == "none"
    assert (
        lic.access(lic.verify(token({**ACCOUNT, "status": "past_due"}), public), NOW)[0] == "full"
    )  # payment retrying
    level, reason = lic.access(lic.verify(token({**ACCOUNT, "status": "cancelled"}), public), NOW)
    assert level == "read_only" and "readable and exportable" in reason
    level, reason = lic.access(ok, NOW + timedelta(days=31))
    assert level == "read_only" and "subscription ended on 15 December 2026" in reason
    trial = lic.verify(token({**ACCOUNT, "plan": "trial", "status": "trialing"}), public)
    assert "free trial ended" in lic.access(trial, NOW + timedelta(days=40))[1]
    level, reason = lic.access(ok, NOW + timedelta(days=15))  # paid up, but offline for too long
    assert level == "read_only" and "reach your account" in reason


def test_passwords():
    stored = hash_password("correct horse battery")
    assert stored.startswith("scrypt$") and verify_password("correct horse battery", stored)
    assert not verify_password("correct horse batterY", stored) and not verify_password("x", "garbage")
    assert hash_password("same password!") != hash_password("same password!")  # salted
    assert weakness("short", "a@b.test") and weakness("jane.roe@example.org", "jane.roe@example.org")
    assert weakness("aaaaaaaaaaaa", "a@b.test") and weakness("password123", "a@b.test")
    assert weakness("correct horse battery", "jane@example.org") is None


# ---------------------------------------------------------------------------- the account service
@pytest.fixture(autouse=True)
def _fresh_limits(monkeypatch):
    from argus.api import account_routes
    from argus.security.ratelimit import SlidingWindowLimiter

    monkeypatch.setattr(account_routes, "_per_ip", SlidingWindowLimiter(limit=20, window=60))
    monkeypatch.setattr(account_routes, "_signups", SlidingWindowLimiter(limit=5, window=3600))


@pytest.fixture
def service(make_client):
    return make_client(account_service_enabled="true", licence_signing_key=PRIVATE, account_signup_enabled="true",
                       public_url="http://testserver", monitors_enabled="false")  # fmt: skip


def sign_in(c, email="jane@example.org", password=GOOD_PHRASE, device="device-0123456789abcdef"):
    return c.post("/api/accounts/token", json={"email": email, "password": password, "device_id": device,
                                               "device_name": "Jane's laptop"})  # fmt: skip


def test_the_account_service_end_to_end(service):
    c = service
    keys = c.get("/api/accounts/public-key").json()
    assert keys["public_key"] == PUBLIC and keys["issuer"] == "http://testserver"
    assert c.post("/api/accounts/signup", json={"email": "jane@example.org", "password": "short"}).status_code == 422
    assert (
        c.post("/api/accounts/signup", json={"email": "not-an-email", "password": "correct horse battery"}).status_code
        == 422
    )
    created = c.post("/api/accounts/signup", json={"email": "Jane@Example.org", "password": "correct horse battery",
                                                    "name": "Jane"})  # fmt: skip
    assert created.status_code == 201 and created.json()["plan"] == "trial" and created.json()["status"] == "trialing"
    assert "password" not in json.dumps(created.json())
    assert (
        c.post("/api/accounts/signup", json={"email": "jane@example.org", "password": "another good one"}).status_code
        == 409
    )

    assert sign_in(c, password="wrong password!").status_code == 401
    assert (
        sign_in(c, email="nobody@example.org").json()["detail"] == "Wrong email or password"
    )  # same answer: no enumeration
    first = sign_in(c)
    assert first.status_code == 200
    payload = lic.verify(first.json()["licence"], lic.load_public_key(PUBLIC), issuer="http://testserver")
    assert payload["email"] == "jane@example.org" and payload["status"] == "trialing"
    assert sign_in(c).status_code == 200  # the same computer again is fine
    other = sign_in(c, device="device-ffffffffffffffff")
    assert other.status_code == 409 and "Sign out on one of them first" in other.json()["detail"]  # trial: one computer

    refreshed = c.post("/api/accounts/refresh", json={"licence": first.json()["licence"]})
    assert refreshed.status_code == 200
    account_id = payload["sub"]
    changed = c.patch(f"/api/accounts/{account_id}", json={"plan": "personal", "status": "active",
                                                           "valid_until": "2027-11-15T00:00:00"})  # fmt: skip
    assert changed.status_code == 200 and changed.json()["max_devices"] == 2
    renewed = lic.verify(c.post("/api/accounts/refresh", json={"licence": first.json()["licence"]}).json()["licence"],
                         lic.load_public_key(PUBLIC))  # fmt: skip
    assert renewed["plan"] == "personal" and renewed["valid_until"].startswith("2027-11-15")
    assert sign_in(c, device="device-ffffffffffffffff").status_code == 200  # the paid plan allows two

    assert c.post("/api/accounts/sign-out", json={"licence": first.json()["licence"]}).status_code == 204
    gone = c.post("/api/accounts/refresh", json={"licence": first.json()["licence"]})
    assert gone.status_code == 401 and "signed out" in gone.json()["detail"]
    assert (
        c.post(
            "/api/accounts/refresh", json={"licence": token(issuer="http://testserver", key=OTHER_PRIVATE)}
        ).status_code
        == 401
    )

    detail = c.get(f"/api/accounts/{account_id}").json()
    states = {d["device_id"]: d["revoked"] for d in detail["device_list"]}
    assert states == {"device-0123456789abcdef": True, "device-ffffffffffffffff": False}
    c.patch(f"/api/accounts/{account_id}", json={"status": "suspended"})
    assert sign_in(c, device="device-ffffffffffffffff").status_code == 403
    actions = [e["action"] for e in c.get("/api/audit").json()]
    assert {"account.signup", "account.sign_in", "account.update", "account.sign_out"} <= set(actions)


def test_repeated_wrong_passwords_lock_the_account(service):
    c = service
    c.post("/api/accounts/signup", json={"email": "jane@example.org", "password": "correct horse battery"})
    for _ in range(5):
        assert sign_in(c, password="wrong password!").status_code == 401
    assert sign_in(c).status_code == 423  # even the right password waits out the lock


def test_account_administration_is_for_platform_admins(service):
    key = service.post("/api/keys", json={"name": "vic", "role": "viewer"}).json()["key"]
    assert service.get("/api/accounts", headers={"Authorization": f"Bearer {key}"}).status_code == 403
    assert service.patch("/api/accounts/acc_x", json={"status": "active"}).status_code == 404


def test_the_service_is_off_unless_enabled(client):
    assert client.get("/api/accounts/public-key").status_code == 404
    assert client.post("/api/accounts/token", json={"email": "a@b.test", "password": "x" * 12,
                                                    "device_id": "d" * 16}).status_code == 404  # fmt: skip


# ---------------------------------------------------------------------------- Argus Personal
class FakeAccountService(ThreadingHTTPServer):
    """Stands in for the central account service (signs real licences with the test key)."""

    daemon_threads = True

    def __init__(self):
        self.account = {**ACCOUNT, "valid_until": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()}
        self.key = PRIVATE
        self.refuse_refresh: tuple[int, str] | None = None
        self.calls: list[tuple[str, dict]] = []
        super().__init__(("127.0.0.1", 0), FakeHandler)
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"


class FakeHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        s = self.server
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        s.calls.append((self.path, body))
        if self.path == "/api/accounts/token":
            if body.get("password") != "correct horse battery":
                return self._send(401, {"detail": "Wrong email or password"})
            return self._send(200, {"licence": self._licence(body["device_id"]), "account": s.account})
        if self.path == "/api/accounts/signup":
            return self._send(201, s.account)
        if self.path == "/api/accounts/refresh":
            if s.refuse_refresh:
                return self._send(s.refuse_refresh[0], {"detail": s.refuse_refresh[1]})
            device = lic.verify(body["licence"], lic.load_public_key(PUBLIC))["device"]
            return self._send(200, {"licence": self._licence(device), "account": s.account})
        if self.path == "/api/accounts/sign-out":
            return self._send(204, None)
        return self._send(404, {"detail": "nope"})

    def _licence(self, device):
        return lic.issue(self.server.account, device_id=device, issuer=self.server.url,
                         private=lic.load_private_key(self.server.key), offline_days=14)  # fmt: skip

    def _send(self, status, payload):
        data = b"" if payload is None else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


@pytest.fixture
def accounts():
    s = FakeAccountService()
    yield s
    s.shutdown()


@pytest.fixture
def personal(make_client, accounts):
    c = make_client(edition="personal", account_server_url=accounts.url, licence_public_key=PUBLIC,
                    monitors_enabled="false", capture_browser="off", allow_private_targets="true")  # fmt: skip
    c.headers["Origin"] = "http://testserver"  # the web app's own pages
    return c


def personal_sign_in(c, password=GOOD_PHRASE):
    return c.post("/api/personal/sign-in", json={"email": "jane@example.org", "password": password})


def new_case(c):
    return c.post(
        "/api/cases", json={"title": "Story", "purpose": "Checking a story for publication", "confirmed": True}
    )


def test_personal_needs_an_account_before_anything(personal):
    c = personal
    status = c.get("/api/personal/status").json()
    assert status["edition"] == "personal" and status["access"] == "none" and status["configured"]
    config = c.get("/api/auth/config").json()
    assert config["personal"]["access"] == "none" and config["api_keys"] is False
    blocked = c.get("/api/me")  # even with the installation's admin API key
    assert blocked.status_code == 401 and blocked.json()["sign_in"] is True
    assert new_case(c).status_code == 401
    assert personal_sign_in(c, password="nope").status_code == 401
    cross = c.post(
        "/api/personal/sign-in", json={"email": "j@x.test", "password": "x"}, headers={"Origin": "https://evil.test"}
    )
    assert cross.status_code == 403  # another site cannot sign this browser in


def test_personal_full_read_only_and_back(personal, accounts):
    c = personal
    signed = personal_sign_in(c)
    assert signed.status_code == 200 and signed.json()["access"] == "full" and "argus_session" in c.cookies
    del c.headers["Authorization"]  # from here on, only the session from the account sign-in
    me = c.get("/api/me").json()
    assert me["name"] == "jane@example.org" and me["auth"] == "session"
    case = new_case(c)
    assert case.status_code == 201
    upload = c.post(f"/api/cases/{case.json()['id']}/uploads", files={"file": ("note.txt", b"evidence", "text/plain")})
    assert upload.status_code == 201
    sent = json.dumps(accounts.calls)
    assert len(accounts.calls[0][1]["device_id"]) >= 24 and "Checking a story" not in sent and "note.txt" not in sent

    accounts.account = {**accounts.account, "status": "cancelled"}
    status = c.post("/api/personal/refresh").json()
    assert status["access"] == "read_only" and status["status"] == "cancelled"
    refused = new_case(c)
    assert refused.status_code == 402 and refused.json()["read_only"] is True
    assert c.get("/api/cases").status_code == 200  # still readable
    assert c.get(f"/api/cases/{case.json()['id']}/export").status_code == 200  # still exportable
    assert c.post(f"/api/evidence/{upload.json()['id']}/verify").json()["intact"]  # still verifiable

    accounts.account = {**accounts.account, "status": "active"}
    assert c.post("/api/personal/refresh").json()["access"] == "full"
    assert new_case(c).status_code == 201


def test_personal_keeps_working_offline(personal, accounts):
    c = personal
    personal_sign_in(c)
    accounts.shutdown()  # the account service is unreachable: the licence carries on
    status = c.post("/api/personal/refresh").json()
    assert status["access"] == "full" and "could not be reached" in status["renewal_problem"]


def test_personal_revoked_elsewhere_becomes_read_only(personal, accounts):
    c = personal
    personal_sign_in(c)
    accounts.refuse_refresh = (401, "This computer was signed out of the account: sign in again")
    status = c.post("/api/personal/refresh").json()
    assert status["access"] == "read_only" and "signed out of the account" in status["reason"]
    assert new_case(c).status_code == 402


def test_personal_rejects_licences_it_cannot_trust(personal, accounts):
    accounts.key = OTHER_PRIVATE  # someone else's key: not the configured public key
    r = personal_sign_in(personal)
    assert r.status_code == 502 and "cannot trust" in r.json()["detail"]
    assert personal.get("/api/personal/status").json()["access"] == "none"


def test_an_expired_subscription_signs_in_read_only(personal, accounts):
    accounts.account = {**accounts.account, "valid_until": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()}
    status = personal_sign_in(personal).json()
    assert status["access"] == "read_only" and "ended on" in status["reason"]
    assert new_case(personal).status_code == 402


def test_signing_out_locks_the_app_again(personal, accounts):
    c = personal
    personal_sign_in(c)
    out = c.post("/api/personal/sign-out")
    assert out.status_code == 200 and out.json()["access"] == "none"
    assert accounts.calls[-1][0] == "/api/accounts/sign-out"  # the computer's place on the account is freed
    assert c.get("/api/cases").status_code == 401


async def test_the_licence_survives_a_restart_on_this_computer_only(tmp_path):
    from argus.accounts.personal import PersonalLicence
    from argus.core.settings import Settings

    class Memory:
        def __init__(self):
            self.data = {}

        async def get(self, key):
            return self.data.get(key)

        async def set(self, key, value):
            self.data[key] = value

        async def delete(self, key):
            self.data.pop(key, None)

    settings = Settings(edition="personal", account_server_url="https://accounts.test", licence_public_key=PUBLIC)
    store = Memory()
    first = PersonalLicence(settings, store)
    await first.load()
    await first._store(token(device=first.device_id, now=datetime.now(timezone.utc)))
    again = PersonalLicence(settings, store)
    await again.load()
    assert again.access()[0] == "full" and again.device_id == first.device_id
    store.data["licence"] = {"token": token(device="another-computer-000", now=datetime.now(timezone.utc))}
    copied = PersonalLicence(settings, store)
    await copied.load()  # a licence copied from another computer is refused
    assert copied.access()[0] == "none" and "licence" not in store.data


def test_the_python_client_can_manage_subscriptions(service):
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "clients" / "python"))
    from argus_client import ArgusClient

    service.post("/api/accounts/signup", json={"email": "jane@example.org", "password": GOOD_PHRASE})
    argus = ArgusClient(http=service)
    account = argus.subscription_accounts()[0]
    updated = argus.set_subscription(account["id"], plan="professional", status="active", billing_reference="cus_123")
    assert (
        updated["plan"] == "professional" and updated["max_devices"] == 3 and updated["billing_reference"] == "cus_123"
    )
