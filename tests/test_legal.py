"""Legal and privacy: the documents, accepting them, customers' data rights, retention, case reviews."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from argus.accounts import legal, privacy
from argus.core.settings import Settings
from tests import test_teams
from tests.test_accounts import GOOD_PHRASE, PUBLIC, FakeAccountService, FakeHandler
from tests.test_plans import on_plan

fake_stripe, service = test_teams.fake_stripe, test_teams.service  # the account service fixtures
owner_with_team, payload, sign_in = test_teams.owner_with_team, test_teams.payload, test_teams.sign_in


def publish(c, version="2026-11-20", **details):
    s = c.app.state.settings
    s.legal_terms_version = version
    for key, value in details.items():
        setattr(s, key, value)


def signup(c, email="jane@example.org", **extra):
    return c.post("/api/accounts/signup", json={"email": email, "password": GOOD_PHRASE, **extra})


# ---------------------------------------------------------------------------- the documents
def test_the_documents(service):
    c = service
    page = c.get("/legal/terms")
    assert page.status_code == 200 and "Draft: these documents have not been published" in page.text
    assert "[your business&#x27;s legal name]" in page.text  # a visible gap until the owner fills it in
    publish(c, legal_company_name="Acme <script>alert(1)</script> Ltd", legal_contact_email="hello@acme.example",
            legal_company_address="1 High Street, London", legal_hosting_provider="Hetzner | Germany (EU)")  # fmt: skip
    page = c.get("/legal/privacy").text
    assert "Acme &lt;script&gt;" in page and "<script>alert" not in page  # the owner's details are text
    assert "Version 2026-11-20" in page and "Draft" not in page and "hello@acme.example" in page
    assert "Germany (EU)" in c.get("/legal/subprocessors").text
    for doc in legal.DOCS:
        assert c.get(f"/legal/{doc}").status_code == 200
    assert c.get("/legal/../../etc/passwd").status_code == 404 and c.get("/legal/nonsense").status_code == 404
    index = c.get("/api/legal").json()
    assert index["version"] == "2026-11-20" and index["documents"]["terms"] == "http://testserver/legal/terms"


def test_not_on_other_servers(make_client):
    c = make_client(monitors_enabled="false")
    assert c.get("/legal/terms").status_code == 404 and c.get("/api/legal").status_code == 404


def test_markdown_rendering():
    out = legal.to_html(
        "# T\n\nA **b** [x](/legal/terms) [y](javascript:alert(1))\n\n- one\n- two\n\n| a | b |\n|---|---|\n| 1 | 2 |"
    )
    assert "<h1>T</h1>" in out and "<strong>b</strong>" in out and '<a href="/legal/terms">x</a>' in out
    assert "javascript" not in out.split("[y]")[0] and 'href="javascript' not in out
    assert "<ul><li>one</li><li>two</li></ul>" in out and "<th>a</th>" in out and "<td>2</td>" in out


def test_console_health():
    s = Settings(account_service_enabled=True)
    assert legal.health(s)[0] == "warn" and "Missing" in legal.health(s)[1]
    s = Settings(legal_company_name="A", legal_company_address="B", legal_contact_email="c@d.example")
    assert "Not published" in legal.health(s)[1]
    s.legal_terms_version = "2026-11-20"
    assert "not yet reviewed by a lawyer" in legal.health(s)[1]
    s.legal_reviewed = True
    assert legal.health(s)[0] == "ok"


# ---------------------------------------------------------------------------- accepting them
def test_accepting_and_accepting_again(service):
    c = service
    assert signup(c, "early@example.org").status_code == 201  # not published yet: nothing to accept
    publish(c, "2026-11-20")
    r = signup(c)
    assert r.status_code == 422 and "Agree to the Terms" in r.json()["detail"]
    made = signup(c, accept_terms=True).json()
    assert made["terms_version"] == "2026-11-20" and made["terms_accepted_at"]
    signed = sign_in(c, "jane@example.org").json()
    assert signed["terms"]["required"] is False and signed["terms"]["documents"]["privacy"].endswith("/legal/privacy")
    early = sign_in(c, "early@example.org", device="device-eeeeeeeeeeeeeeee").json()
    assert early["terms"]["required"] is True  # accounts from before must accept

    publish(c, "2027-01-15")  # the documents change
    refreshed = c.post("/api/accounts/refresh", json={"licence": signed["licence"]}).json()
    assert refreshed["terms"]["required"] is True and refreshed["terms"]["accepted_version"] == "2026-11-20"
    accepted = c.post("/api/accounts/accept-terms", json={"licence": signed["licence"]}).json()
    assert accepted["terms"]["required"] is False and accepted["terms"]["accepted_version"] == "2027-01-15"
    publish(c, "")
    assert c.post("/api/accounts/accept-terms", json={"licence": signed["licence"]}).status_code == 409
    actions = [e["action"] for e in c.get("/api/audit?limit=50").json()]
    assert "account.terms_accepted" in actions


# ---------------------------------------------------------------------------- data rights
def test_a_copy_of_my_data(service):
    c = service
    signup(c)
    licence = sign_in(c, "jane@example.org").json()["licence"]
    data = c.post("/api/accounts/export", json={"licence": licence}).json()
    assert data["account"]["email"] == "jane@example.org" and "billing_reference" not in data["account"]
    assert "password" not in json.dumps(data).replace("password_reset", "") and len(data["computers"]) == 1
    assert data["credits"] and "cases" in data["note"]
    assert any(e["action"] == "account.signup" for e in data["security_log"])
    assert c.post("/api/accounts/export", json={"licence": "not a licence"}).status_code == 401


def test_deleting_an_account(service, fake_stripe):
    c = service
    acc, licence = owner_with_team(c, fake_stripe)
    c.portal.call(lambda: c.app.state.subscribers.record_payment("pi_1", acc, kind="subscription", amount=4900,
                                                                 currency="gbp"))  # fmt: skip
    member = c.post("/api/teams/add", json={"licence": licence, "email": "nina@agency.example", "name": "Nina"})
    assert member.status_code == 200
    body = {"licence": licence, "password": GOOD_PHRASE, "confirm": "DELETE"}
    assert c.post("/api/accounts/delete", json={**body, "confirm": "yes"}).status_code == 422
    assert c.post("/api/accounts/delete", json={**body, "password": "wrong password"}).status_code == 401
    blocked = c.post("/api/accounts/delete", json=body)
    assert blocked.status_code == 409 and "team's members" in blocked.json()["detail"]
    nina = next(m for m in c.post("/api/teams/status", json={"licence": licence}).json()["members"]
                if m["email"] == "nina@agency.example")  # fmt: skip
    c.post("/api/teams/remove", json={"licence": licence, "member_id": nina["id"]})
    reference = c.get(f"/api/accounts/{acc}").json()["billing_reference"]

    assert c.post("/api/accounts/delete", json=body).json() == {"deleted": True}
    assert ("DELETE", f"/v1/customers/{reference}") in [(m, p) for m, p, *_ in fake_stripe.calls]  # ends billing too
    gone = c.get(f"/api/accounts/{acc}").json()
    assert gone["email"] == f"deleted-{acc}@deleted.invalid" and gone["name"] == "" and gone["deleted_at"]
    assert gone["status"] == "cancelled" and gone["billing_reference"] == ""
    assert c.portal.call(lambda: c.app.state.subscribers.devices(acc)) == []
    assert [p["id"] for p in c.portal.call(lambda: c.app.state.subscribers.payments(acc))] == ["pi_1"]  # tax records
    assert sign_in(c, "olivia@agency.example").status_code == 401
    assert c.post("/api/accounts/refresh", json={"licence": licence}).status_code == 401
    assert signup(c, "olivia@agency.example").status_code == 201  # the address is free again
    assert "account.deleted" in [e["action"] for e in c.get("/api/audit?limit=50").json()]


def test_retention(service):
    c = service
    acc = signup(c).json()["id"]
    repo = c.app.state.subscribers
    c.portal.call(
        lambda: c.app.state.mailer.notify({"id": acc, "email": "jane@example.org", "name": ""}, "welcome", "x")
    )
    test_teams.flush(c)
    sign_in(c, "jane@example.org")
    c.portal.call(lambda: repo.revoke_all_devices(acc))
    assert c.portal.call(lambda: privacy.purge(c.app)) == {"emails": 0, "devices": 0, "resets": 0, "invites": 0}
    later = datetime.now(timezone.utc) + timedelta(days=400)
    removed = c.portal.call(lambda: privacy.purge(c.app, later))
    assert removed["emails"] >= 1 and removed["devices"] == 1
    assert c.portal.call(lambda: c.app.state.account_mail.for_account(acc)) == []


# ---------------------------------------------------------------------------- in Argus Personal
class LegalHandler(FakeHandler):
    def do_POST(self):
        s = self.server
        if self.path in ("/api/accounts/accept-terms", "/api/accounts/export", "/api/accounts/delete"):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            s.calls.append((self.path, body))
            if self.path.endswith("accept-terms"):
                s.terms = {**s.terms, "required": False, "accepted_version": s.terms["version"]}
                return self._send(200, {"terms": s.terms})
            if self.path.endswith("export"):
                return self._send(200, {"account": {"email": "jane@example.org"}})
            if body.get("password") != GOOD_PHRASE:
                return self._send(401, {"detail": "Wrong password"})
            return self._send(200, {"deleted": True})
        return super().do_POST()

    def _send(self, status, payload):
        if isinstance(payload, dict) and "licence" in payload:
            payload = {**payload, "terms": self.server.terms}
        return super()._send(status, payload)


def personal_client(make_client):
    accounts = FakeAccountService()
    accounts.RequestHandlerClass = LegalHandler
    accounts.terms = {"version": "2026-11-20", "required": True, "accepted_version": None,
                      "documents": {"terms": f"{accounts.url}/legal/terms"}}  # fmt: skip
    c = make_client(edition="personal", account_server_url=accounts.url, licence_public_key=PUBLIC,
                    monitors_enabled="false", capture_browser="off")  # fmt: skip
    c.headers["Origin"] = "http://testserver"
    return c, accounts


def test_argus_personal_asks_to_accept(make_client):
    c, accounts = personal_client(make_client)
    try:
        r = c.post("/api/personal/sign-up", json={"email": "jane@example.org", "password": GOOD_PHRASE,
                                                   "accept_terms": True})  # fmt: skip
        assert r.status_code == 200
        assert next(b for p, b in accounts.calls if p == "/api/accounts/signup")["accept_terms"] is True
        status = c.get("/api/personal/status").json()
        assert status["terms"]["required"] is True
        made = c.post("/api/cases", json={"title": "Story", "purpose": "Checking a story", "confirmed": True})
        assert made.status_code == 403 and made.json()["terms"] is True  # new work waits...
        assert c.get("/api/cases").status_code == 200  # ...reading doesn't
        assert c.post("/api/personal/accept-terms").json()["terms"]["required"] is False
        assert (
            c.post("/api/cases", json={"title": "Story", "purpose": "Checking a story", "confirmed": True}).status_code
            == 201
        )

        download = c.get("/api/personal/account-data")
        assert download.status_code == 200 and "attachment" in download.headers["content-disposition"]
        assert download.json()["account"]["email"] == "jane@example.org"
        assert c.post("/api/personal/delete-account", json={"password": "nope", "confirm": "DELETE"}).status_code == 401
        gone = c.post("/api/personal/delete-account", json={"password": GOOD_PHRASE, "confirm": "DELETE"}).json()
        assert gone["signed_in"] is False
        assert c.get("/api/cases").status_code == 401  # signed out; the cases are still on this computer
    finally:
        accounts.shutdown()


def test_cases_due_for_review(make_client):
    c = make_client(monitors_enabled="false")
    case = c.post("/api/cases", json={"title": "Old", "purpose": "An old investigation", "confirmed": True}).json()
    assert c.get("/api/cases").json()[0]["review_due"] is False
    c.app.state.settings.case_review_months = 1
    from argus.storage.db import CaseRow

    async def age():
        async with c.app.state.db.session() as s, s.begin():
            row = await s.get(CaseRow, case["id"])
            row.updated_at = datetime.now(timezone.utc) - timedelta(days=45)

    c.portal.call(age)
    assert c.get("/api/cases").json()[0]["review_due"] is True
    c.app.state.settings.case_review_months = 0
    assert "review_due" not in c.get("/api/cases").json()[0]


def test_the_personal_plan_fixture_still_works(make_client):
    accounts = FakeAccountService()
    try:
        c = make_client(edition="personal", account_server_url=accounts.url, licence_public_key=PUBLIC,
                        monitors_enabled="false", capture_browser="off")  # fmt: skip
        c.headers["Origin"] = "http://testserver"
        on_plan(c, accounts, "professional")
        assert c.get("/api/personal/status").json()["terms"] is None  # an older service sends no terms: no prompt
    finally:
        accounts.shutdown()
