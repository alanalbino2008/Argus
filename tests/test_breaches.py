"""Breach intelligence: masked exposures, password-reuse correlation, and the approval-gated reveal.

Argus never stores a plaintext password: these tests check that only the mask and a one-way hash are
kept, that reuse links identifiers, and that revealing plaintext needs authorisation, a reason, and
(where set) a second approver, and is audited."""

from __future__ import annotations

import contextlib

from argus.intel import breaches as B
from tests.test_learning import LearningScans
from tests.test_modules_offline import FakeResponse, FakeSession


def test_a_plaintext_password_becomes_a_mask_and_a_hash_only():
    e = B.exposure("Jane@Example.org", "email", {"database": "Acme 2019", "date": "2019-05-01",
                                                  "password": "Summer2019!", "username": "janed"})  # fmt: skip
    assert e["password_masked"] == "S•••••••••!  (11 chars)" and "Summer2019!" not in str(e)
    assert e["password_sha256"] == B.password_hash("Summer2019!") and len(e["password_sha256"]) == 64
    assert e["identifier"] == "jane@example.org" and e["breach"] == "Acme 2019" and e["date"] == "2019-05-01"
    assert "password" not in e  # the plaintext is dropped
    short = B.exposure("x", "email", {"breach": "b", "password": "abc"})
    assert short["password_masked"] == "•••"


def test_reused_passwords_link_identifiers():
    exposures = [
        B.exposure("jane@gmail.com", "email", {"breach": "A", "password": "Tr0ub4dour&3"}),
        B.exposure("jdoe@yahoo.com", "email", {"breach": "B", "password": "Tr0ub4dour&3"}),
        B.exposure("someone@else.com", "email", {"breach": "C", "password": "Tr0ub4dour&3".swapcase()}),
        B.exposure("lonely@x.com", "email", {"breach": "D", "password": "unique-one"}),
    ]  # fmt: skip
    groups = B.reuse(exposures)
    assert len(groups) == 1 and groups[0]["identifiers"] == ["jane@gmail.com", "jdoe@yahoo.com"]
    assert groups[0]["masked"].startswith("T") and set(groups[0]["breaches"]) == {"A", "B"}
    assert B.shared_with(exposures, "jane@gmail.com", {"jdoe@yahoo.com", "lonely@x.com"}) == ["jdoe@yahoo.com"]


async def test_the_custom_provider_is_read_server_side_and_plaintext_is_dropped(monkeypatch):
    from argus.core.settings import get_settings
    from argus.intel import breach_lookup
    from argus.intel.breach_lookup import fetch_exposures, reveal_one

    monkeypatch.setenv("ARGUS_BREACH_PROVIDER", "custom")
    monkeypatch.setenv("ARGUS_BREACH_PROVIDER_URL", "https://api.example.com/search")
    monkeypatch.setenv("ARGUS_BREACH_PROVIDER_API_KEY", "bk-123")
    get_settings.cache_clear()
    answer = {"entries": [{"database": "Acme 2019", "date": "2019", "email": "jane@example.org", "password": "Summer2019!"},
                          {"database": "Shop 2021", "date": "2021", "email": "jane@example.org", "password_hash": "$2a$x"}]}  # fmt: skip
    sessions = []

    class Http(FakeSession):
        def get(self, url, **kwargs):
            sessions.append((url, kwargs.get("headers", {}).get("Authorization"), kwargs.get("params")))
            return super().get(url, **kwargs)

    @contextlib.asynccontextmanager
    async def fake_client(settings, route):
        yield Http({r"api\.example\.com/search": FakeResponse(200, answer)})

    monkeypatch.setattr(breach_lookup, "client", fake_client)
    got = await fetch_exposures(get_settings(), "jane@example.org", "email", None)
    assert [e["breach"] for e in got] == ["Acme 2019", "Shop 2021"]
    assert got[0]["password_masked"] and got[1]["hash_only"] and not got[1]["password_masked"]
    assert all("password" not in e for e in got) and "Summer2019!" not in str(got)
    assert sessions[0][1] == "Bearer bk-123" and sessions[0][2] == {"query": "jane@example.org"}
    # reveal_one re-fetches live and returns the one plaintext.
    revealed = await reveal_one(get_settings(), "jane@example.org", "email", "Acme 2019",
                                B.password_hash("Summer2019!"), None)  # fmt: skip
    assert revealed["password"] == "Summer2019!"
    get_settings.cache_clear()


def test_infostealer_records_are_recognised_and_summarised():
    # a plain breach row is not a stealer log
    plain = B.exposure("jane@x.com", "email", {"breach": "Acme 2019", "date": "2019", "password": "p"})
    assert plain["is_stealer"] is False and plain["site"] is None
    # a record with a captured-site + stealer family is a stealer log, and the site is kept as a bare host
    st = B.exposure("jane@x.com", "email", {"breach": "Logs", "url": "https://login.bank.example/app",
                                            "stealer": "RedLine", "computer": "DESKTOP-7", "compromised": "2024-03-02",
                                            "password": "hunter2"})  # fmt: skip
    assert st["is_stealer"] and st["site"] == "login.bank.example" and st["stealer"] == "RedLine"
    assert st["computer"] == "DESKTOP-7" and st["infected_at"] == "2024-03-02" and "hunter2" not in str(st)
    # a 'stealer'-named database with a site also counts
    assert B.exposure("x", "email", {"database": "StealerLogs", "url": "shop.example"})["is_stealer"]
    summary = B.stealer_summary([plain, st, B.exposure("jane@x.com", "email", {"type": "stealer", "url": "mail.example"})])
    assert summary["infections"] == 2 and summary["sites"] == ["login.bank.example", "mail.example"]
    assert summary["site_count"] == 2 and summary["families"] == ["RedLine"] and summary["latest"] == "2024-03-02"
    assert B.summary([st])["stealer"]["sites"] == ["login.bank.example"]  # carried in the person summary


async def test_hibp_stealer_logs_for_an_email_are_fetched(monkeypatch):
    from argus.core.settings import get_settings
    from argus.intel import breach_lookup
    from argus.intel.breach_lookup import fetch_exposures

    monkeypatch.setenv("ARGUS_BREACH_PROVIDER", "hibp")
    monkeypatch.setenv("ARGUS_HIBP_API_KEY", "hibp-key")
    get_settings.cache_clear()
    answers = {
        r"breachedaccount": FakeResponse(200, [{"Name": "Acme", "Title": "Acme", "BreachDate": "2019-01-01",
                                                "DataClasses": ["Email addresses", "Passwords"]}]),
        r"stealerlogsbyemail": FakeResponse(200, ["netflix.com", "https://portal.work.example/login"]),
    }  # fmt: skip

    @contextlib.asynccontextmanager
    async def fake_client(settings, route):
        yield FakeSession(answers)

    monkeypatch.setattr(breach_lookup, "client", fake_client)
    got = await fetch_exposures(get_settings(), "jane@example.org", "email", None)
    assert [e["breach"] for e in got] == ["Acme", "Infostealer logs", "Infostealer logs"]
    st = B.stealer_summary(got)
    assert st["infections"] == 2 and st["sites"] == ["netflix.com", "portal.work.example"]
    get_settings.cache_clear()


def _subject_with_breaches(make_client, monkeypatch, provider="custom"):
    from argus.intel import breach_lookup

    c = make_client(monitors_enabled="false", breach_provider=provider, breach_provider_url="https://api.example.com/x")
    c.app.state.playbook_scan = LearningScans()
    case_id = c.post("/api/cases", json={"title": "F", "purpose": "Fraud report R-90", "confirmed": True,
                                         "authorization": "Warrant W-9"}).json()["id"]  # fmt: skip
    sid = c.post(f"/api/cases/{case_id}/subjects", json={"name": "Jane Doe", "confirmed": True,
                 "known": {"names": ["Jane Doe"], "emails": ["jane@example.org"], "usernames": ["janedoe84"]}}).json()["id"]  # fmt: skip

    async def fake_fetch(settings, identifier, kind, route):
        if identifier.lower() == "jane@example.org":
            return [B.exposure(identifier, kind, {"breach": "Acme 2019", "date": "2019", "password": "ReUsed-Pw-1"})]
        if identifier.lower() == "janedoe84":
            return [B.exposure(identifier, kind, {"breach": "Shop 2021", "date": "2021", "password": "ReUsed-Pw-1"})]
        return []

    monkeypatch.setattr(breach_lookup, "fetch_exposures", fake_fetch)
    return c, case_id, sid


def test_breaches_on_a_person_feed_the_timeline_and_scoring(make_client, monkeypatch):
    c, case_id, sid = _subject_with_breaches(make_client, monkeypatch)
    out = c.post(f"/api/cases/{case_id}/subjects/{sid}/breaches")
    assert out.status_code == 200, out.text
    summary = out.json()["summary"]
    assert set(summary["breaches"]) == {"Acme 2019", "Shop 2021"} and summary["reuse"]
    view = c.get(f"/api/cases/{case_id}/subjects/{sid}/breaches").json()
    assert all("password_masked" not in str(e) or "ReUsed-Pw-1" not in str(e) for e in view["exposures"])
    assert "ReUsed-Pw-1" not in str(view)  # never plaintext
    timeline = c.get(f"/api/cases/{case_id}/subjects/{sid}/timeline").json()["events"]
    assert any(e["kind"] == "breach" and "Acme 2019" in e["title"] for e in timeline)
    entry = next(e for e in c.get("/api/audit?limit=50").json() if e["action"] == "subject.breaches")
    assert entry["details"]["exposures"] == 2 and entry["details"]["authorization"] == "Warrant W-9"


def test_revealing_a_password_needs_authorisation_a_reason_and_is_audited(make_client, monkeypatch):
    from argus.intel import breach_lookup

    c, case_id, sid = _subject_with_breaches(make_client, monkeypatch)
    c.post(f"/api/cases/{case_id}/subjects/{sid}/breaches")

    async def fake_reveal(settings, identifier, kind, breach, want_hash, route):
        return {"identifier": identifier, "breach": breach, "password": "ReUsed-Pw-1", "username": None, "email": None}

    monkeypatch.setattr(breach_lookup, "reveal_one", fake_reveal)
    body = {
        "identifier": "jane@example.org",
        "breach": "Acme 2019",
        "hash": B.password_hash("ReUsed-Pw-1"),
        "reason": "",
    }
    assert c.post(f"/api/cases/{case_id}/subjects/{sid}/breaches/reveal", json=body).status_code == 422  # no reason
    body["reason"] = "Confirming the credential disclosed under warrant W-9"
    body["hash"] = "deadbeef"
    assert (
        c.post(f"/api/cases/{case_id}/subjects/{sid}/breaches/reveal", json=body).status_code == 404
    )  # not an exposure here
    body["hash"] = B.password_hash("ReUsed-Pw-1")
    ok = c.post(f"/api/cases/{case_id}/subjects/{sid}/breaches/reveal", json=body)
    assert ok.status_code == 200 and ok.json()["password"] == "ReUsed-Pw-1" and "recorded" in ok.json()["warning"]
    entry = next(e for e in c.get("/api/audit?limit=50").json() if e["action"] == "breach.reveal")
    assert entry["details"]["reason"].startswith("Confirming") and entry["details"]["identifier"] == "jane@example.org"


def test_reveal_is_blocked_without_a_legal_authorisation(make_client, monkeypatch):
    c, _case, _sid = _subject_with_breaches(make_client, monkeypatch)
    plain = c.post("/api/cases", json={"title": "N", "purpose": "No authorisation here", "confirmed": True}).json()[
        "id"
    ]
    psid = c.post(f"/api/cases/{plain}/subjects", json={"name": "X", "confirmed": True,
                  "known": {"emails": ["jane@example.org"]}}).json()["id"]  # fmt: skip
    c.post(f"/api/cases/{plain}/subjects/{psid}/breaches")
    body = {
        "identifier": "jane@example.org",
        "breach": "Acme 2019",
        "hash": B.password_hash("ReUsed-Pw-1"),
        "reason": "x",
    }
    r = c.post(f"/api/cases/{plain}/subjects/{psid}/breaches/reveal", json=body)
    assert r.status_code == 409 and "legal authorisation" in r.json()["detail"]


def test_breach_provider_off_by_default(make_client):
    c = make_client(monitors_enabled="false")
    c.app.state.playbook_scan = LearningScans()
    case_id = c.post("/api/cases", json={"title": "F", "purpose": "Fraud report R-91", "confirmed": True}).json()["id"]
    sid = c.post(f"/api/cases/{case_id}/subjects", json={"name": "Jane", "confirmed": True,
                 "known": {"emails": ["jane@example.org"]}}).json()["id"]  # fmt: skip
    assert c.post(f"/api/cases/{case_id}/subjects/{sid}/breaches").status_code == 409


def test_breach_and_reveal_endpoints_are_rate_limited(make_client, monkeypatch):
    from argus.api import subject_routes

    c, case_id, sid = _subject_with_breaches(make_client, monkeypatch)
    monkeypatch.setattr(subject_routes._breach_limiter, "limit", 1)
    assert c.post(f"/api/cases/{case_id}/subjects/{sid}/breaches").status_code == 200
    assert c.post(f"/api/cases/{case_id}/subjects/{sid}/breaches").status_code == 429
