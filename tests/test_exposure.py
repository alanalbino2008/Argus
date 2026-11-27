"""Breach and dark-web exposure: rules, sources, the monitor, alerting, privacy and the API."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone

import pytest
from aiohttp import web

from argus.core.settings import Settings
from argus.intel import breach_sources
from argus.intel.breach_sources import BreachSources, SourceError, SourceUnavailable
from argus.intel.exposure import (
    account_findings,
    breach_severity,
    domain_breach_findings,
    headline,
    mask_email,
    normalise_name,
    ransomware_findings,
    stealer_findings,
)
from argus.intel.exposure_monitor import ExposureMonitor
from argus.notify import render

NOW = datetime(2026, 11, 15, tzinfo=timezone.utc)
RECENT = (NOW - timedelta(days=30)).isoformat()
CATALOGUE = {
    "FreshLeak": {"Name": "FreshLeak", "Title": "Fresh Leak", "BreachDate": "2026-10-01", "AddedDate": RECENT,
                  "DataClasses": ["Email addresses", "Passwords"], "IsVerified": True},
    "OldForum": {"Name": "OldForum", "Title": "Old Forum", "BreachDate": "2016-01-01", "AddedDate": "2017-01-01T00:00:00Z",
                 "DataClasses": ["Email addresses", "Passwords"]},
    "Newsletter": {"Name": "Newsletter", "Title": "Newsletter", "BreachDate": "2025-12-01", "AddedDate": RECENT,
                   "DataClasses": ["Email addresses", "Names"]},
    "Spam": {"Name": "Spam", "Title": "Spam list", "AddedDate": RECENT, "IsSpamList": True, "DataClasses": ["Passwords"]},
    "AcmeItself": {"Name": "AcmeItself", "Title": "Acme", "Domain": "acme.com", "BreachDate": "2026-09-01",
                   "AddedDate": RECENT, "DataClasses": ["Email addresses"]},
}  # fmt: skip


# ---------------------------------------------------------------------------- rules
def test_breach_severity_weighs_passwords_and_recency():
    assert [breach_severity(CATALOGUE[n], NOW) for n in ("FreshLeak", "OldForum", "Newsletter", "Spam")] == [
        "high", "medium", "low", "low"]  # fmt: skip


def test_findings_from_each_source():
    accounts = account_findings("acme.com", {"Alice.Smith": ["FreshLeak", "Unknown"]}, CATALOGUE, NOW)
    assert [(f.account, f.severity, f.details["breach_title"]) for f in accounts] == [
        ("alice.smith@acme.com", "high", "Fresh Leak"), ("alice.smith@acme.com", "low", "Unknown")]  # fmt: skip
    assert accounts[0].details["data_classes"] == ["Email addresses", "Passwords"]
    [stealer] = stealer_findings("acme.com", {"bob": ["https://vpn.acme.com/login", "portal.example", "vpn.acme.com"]})
    assert stealer.severity == "critical" and stealer.details["websites"] == ["portal.example", "vpn.acme.com"]
    [own] = domain_breach_findings("acme.com", CATALOGUE, NOW, subject_name="Acme")
    assert own.severity == "high" and own.title == "Acme was breached: Acme"
    assert domain_breach_findings("notacme.com", CATALOGUE, NOW) == []


def test_ransomware_posts_match_by_domain_or_exact_name_only():
    posts = [
        {"post_title": "acme.com", "group_name": "lockbit3", "discovered": RECENT},  # victim given as a domain
        {"victim": "Acme Corporation Ltd", "group": "akira", "discovered": RECENT},  # name only
        {"victim": "Acme Holdings", "group": "akira", "discovered": "2020-01-01"},  # name, but old
        {"victim": "notacme.com", "group": "x", "discovered": RECENT},  # a different organisation
        {"victim": "Acmeville Bakery", "group": "y", "discovered": RECENT},  # merely similar
        {"victim": "Other", "website": "https://shop.acme.com", "group": "play", "discovered": RECENT},  # subdomain
        "garbage",
    ]
    found = ransomware_findings("acme.com", posts, NOW, names=("ACME Corp.",))
    assert [(f.details["group"], f.details["match"], f.severity) for f in found] == [
        ("lockbit3", "domain", "critical"), ("akira", "name", "high"), ("akira", "name", "medium"),
        ("play", "domain", "critical")]  # fmt: skip
    assert "(matched by name)" in found[1].title
    again = ransomware_findings("acme.com", posts + posts[:1], NOW, names=("ACME Corp.",))
    assert len(again) == 4  # the same post twice is one finding
    assert normalise_name("ACME, Inc.") == normalise_name("Acme Corporation") == "acme"


def test_masking_and_headlines_never_name_people():
    assert mask_email("alice.smith@acme.com") == "a•••h@acme.com" and mask_email("al@acme.com") == "a•••@acme.com"
    new = [{"kind": "stealer_log", "account": "bob@acme.com", "details": {}},
           {"kind": "breach_account", "account": "a@acme.com", "details": {"breach_title": "Fresh Leak"}},
           {"kind": "breach_account", "account": "b@acme.com", "details": {"breach_title": "Fresh Leak"}},
           {"kind": "ransomware_post", "details": {"group": "akira"}}]  # fmt: skip
    text = headline("acme.com", new, baseline=False, subject_name="Acme")
    assert text == ("New exposure for Acme: named on the akira ransomware leak site; 1 staff account in infostealer "
                    "logs; 2 staff accounts in a new breach (Fresh Leak)")  # fmt: skip
    assert "@" not in text


# ---------------------------------------------------------------------------- the source client
@pytest.fixture
async def fake_sources(monkeypatch):
    """HIBP and a ransomware feed on localhost."""
    calls: list[str] = []
    state = {"domain_status": 200, "stealer_status": 403}

    async def breaches(request):
        calls.append("breaches")
        return web.json_response(list(CATALOGUE.values()))

    async def domain(request):
        calls.append(f"domain:{request.headers.get('hibp-api-key')}")
        if state["domain_status"] != 200:
            return web.json_response({}, status=state["domain_status"], headers={"Retry-After": "2"})
        return web.json_response({"alice": ["FreshLeak"], "bob": ["OldForum"]})

    async def stealer(request):
        return web.json_response({"carol": ["vpn.acme.com"]}, status=state["stealer_status"])

    async def victims(request):
        calls.append(f"ransomware:{request.match_info['q']}")
        return web.json_response({"victims": [{"victim": "acme.com", "group": "akira", "discovered": RECENT}]})

    app = web.Application()
    app.router.add_get("/api/v3/breaches", breaches)
    app.router.add_get("/api/v3/breacheddomain/{d}", domain)
    app.router.add_get("/api/v3/stealerlogsbyemaildomain/{d}", stealer)
    app.router.add_get("/feed/searchvictims/{q}", victims)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    base = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
    monkeypatch.setattr(breach_sources, "HIBP", f"{base}/api/v3")
    monkeypatch.setattr(breach_sources, "HIBP_SPACING", 0)
    monkeypatch.setattr(breach_sources, "FEED_SPACING", 0)
    yield {"base": base, "calls": calls, "state": state}
    await runner.cleanup()


async def test_the_source_client_reads_hibp_and_the_feed(fake_sources):
    settings = Settings(
        allow_private_targets=True, hibp_api_key="hibp-key", ransomware_feed_url=f"{fake_sources['base']}/feed/"
    )
    sources = BreachSources(settings)
    try:
        assert set(await sources.catalogue()) == set(CATALOGUE)
        await sources.catalogue()
        assert fake_sources["calls"].count("breaches") == 1  # cached
        assert await sources.domain_accounts("acme.com") == {"alice": ["FreshLeak"], "bob": ["OldForum"]}
        assert "domain:hibp-key" in fake_sources["calls"]
        with pytest.raises(SourceUnavailable, match="verify it in your HIBP domain search"):
            await sources.stealer_accounts("acme.com")  # 403: unverified domain or not on the plan
        fake_sources["state"]["stealer_status"] = 200
        assert await sources.stealer_accounts("acme.com") == {"carol": ["vpn.acme.com"]}
        fake_sources["state"]["domain_status"] = 429
        with pytest.raises(SourceError, match="rate limit"):
            await sources.domain_accounts("acme.com")
        fake_sources["state"]["domain_status"] = 404
        assert await sources.domain_accounts("acme.com") == {}
        [post] = await sources.ransomware_posts("Acme Corp")
        assert post["group"] == "akira" and "ransomware:Acme Corp" in fake_sources["calls"]
    finally:
        await sources.close()
    keyless = BreachSources(Settings(ransomware_feed_url=""))
    assert keyless.capabilities() == {"breach_catalogue": True, "domain_search": False, "stealer_logs": False,
                                      "ransomware": False}  # fmt: skip
    with pytest.raises(SourceUnavailable, match="ARGUS_HIBP_API_KEY"):
        await keyless.domain_accounts("acme.com")
    with pytest.raises(SourceUnavailable, match="turned off"):
        await keyless.ransomware_posts("acme")
    await keyless.close()


async def test_sources_refuse_private_addresses_by_default():
    sources = BreachSources(Settings(ransomware_feed_url="http://127.0.0.1:9/feed"))
    try:
        with pytest.raises(SourceError):
            await sources.ransomware_posts("acme")
    finally:
        await sources.close()


# ---------------------------------------------------------------------------- the monitor
class FakeSources:
    def __init__(self):
        self.accounts = {"alice": ["OldForum"], "bob": ["Newsletter"]}
        self.stealer: dict | Exception = SourceUnavailable("Needs a Have I Been Pwned API key")
        self.stealer_emails: dict[str, list] = {}
        self.posts: dict[str, list] = {}
        self.catalogue_error: Exception | None = None

    def capabilities(self):
        return {"breach_catalogue": True, "domain_search": True, "stealer_logs": False, "ransomware": True}

    async def catalogue(self):
        if self.catalogue_error:
            raise self.catalogue_error
        return CATALOGUE

    async def domain_accounts(self, domain):
        return self.accounts

    async def stealer_accounts(self, domain):
        if isinstance(self.stealer, Exception):
            raise self.stealer
        return self.stealer

    async def ransomware_posts(self, keyword):
        return self.posts.get(keyword, [])

    async def stealer_by_email(self, email):
        return self.stealer_emails.get(email, [])

    async def close(self):
        pass


@pytest.fixture
def client(make_client):
    return make_client(monitors_enabled="false", notifications_enabled="false", report_schedules_enabled="false")


class FakeDarkWeb:
    """A stand-in for DarkWebSources: returns canned index/paste hits, or raises to simulate 'off'."""

    def __init__(self):
        self.index_hits: list | Exception = SourceUnavailable("The dark-web index is off")
        self.paste_hits: list | Exception = SourceUnavailable("The paste/leak-forum monitor is off")

    def capabilities(self):
        return {"darkweb_index": not isinstance(self.index_hits, Exception),
                "paste_monitor": not isinstance(self.paste_hits, Exception)}  # fmt: skip

    async def index(self, selector):
        if isinstance(self.index_hits, Exception):
            raise self.index_hits
        return self.index_hits

    async def pastes(self, selector):
        if isinstance(self.paste_hits, Exception):
            raise self.paste_hits
        return self.paste_hits

    async def close(self):
        pass


def install(client, sources, darkweb=None):
    app = client.app
    app.state.exposure_monitor = ExposureMonitor(
        app.state.exposure, app.state.settings, sources=sources, darkweb=darkweb or FakeDarkWeb(),
        suppliers=lambda ws: app.state.suppliers.list_suppliers(workspace_id=ws),
    )  # fmt: skip
    return app.state.exposure_monitor


BASIS = "Our corporate domain, monitored by the SOC"


def watch(client, domain="acme.com", **extra):
    body = {"domain": domain, "organisation": "Acme Corp", "basis": BASIS, "authorized": True, **extra}
    return client.post("/api/exposure/watches", json=body)


def test_baseline_alerts_only_on_serious_findings_then_every_new_one(client):
    sources = FakeSources()
    monitor = install(client, sources)
    created = watch(client)
    assert created.status_code == 201, created.text
    [outcome] = client.portal.call(monitor.tick)
    # Baseline: an old breach (medium), a newsletter (low) and the organisation's own 2026 breach (high).
    assert outcome["status"] == "ok"  # a source not available on this plan is not an error
    assert outcome["new"] == 3 and outcome["alert"]
    [alert] = client.get("/api/alerts").json()
    assert alert["severity"] == "high" and alert["headline"] == "First exposure check for Acme Corp: breached (Acme)"
    assert alert["summary"]["exposure"]["baseline"] is True
    assert client.portal.call(monitor.tick) == []  # not due again yet

    # The next check finds an infostealer infection and a leak-site post.
    sources.stealer = {"carol": ["vpn.acme.com"]}
    sources.posts = {
        "Acme Corp": [{"victim": "Acme Corp", "group": "akira", "discovered": datetime.now(timezone.utc).isoformat()}]
    }
    client.post(f"/api/exposure/watches/{created.json()['id']}/check")
    [outcome] = client.portal.call(monitor.tick)
    assert outcome["new"] == 2
    latest = client.get("/api/alerts").json()[0]
    assert latest["severity"] == "critical"
    assert latest["headline"] == ("New exposure for Acme Corp: named on the akira ransomware leak site; "
                                  "1 staff account in infostealer logs")  # fmt: skip
    assert "carol" not in json.dumps(latest) and "@" not in json.dumps(latest)  # alerts travel; addresses stay

    client.post(f"/api/exposure/watches/{created.json()['id']}/check")
    assert client.portal.call(monitor.tick)[0]["new"] == 0  # the same things again: nothing new
    assert len(client.get("/api/alerts").json()) == 2


def test_a_failing_source_is_reported_and_others_still_run(client):
    sources = FakeSources()
    sources.catalogue_error = SourceError("Timed out")
    monitor = install(client, sources)
    w = watch(client).json()
    [outcome] = client.portal.call(monitor.tick)
    assert outcome["status"] == "partial"
    saved = client.get("/api/exposure").json()["watches"][0]
    assert saved["sources"]["breach_catalogue"] == {"status": "error", "message": "Timed out"}
    assert saved["sources"]["stealer_logs"]["status"] == "unavailable"
    assert saved["sources"]["domain_search"] == {"status": "ok", "found": 2}
    assert "breach_catalogue: Timed out" in saved["last_message"] and saved["checks"] == 1
    assert w["id"] == saved["id"]


def test_suppliers_are_swept_for_breaches_and_ransomware(client):
    sources = FakeSources()
    monitor = install(client, sources)
    supplier = {"name": "Acme Corp", "domain": "acme.com", "tier": "critical", "basis": "Contracted payroll provider",
                "authorized": True}  # fmt: skip
    assert client.post("/api/suppliers", json=supplier).status_code == 201
    sources.posts = {
        "acme.com": [{"victim": "acme.com", "group": "akira", "discovered": datetime.now(timezone.utc).isoformat()}]
    }
    [outcome] = client.portal.call(monitor.tick)
    assert outcome["new"] == 2
    data = client.get("/api/exposure").json()
    assert [w["scope"] for w in data["watches"]] == ["suppliers"]
    kinds = {f["kind"]: f for f in data["findings"]}
    assert set(kinds) == {"ransomware_post", "domain_breach"} and kinds["ransomware_post"]["supplier_id"]
    assert kinds["domain_breach"]["subject_name"] == "Acme Corp"
    alert = client.get("/api/alerts").json()[0]
    assert alert["headline"].startswith("First exposure check for supplier Acme Corp: named on the akira")
    assert alert["target"] == "supplier register" and alert["severity"] == "critical"
    [listed] = client.get("/api/suppliers").json()["suppliers"]
    assert listed["exposure"] == {"ransomware_post": 1, "domain_breach": 1}


# ---------------------------------------------------------------------------- selector (dark-web) watches
def selector_watch(client, selector="Project Falcon", **extra):
    body = {"selector": selector, "label": "Codename", "basis": "Our unreleased product codename", "authorized": True,
            **extra}  # fmt: skip
    return client.post("/api/exposure/selectors", json=body)


def test_a_selector_watch_covers_the_dark_web_pastes_and_leak_feeds(client):
    sources = FakeSources()
    now = datetime.now(timezone.utc).isoformat()
    sources.posts = {"Project Falcon": [{"victim": "Project Falcon", "group": "akira", "discovered": now}]}
    darkweb = FakeDarkWeb()
    darkweb.index_hits = [{"title": "Falcon database dump", "onion": "http://abc123.onion/t/9",
                           "snippet": "Project Falcon credentials for sale", "date": now, "is_onion": True}]  # fmt: skip
    darkweb.paste_hits = [
        {"title": "falcon leak", "url": "https://paste.example/xy", "snippet": "combolist", "date": now}
    ]
    monitor = install(client, sources, darkweb)

    created = selector_watch(client)
    assert created.status_code == 201, created.text
    assert created.json()["scope"] == "selector" and created.json()["selector"] == "Project Falcon"

    [outcome] = client.portal.call(monitor.tick)
    assert outcome["status"] == "ok" and outcome["new"] == 3  # index + paste + ransomware
    data = client.get("/api/exposure?status=all").json()
    kinds = {f["kind"] for f in data["findings"]}
    assert kinds == {"darkweb_mention", "paste_leak", "ransomware_post"}
    dw = next(f for f in data["findings"] if f["kind"] == "darkweb_mention")
    # a leak-looking, recent mention is raised to high; the onion is kept but never fetched
    assert dw["severity"] == "high" and dw["details"]["onion"] == "http://abc123.onion/t/9"
    assert dw["subject"] == "Project Falcon" and dw["details"]["leak_signal"] is True
    caps = data["capabilities"]
    assert caps["darkweb_index"] is True and caps["paste_monitor"] is True

    # Re-running finds nothing new.
    client.post(f"/api/exposure/watches/{created.json()['id']}/check")
    assert client.portal.call(monitor.tick)[0]["new"] == 0


def test_an_email_selector_also_checks_infostealer_logs(client):
    sources = FakeSources()
    sources.stealer_emails = {"ceo@acme.com": ["netflix.com", "https://portal.work.example/login"]}
    monitor = install(client, sources)
    created = selector_watch(client, selector="ceo@acme.com")
    assert created.status_code == 201
    [outcome] = client.portal.call(monitor.tick)
    assert outcome["new"] == 1
    [f] = client.get("/api/exposure?status=all").json()["findings"]
    assert f["kind"] == "stealer_log" and f["severity"] == "critical" and f["subject"] == "ceo@acme.com"
    assert set(f["details"]["websites"]) == {"netflix.com", "portal.work.example"}


def test_selector_watch_validation_and_dedup(client):
    install(client, FakeSources())
    assert selector_watch(client, authorized=False).status_code == 422
    assert selector_watch(client, selector="x").status_code == 422  # too short
    first = selector_watch(client, selector="Acme Corp")
    assert first.status_code == 201
    assert selector_watch(client, selector="Acme Corp").status_code == 409  # already watched
    # a selector and a domain of the same text are different scopes and both allowed
    assert watch(client, domain="acme.com").status_code == 201


def test_selector_watch_without_providers_reports_them_unavailable(client):
    sources = FakeSources()
    sources.posts = {}
    monitor = install(client, sources)  # FakeDarkWeb defaults to "off"
    created = selector_watch(client)
    [outcome] = client.portal.call(monitor.tick)
    assert outcome["status"] in ("ok", "partial")  # unavailable providers are not errors
    saved = next(w for w in client.get("/api/exposure").json()["watches"] if w["id"] == created.json()["id"])
    assert saved["sources"]["darkweb_index"]["status"] == "unavailable"
    assert saved["sources"]["paste_monitor"]["status"] == "unavailable"


# ---------------------------------------------------------------------------- privacy, triage and the API
def test_addresses_are_masked_and_revealing_or_exporting_them_is_audited(client):
    client.post("/api/demo")
    data = client.get("/api/exposure").json()
    assert data["summary"]["open"] == 9 and data["summary"]["accounts"] == 6
    assert data["summary"]["by_kind"]["stealer_log"] == 1 and data["summary"]["by_kind"]["ransomware_post"] == 1
    assert [f["kind"] for f in data["findings"][:2]] == ["stealer_log", "ransomware_post"]  # most urgent first
    assert all(f["account"] is None for f in data["findings"])
    assert "r.chen" not in json.dumps(data) and data["findings"][0]["account_masked"] == "r•••n@acme-corp.example"
    [demo] = data["watches"]
    assert demo["demo"] and client.post(f"/api/exposure/watches/{demo['id']}/check").status_code == 409

    revealed = client.get("/api/exposure?reveal=true").json()
    assert revealed["findings"][0]["account"] == "r.chen@acme-corp.example"
    export = client.get("/api/exposure/export.csv")
    rows = list(csv.reader(io.StringIO(export.text)))
    assert rows[0][:4] == ["Severity", "Type", "Subject", "Account"] and rows[1][3] == "r.chen@acme-corp.example"
    events = {e["action"]: e for e in client.get("/api/audit?limit=20").json()}
    assert events["exposure.reveal"]["details"] == {"addresses": 6}
    assert events["exposure.export"]["details"] == {"findings": 9, "addresses": 6}

    viewer = client.post("/api/keys", json={"name": "v", "role": "viewer"}).json()["key"]
    as_viewer = {"Authorization": f"Bearer {viewer}"}
    assert client.get("/api/exposure", headers=as_viewer).status_code == 200
    assert client.get("/api/exposure?reveal=true", headers=as_viewer).status_code == 403
    assert client.get("/api/exposure/export.csv", headers=as_viewer).status_code == 403


def test_triage_records_who_did_what(client):
    client.post("/api/demo")
    stealer = client.get("/api/exposure").json()["findings"][0]
    done = client.post("/api/exposure/findings/status",
                       json={"ids": [stealer["id"]], "status": "resolved", "note": "Password reset, laptop re-imaged"})  # fmt: skip
    assert done.json() == {"updated": 1}
    data = client.get("/api/exposure").json()
    assert data["summary"]["by_kind"]["stealer_log"] == 0 and stealer["id"] not in {f["id"] for f in data["findings"]}
    [resolved] = client.get("/api/exposure?status=resolved").json()["findings"]
    assert resolved["note"] == "Password reset, laptop re-imaged" and resolved["resolved_by"]
    client.post("/api/exposure/findings/status", json={"ids": [stealer["id"]], "status": "open"})
    assert client.get("/api/exposure").json()["summary"]["by_kind"]["stealer_log"] == 1
    assert any(e["action"] == "exposure.triage" for e in client.get("/api/audit?limit=10").json())


def test_watch_validation_roles_and_isolation(client):
    assert watch(client, authorized=False).status_code == 422
    assert watch(client, domain="not a domain").status_code == 422
    assert watch(client, domain="intranet.local").status_code == 422
    w = watch(client, domain="https://www.Acme.com/about").json()
    assert w["domain"] == "acme.com"
    assert watch(client).status_code == 409
    assert client.patch(f"/api/exposure/watches/{w['id']}", json={"interval_hours": 2}).status_code == 422
    assert client.patch(f"/api/exposure/watches/{w['id']}", json={"enabled": False}).json()["enabled"] is False

    client.post("/api/workspaces", json={"name": "Red Team"})
    red = {"X-Argus-Workspace": "red-team"}
    assert client.get("/api/exposure", headers=red).json()["watches"] == []
    for method, path in [("PATCH", f"/api/exposure/watches/{w['id']}"), ("POST", f"/api/exposure/watches/{w['id']}/check"),
                         ("DELETE", f"/api/exposure/watches/{w['id']}")]:  # fmt: skip
        kwargs = {"json": {"enabled": True}} if method == "PATCH" else {}
        assert client.request(method, path, headers=red, **kwargs).status_code == 404, path
    analyst = client.post("/api/keys", json={"name": "a", "role": "analyst"}).json()["key"]
    assert (
        client.delete(f"/api/exposure/watches/{w['id']}", headers={"Authorization": f"Bearer {analyst}"}).status_code
        == 403
    )
    assert client.delete(f"/api/exposure/watches/{w['id']}").status_code == 204


def test_exposure_alerts_link_to_the_exposure_page():
    alert = {"id": "alert_1", "severity": "critical", "target": "acme.com", "headline": "x", "investigation_id": "",
             "previous_investigation_id": "", "summary": {"summary": {}, "exposure": {"scope": "domain", "counts": {}}}}  # fmt: skip
    event = render.alert_event(alert, {"id": "ws_default", "name": "Default"}, "https://argus.example")
    assert event["alert"]["url"] == "https://argus.example/?ws=ws_default#/exposure"
    assert event["alert"]["exposure"]["scope"] == "domain"


async def test_closed_findings_are_purged_after_the_retention_period(tmp_path):
    from argus.intel.exposure import Finding
    from argus.storage.db import Database, ExposureFindingRow
    from argus.storage.exposure_repo import ExposureRepository
    from argus.storage.migrate import upgrade_database
    from tests.conftest import database_url

    db = Database(database_url(tmp_path, "purge.db"))
    await upgrade_database(db)
    repo = ExposureRepository(db)
    w = await repo.create_watch(workspace_id="ws_default", scope="domain", domain="acme.com", by="t", basis=BASIS)
    finding = Finding(
        key="k1", kind="breach_account", severity="low", title="t", subject="acme.com", account="a@acme.com"
    )
    await repo.record_check(w, [finding], status="ok", message="", sources={})
    [f] = await repo.findings(workspace_id="ws_default")
    await repo.set_status([f["id"]], workspace_id="ws_default", status="resolved", by="t")
    assert await repo.purge(older_than_days=365) == 0
    async with db.session() as s, s.begin():
        row = await s.get(ExposureFindingRow, f["id"])
        row.resolved_at = datetime.now(timezone.utc) - timedelta(days=400)
    assert await repo.purge(older_than_days=365) == 1
    await db.dispose()


def test_the_python_client_covers_exposure(client):
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "clients" / "python"))
    from argus_client import ArgusClient

    argus = ArgusClient(http=client)
    client.post("/api/demo")
    assert argus.exposure()["summary"]["open"] == 9
    first = argus.exposure(reveal=True)["findings"][0]
    assert first["account"] == "r.chen@acme-corp.example"
    assert argus.resolve_exposure([first["id"]], note="Password reset") == 1
    assert argus.watch_exposure("acme.com", basis=BASIS)["domain"] == "acme.com"
