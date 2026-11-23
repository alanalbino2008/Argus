"""Phase 82: a lookalike becomes a case, with its evidence and a capture of its website."""

from __future__ import annotations

import contextlib
import json

import pytest

from argus.evidence import capture as capture_module
from argus.evidence.capture import CaptureError, capture_upload
from argus.intel import brand_watch
from argus.intel.brand_watch import SourceFailed
from argus.intel.lookalike_triage import WebProfile
from tests.test_brand_watch import _cert

TOR = [{"name": "tor", "url": "http://127.0.0.1:9050", "kind": "tor"}]


@pytest.fixture
def world(make_client, monkeypatch):
    state = {"captured": [], "fail": None}

    async def fake_crtsh(http, brand):
        return [_cert("acmebank-login.com", days_ago=2)]

    async def fake_certspotter(http, name, key):
        raise SourceFailed("not in this test")

    async def fake_capture(url, settings, route=None):
        state["captured"].append((url, route.name if route else "direct"))
        if state["fail"]:
            raise CaptureError(state["fail"])
        return await capture_upload("page.html", "text/html", b"<html><title>Sign in</title></html>", settings)

    monkeypatch.setattr(brand_watch, "crtsh", fake_crtsh)
    monkeypatch.setattr(brand_watch, "certspotter", fake_certspotter)
    monkeypatch.setattr(capture_module, "capture_url", fake_capture)
    c = make_client(monitors_enabled="false", notifications_enabled="false", encryption_key="k" * 40,
                    egress_routes=json.dumps(TOR), capture_browser="off")  # fmt: skip
    watcher = c.app.state.brand_watcher
    watcher.kick = lambda: None
    watcher.http_factory = contextlib.nullcontext
    watcher.web_factory = lambda route: contextlib.nullcontext()

    async def dns(name):
        return {"ips": ["45.77.10.5"], "ns": ["ns1.evil.example"], "mx": []} if name != "acmebank.com" else {
            "ips": ["192.0.2.10"], "ns": ["ns1.acmebank.com"], "mx": []}  # fmt: skip

    async def web(http, name):
        return WebProfile(True, 200, name, "AcmeBank sign in" if name != "acmebank.com" else "AcmeBank", True, "")

    async def no_screenshot(url, mode):
        return None

    watcher.dns_lookup, watcher.web_lookup, watcher.screenshot = dns, web, no_screenshot
    return c, state


def _watch(c, web_check="tor"):
    watch = c.post("/api/brand-watches", json={"domain": "acmebank.com", "web_check": web_check}).json()
    c.portal.call(c.app.state.brand_watcher.tick)
    return watch


def test_a_lookalike_becomes_a_case(world):
    c, state = world
    watch = _watch(c)
    url = f"/api/brand-watches/{watch['id']}/lookalikes/acmebank-login.com/case"
    assert c.post(url, json={}).status_code == 422  # a new case needs a stated, legitimate purpose
    result = c.post(url, json={"confirmed": True}).json()
    case = result["case"]
    assert case["title"] == "Lookalike acmebank-login.com imitating acmebank.com"
    assert (
        case["opsec_mode"] == "anonymous" and case["egress"] == "tor"
    )  # the watch visits through Tor: so does the case
    assert "brand-protection" in case["tags"] and "phishing" in case["tags"]
    assert state["captured"] == [("https://acmebank-login.com/", "tor")] and result["capture"]["digest"]
    full = c.get(f"/api/cases/{case['id']}").json()
    kinds = sorted(i["kind"] for i in full["items"])
    assert kinds == ["entity", "entity", "event", "event", "link", "note"]
    lookalike = next(i for i in full["items"] if i["kind"] == "entity" and i["data"]["value"] == "acmebank-login.com")
    assert lookalike["data"]["attributes"]["imitates"] == "acmebank.com"
    assert lookalike["data"]["attributes"]["verdict"] == "Active phishing page"
    link = next(i for i in full["items"] if i["kind"] == "link")
    assert link["data"]["label"] == "imitates" and link["data"]["from"] == lookalike["id"]
    assert len(full["captures"]) == 1
    recent = c.get("/api/brand-watches").json()[0]["recent"]
    assert recent[0]["case_id"] == case["id"]
    assert {"brand_watch.case", "evidence.capture", "case.create"} <= {e["action"] for e in c.get("/api/audit").json()}


def test_add_to_an_existing_case_and_failed_captures(world):
    c, state = world
    watch = _watch(c, web_check="direct")
    existing = c.post("/api/cases", json={"title": "Acme phishing wave", "purpose": "Brand protection for Acme Bank",
                                          "confirmed": True}).json()  # fmt: skip
    state["fail"] = "The site did not answer"
    url = f"/api/brand-watches/{watch['id']}/lookalikes/acmebank-login.com/case"
    result = c.post(url, json={"case_id": existing["id"]}).json()
    assert result["case"]["id"] == existing["id"] and result["capture"] is None
    assert result["warning"] == "The website could not be captured: The site did not answer"
    assert state["captured"] == [("https://acmebank-login.com/", "direct")]
    assert len(c.get(f"/api/cases/{existing['id']}").json()["items"]) == result["items"]
    no_capture = c.post(url, json={"case_id": existing["id"], "capture": False}).json()
    assert no_capture["warning"] is None and len(state["captured"]) == 1


def test_access(world):
    c, _ = world
    watch = _watch(c)
    url = f"/api/brand-watches/{watch['id']}/lookalikes/acmebank-login.com/case"
    viewer = c.post("/api/keys", json={"name": "reader", "role": "viewer"}).json()["key"]
    assert c.post(url, json={"confirmed": True}, headers={"Authorization": f"Bearer {viewer}"}).status_code == 403
    assert (
        c.post(f"/api/brand-watches/{watch['id']}/lookalikes/nope.example/case", json={"confirmed": True}).status_code
        == 404
    )
    c.post("/api/workspaces", json={"id": "red-team", "name": "Red team"})
    assert c.post(url, json={"confirmed": True}, headers={"X-Argus-Workspace": "red-team"}).status_code == 404
    other = c.post("/api/cases", json={"title": "Theirs", "purpose": "Another team's case", "confirmed": True},
                   headers={"X-Argus-Workspace": "red-team"}).json()  # fmt: skip
    assert c.post(url, json={"case_id": other["id"]}).status_code == 404  # never into another team's case


def test_a_removed_route_never_breaks_a_run(world):
    c, _ = world
    watch = _watch(c)
    c.app.state.settings.egress_routes = []  # the watch's route was removed from the settings
    watcher = c.app.state.brand_watcher
    watcher.web_factory = watcher._web_client  # the real one
    c.post(f"/api/brand-watches/{watch['id']}/run")
    (outcome,) = c.portal.call(watcher.tick)
    assert outcome["status"] in ("ok", "partial")
    assert "route 'tor' is not configured" in c.get("/api/brand-watches").json()[0]["last_message"]
