"""Cases and evidence: capture, the guard proxy, timestamps, custody, tamper detection, privacy of cases."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import zipfile

import pytest
from aiohttp import web
from sqlalchemy import update

from argus.core.settings import Settings
from argus.evidence import capture as cap
from argus.evidence import guard_proxy
from argus.evidence.guard_proxy import GuardProxy
from argus.security.network import BlockedDestinationError
from argus.storage.db import EvidenceCustodyRow, EvidenceFileRow

MEMO = ('<html><head><title>Leaked memo</title><script>alert(1)</script></head><body><h1>Board memo</h1>'
        '<p>The plan is <b>secret</b>.</p><img src="http://169.254.169.254/latest/meta-data/"></body></html>')  # fmt: skip


def responder(text, content_type="text/html"):
    async def handler(request):
        return web.Response(text=text, content_type=content_type)

    return handler


async def serve(routes):
    app = web.Application()
    for path, handler in routes.items():
        app.router.add_get(path, handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    return runner, site._server.sockets[0].getsockname()[1]


# ---------------------------------------------------------------------------- pure helpers
def test_urls_text_and_digests():
    for bad in ("ftp://example.com/x", "javascript:alert(1)", "http://user:pw@example.com/", "http://10.0.0.1/",
                "http://localhost/admin", "https://exa mple.com"):  # fmt: skip
        with pytest.raises(cap.CaptureError):
            cap.check_url(bad, allow_private=False)
    assert cap.check_url(" https://example.com/a ", allow_private=False) == "https://example.com/a"
    title, text = cap.visible_text(MEMO)
    assert title == "Leaked memo" and "Board memo" in text and "The plan is secret" in text and "alert" not in text
    manifest, digest = cap.build({"url": "https://example.com"}, {"a.txt": ("text/plain", b"hello")})
    assert manifest["files"] == [{"name": "a.txt", "media_type": "text/plain", "size": 5,
                                  "sha256": hashlib.sha256(b"hello").hexdigest()}]  # fmt: skip
    assert digest == hashlib.sha256(cap.canonical(manifest)).hexdigest()


def test_rfc3161_request_and_reply():
    digest = "ab" * 32
    req = cap.timestamp_request(digest, 12345)
    assert req[0] == 0x30 and bytes.fromhex(digest) in req and bytes.fromhex("608648016503040201") in req
    assert req.endswith(b"\x01\x01\xff")  # certReq TRUE: the reply includes the TSA's certificate
    granted = bytes.fromhex("3009300302010030020500")  # status 0 + a (dummy) token
    assert cap.timestamp_granted(granted)
    assert not cap.timestamp_granted(bytes.fromhex("30053003020102"))  # rejection
    assert not cap.timestamp_granted(b"garbage")


# ---------------------------------------------------------------------------- the guard proxy
async def _via_proxy(proxy_port: int, request: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    writer.write(request)
    await writer.drain()
    data = await asyncio.wait_for(reader.read(65536), 10)
    writer.close()
    return data


async def test_the_guard_proxy_refuses_internal_addresses(monkeypatch):
    runner, port = await serve({"/": responder("public page", "text/plain")})
    try:

        async def fake_resolve(host, _port):
            if host == "public.test":
                return ["127.0.0.1"]
            raise BlockedDestinationError(host)

        monkeypatch.setattr(guard_proxy, "resolve_public", fake_resolve)
        async with GuardProxy(allow_private=False) as proxy:
            ok = await _via_proxy(
                proxy.port, f"GET http://public.test:{port}/ HTTP/1.1\r\nHost: public.test\r\n\r\n".encode()
            )
            assert ok.startswith(b"HTTP/1.1 200") and b"public page" in ok
            for target in ("169.254.169.254:80", "127.0.0.1:22", "metadata.google.internal:80"):
                refused = await _via_proxy(proxy.port, f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
                assert refused.startswith(b"HTTP/1.1 403"), target
            assert "169.254.169.254:80" in proxy.log.blocked and f"public.test:{port}" in proxy.log.allowed
    finally:
        await runner.cleanup()


# ---------------------------------------------------------------------------- capturing
async def test_capture_follows_redirects_and_records_everything():
    async def moved(request):
        raise web.HTTPFound("/memo")

    runner, port = await serve({
        "/start": moved, "/memo": responder(MEMO),
        "/data.json": responder('{"leak": true}', "application/json"),
    })  # fmt: skip
    settings = Settings(allow_private_targets=True, capture_browser="off")
    try:
        c = await cap.capture_url(f"http://127.0.0.1:{port}/start", settings)
        assert c.manifest["final_url"].endswith("/memo") and c.manifest["title"] == "Leaked memo"
        assert set(c.files) == {"page.html", "headers.json", "text.txt"}
        redirects = json.loads(c.files["headers.json"][1])["redirects"]
        assert [r["status"] for r in redirects] == [302, 200]
        assert any("No headless browser" in w for w in c.warnings)
        other = await cap.capture_url(f"http://127.0.0.1:{port}/data.json", settings)
        assert (
            set(other.files) == {"response.bin", "headers.json"}
            and other.files["response.bin"][0] == "application/json"
        )
    finally:
        await runner.cleanup()


async def test_a_redirect_to_an_internal_address_is_refused(monkeypatch):
    async def to_metadata(request):
        raise web.HTTPFound("http://169.254.169.254/latest/meta-data/")

    runner, port = await serve({"/": to_metadata})
    real_check = cap.check_url

    def check(url, *, allow_private):  # the first hop is our local test server; everything after is "real"
        return real_check(url, allow_private=url.startswith(f"http://127.0.0.1:{port}"))

    monkeypatch.setattr(cap, "check_url", check)
    try:
        with pytest.raises(cap.CaptureError, match="public internet"):
            await cap.capture_url(
                f"http://127.0.0.1:{port}/", Settings(allow_private_targets=True, capture_browser="off")
            )
    finally:
        await runner.cleanup()


@pytest.mark.skipif(cap.find_browser(Settings()) is None, reason="no headless browser installed")
async def test_the_browser_screenshot_goes_through_the_guard(monkeypatch):
    runner, port = await serve({"/": responder(MEMO)})

    async def fake_resolve(host, _port):
        if host == "public.test":
            return ["127.0.0.1"]
        raise BlockedDestinationError(host)

    monkeypatch.setattr(guard_proxy, "resolve_public", fake_resolve)
    settings = Settings()
    try:
        rendered = await cap.render(f"http://public.test:{port}/", cap.find_browser(settings), settings)
    finally:
        await runner.cleanup()
    assert rendered["screenshot"] and rendered["screenshot"].startswith(b"\x89PNG")
    assert b"Board memo" in rendered["dom"] and "169.254.169.254:80" in rendered["blocked"]


async def test_trusted_timestamps(monkeypatch):
    seen = {}

    async def tsa(request):
        seen["type"] = request.headers["Content-Type"]
        seen["body"] = await request.read()
        return web.Response(body=bytes.fromhex("3009300302010030020500"), content_type="application/timestamp-reply")

    app = web.Application()
    app.router.add_post("/tsr", tsa)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    url = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/tsr"
    try:
        c = await cap.capture_upload("chat.png", "image/png", b"\x89PNG fake", Settings(
            allow_private_targets=True, evidence_timestamp_url=url))  # fmt: skip
    finally:
        await runner.cleanup()
    assert c.timestamp_token and seen["type"] == "application/timestamp-query"
    assert bytes.fromhex(c.digest) in seen["body"]  # only the digest is sent, never the evidence


# ---------------------------------------------------------------------------- the API
@pytest.fixture
def client(make_client):
    c = make_client(monitors_enabled="false", notifications_enabled="false", report_schedules_enabled="false",
                    allow_private_targets="true", capture_browser="off")  # fmt: skip
    c.post("/api/demo")
    return c


def new_case(client, **extra):
    body = {
        "title": "Fake charity",
        "purpose": "Investigating a fake charity fundraising online",
        "confirmed": True,
        **extra,
    }
    return client.post("/api/cases", json=body)


def keys(client):
    analyst = client.post("/api/keys", json={"name": "jo", "role": "analyst"}).json()["key"]
    viewer = client.post("/api/keys", json={"name": "vic", "role": "viewer"}).json()["key"]
    return {"Authorization": f"Bearer {analyst}"}, {"Authorization": f"Bearer {viewer}"}


def test_cases_need_a_purpose_and_restricted_cases_stay_private(client):
    assert new_case(client, confirmed=False).status_code == 422
    assert new_case(client, purpose="because").status_code == 422
    open_case = new_case(client).json()
    as_jo, as_vic = keys(client)
    private = new_case(client, title="Source: insider", restricted=True).json()
    assert [c["title"] for c in client.get("/api/cases", headers=as_jo).json()] == ["Fake charity"]
    assert client.get(f"/api/cases/{private['id']}", headers=as_jo).status_code == 404  # invisible, not forbidden
    assert client.patch(f"/api/cases/{private['id']}", json={"members": ["jo"]}).status_code == 200
    assert client.get(f"/api/cases/{private['id']}", headers=as_jo).status_code == 200
    assert client.patch(f"/api/cases/{private['id']}", json={"restricted": False}, headers=as_jo).status_code == 403
    assert client.post("/api/cases", json={"title": "x", "purpose": "a legitimate purpose", "confirmed": True},
                       headers=as_vic).status_code == 403  # fmt: skip
    assert client.get(f"/api/cases/{open_case['id']}", headers=as_vic).status_code == 200
    client.post("/api/workspaces", json={"name": "Other"})
    assert client.get(f"/api/cases/{open_case['id']}", headers={"X-Argus-Workspace": "other"}).status_code == 404
    assert any(e["action"] == "case.view" for e in client.get("/api/audit?limit=20").json())


def test_people_links_scans_and_timeline(client):
    case = new_case(client).json()
    url = f"/api/cases/{case['id']}/items"
    person = client.post(url, json={"kind": "entity", "data": {"type": "person", "value": "Jane Roe",
                         "attributes": {"home address": "12 Example Street, Exampletown", "relative": "John Roe (brother)"}}}).json()  # fmt: skip
    assert person["title"] == "Jane Roe" and person["data"]["attributes"]["home address"].startswith("12 Example")
    handle = client.post(url, json={"kind": "entity", "data": {"type": "username", "value": "@janeroe_charity"}}).json()
    link = client.post(url, json={"kind": "link", "data": {"from": person["id"], "to": handle["id"], "label": "runs",
                                                            "confidence": "confirmed"}})  # fmt: skip
    assert link.status_code == 201 and link.json()["data"]["confidence"] == "confirmed"
    assert (
        client.post(url, json={"kind": "link", "data": {"from": person["id"], "to": person["id"]}}).status_code == 422
    )
    assert client.post(url, json={"kind": "entity", "data": {"type": "spaceship", "value": "x"}}).status_code == 422
    assert client.post(url, json={"kind": "event", "title": "Domain registered"}).status_code == 422
    event = client.post(
        url, json={"kind": "event", "title": "Domain registered", "occurred_at": "2026-03-01T10:00:00Z"}
    )
    assert event.status_code == 201
    inv = client.get("/api/investigations").json()[0]
    scan = client.post(url, json={"kind": "scan", "data": {"investigation_id": inv["id"]}}).json()
    assert scan["data"]["target"] == inv["target"]
    assert client.post(url, json={"kind": "scan", "data": {"investigation_id": "inv_nope"}}).status_code == 404
    note = client.post(url, json={"kind": "note", "title": "Lead", "body": "Check the Companies House filing."}).json()
    client.patch(f"{url}/{note['id']}", json={"body": "Checked: dissolved in 2024."})
    # Removing a person removes the links that pointed at them.
    assert client.delete(f"{url}/{person['id']}").status_code == 204
    kinds = sorted(i["kind"] for i in client.get(f"/api/cases/{case['id']}").json()["items"])
    assert kinds == ["entity", "event", "note", "scan"]


def test_capture_custody_tamper_detection_and_bundle(client):
    case = new_case(client).json()

    async def start():
        return await serve({"/memo": responder(MEMO)})

    runner, port = client.portal.call(start)
    try:
        r = client.post(
            f"/api/cases/{case['id']}/captures",
            json={"url": f"http://127.0.0.1:{port}/memo", "note": "Before deletion"},
        )
    finally:
        client.portal.call(runner.cleanup)
    assert r.status_code == 201, r.text
    ev = r.json()
    assert ev["title"] == "Leaked memo" and {f["name"] for f in ev["files"]} == {
        "page.html",
        "headers.json",
        "text.txt",
    }
    upload = client.post(f"/api/cases/{case['id']}/uploads", files={"file": ("chat.png", b"\x89PNG\r\n\x1a\nfake", "image/png")},
                         data={"note": "Screenshot sent by a source"}).json()  # fmt: skip
    svg = client.post(
        f"/api/cases/{case['id']}/uploads", files={"file": ("x.svg", b"<svg onload=alert(1)>", "image/svg+xml")}
    ).json()

    # Hostile content is never rendered by Argus.
    page = client.get(f"/api/evidence/{ev['id']}/files/page.html")
    assert (
        page.headers["content-type"] == "application/octet-stream"
        and "attachment" in page.headers["content-disposition"]
    )
    assert page.headers["content-security-policy"].startswith("sandbox")
    image = client.get(f"/api/evidence/{upload['id']}/files/chat.png")
    assert image.headers["content-type"] == "image/png" and "inline" in image.headers["content-disposition"]
    assert client.get(f"/api/evidence/{svg['id']}/files/x.svg").headers["content-type"] == "application/octet-stream"

    assert client.post(f"/api/evidence/{ev['id']}/verify").json()["intact"] is True
    custody = client.get(f"/api/evidence/{ev['id']}").json()["custody"]
    assert [c["action"] for c in custody] == ["captured", "viewed", "verified"]

    # The bundle: every file listed in SHA256SUMS, and the sums are right.
    bundle = client.get(f"/api/cases/{case['id']}/export")
    zf = zipfile.ZipFile(io.BytesIO(bundle.content))
    sums = dict(line.split("  ")[::-1] for line in zf.read("SHA256SUMS").decode().splitlines())
    for path, digest in sums.items():
        assert hashlib.sha256(zf.read(path)).hexdigest() == digest, path
    assert f"captures/{ev['id']}/files/page.html" in sums and "README.txt" in sums and "timeline.csv" in sums
    manifest = json.loads(zf.read(f"captures/{ev['id']}/manifest.json"))
    assert (
        hashlib.sha256(
            json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()
        == ev["digest"]
    )
    assert json.loads(zf.read(f"captures/{ev['id']}/custody.json"))["custody"][-1]["action"] == "exported"

    # Tampering is detected: a changed file, then a rewritten custody entry.
    async def tamper_file():
        async with client.app.state.db.session() as s, s.begin():
            await s.execute(update(EvidenceFileRow).where(EvidenceFileRow.capture_id == ev["id"],
                                                          EvidenceFileRow.name == "text.txt").values(data=b"edited"))  # fmt: skip

    client.portal.call(tamper_file)
    result = client.post(f"/api/evidence/{ev['id']}/verify").json()
    assert not result["intact"] and "text.txt has changed" in result["problems"][0]

    async def tamper_custody():
        async with client.app.state.db.session() as s, s.begin():
            await s.execute(update(EvidenceCustodyRow).where(EvidenceCustodyRow.capture_id == upload["id"],
                                                             EvidenceCustodyRow.seq == 1).values(by="someone else"))  # fmt: skip

    client.portal.call(tamper_custody)
    assert "Custody entry 1 was altered" in client.post(f"/api/evidence/{upload['id']}/verify").json()["problems"][0]


def test_capture_errors_are_explained(client, monkeypatch):
    case = new_case(client).json()
    r = client.post(f"/api/cases/{case['id']}/captures", json={"url": "ftp://example.com/file"})
    assert r.status_code == 422 and "http" in r.json()["detail"]

    async def boom(url, settings):
        raise cap.CaptureError("Could not load the page (ClientConnectorError)")

    monkeypatch.setattr("argus.api.case_routes.capture_url", boom)
    r = client.post(f"/api/cases/{case['id']}/captures", json={"url": "https://unreachable.example/"})
    assert r.status_code == 422 and "Could not load" in r.json()["detail"]
    assert (
        client.post(f"/api/cases/{case['id']}/uploads", files={"file": ("e.txt", b"", "text/plain")}).status_code == 422
    )


def test_the_python_client_covers_cases(client):
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "clients" / "python"))
    from argus_client import ArgusClient

    argus = ArgusClient(http=client)
    case = argus.create_case("Shell companies", purpose="Following money through shell companies for a story")
    person = argus.add_to_case(case["id"], "entity", data={"type": "person", "value": "A. Director"})
    assert person["data"]["value"] == "A. Director" and argus.cases()[0]["id"] == case["id"]
    bundle = zipfile.ZipFile(io.BytesIO(argus.export_case(case["id"])))
    assert "case.json" in bundle.namelist()
