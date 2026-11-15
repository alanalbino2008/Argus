"""People and account investigation: the community catalog, username variants, avatar links, account watching."""

from __future__ import annotations

import json

import pytest

from argus.core.models import Entity, EntityType
from argus.core.settings import get_settings
from argus.intel.handles import tokens, variants
from argus.modules.identity import catalog, username_hunter
from argus.modules.identity.platforms import Platform, detect
from argus.modules.identity.username_hunter import UsernameHunterModule
from tests.test_modules_offline import CONFIG, FakeResponse, FakeSession, collect, values

WMN = {
    "license": ["CC BY-SA 4.0"],
    "sites": [
        {"name": "Fotolog", "uri_check": "https://fotolog.test/{account}/", "e_code": 200, "e_string": "Joined",
         "m_code": 404, "m_string": "Not Found", "known": ["anna"], "cat": "images"},
        # Soft 404: both real and missing profiles return 200, told apart by text.
        {"name": "Chess Club", "uri_check": "https://api.chessclub.test/u/{account}",
         "uri_pretty": "https://chessclub.test/@{account}", "e_code": 200, "e_string": "\"username\"",
         "m_code": 200, "m_string": "\"error\"", "known": ["magnus"], "cat": "gaming"},
        {"name": "Dotless", "uri_check": "https://dotless.test/{account}", "e_code": 200, "e_string": "Profile",
         "m_code": 404, "m_string": "nope", "strip_bad_char": ".", "cat": "social"},
        # Unusable entries are skipped, not trusted.
        {"name": "Poster", "uri_check": "https://poster.test/api", "post_body": "{\"u\": \"{account}\"}",
         "e_code": 200, "e_string": "ok", "m_code": 404, "m_string": "no"},
        {"name": "Plain", "uri_check": "http://plain.test/{account}", "e_code": 200, "e_string": "x", "m_code": 404,
         "m_string": "y"},
        {"name": "Retired", "uri_check": "https://retired.test/{account}", "valid": False, "e_code": 200,
         "e_string": "x", "m_code": 404, "m_string": "y"},
        {"name": "Vague", "uri_check": "https://vague.test/{account}", "e_code": 200, "m_code": 404},
        # Same name as a hand-checked site: the hand-checked signature wins.
        {"name": "github", "uri_check": "https://evil.test/{account}", "e_code": 200, "e_string": "x",
         "m_code": 404, "m_string": "y"},
        "not even an object",
    ],
}  # fmt: skip


@pytest.fixture
def wmn_file(tmp_path, monkeypatch):
    path = tmp_path / "wmn-data.json"
    path.write_text(json.dumps(WMN))
    monkeypatch.setenv("ARGUS_USERNAME_CATALOG_FILE", str(path))
    get_settings.cache_clear()
    catalog.reset()
    return path


# ---------------------------------------------------------------------------- the community catalog
def test_whatsmyname_entries_convert_safely():
    platforms, skipped = catalog.convert(WMN)
    names = {p.name: p for p in platforms}
    assert set(names) == {"Fotolog", "Chess Club", "Dotless", "github"}
    assert skipped == 5  # POST, plain HTTP, marked invalid, no signature, not an object
    chess = names["Chess Club"]
    assert chess.profile_url("magnus") == "https://chessclub.test/@magnus"
    assert chess.probe_url("magnus") == "https://api.chessclub.test/u/magnus"
    assert chess.source == "community" and chess.category == "Gaming" and chess.known == "magnus"
    assert detect(chess, 200, '{"username": "magnus"}')
    assert not detect(chess, 200, '{"error": "not found", "username": null}')  # the "missing" text wins
    assert not detect(names["Fotolog"], 404, "Not Found")
    assert names["Dotless"].probe_url("jane.roe") == "https://dotless.test/janeroe"
    assert catalog.convert({"sites": "nonsense"}) == ([], 0) and catalog.convert([]) == ([], 0)


async def test_the_hunter_searches_the_community_catalog(wmn_file):
    session = FakeSession({
        r"fotolog\.test/anna/": FakeResponse(200, "<p>Joined 2011</p>"),
        r"chessclub\.test/u/anna$": FakeResponse(200, '{"username": "anna"}'),
        r"chessclub\.test/u/zq": FakeResponse(200, '{"error": "no such user"}'),
        r"dotless\.test/": FakeResponse(200, "Profile"),  # says yes to anything: the canary catches it
    })  # fmt: skip
    seed = Entity.create(EntityType.USERNAME, "anna")
    entities, _ = await collect(UsernameHunterModule(), seed, session)
    found = {e.metadata["platform"]: e for e in entities}
    assert set(found) == {"Fotolog", "Chess Club"}
    assert found["Chess Club"].value == "https://chessclub.test/@anna"
    assert found["Fotolog"].metadata["signature"] == "community" and found["Fotolog"].confidence == 0.75
    assert seed.metadata["platforms_unreliable"] == ["Dotless"]
    assert seed.metadata["platforms_checked"] > 120  # the hand-checked sites as well
    assert not any("evil.test" in url for url in session.requested)  # hand-checked GitHub kept
    assert catalog.status()["community_sites"] == 4 and catalog.status()["source"] == "wmn-data.json"


async def test_a_missing_catalog_never_stops_a_scan(monkeypatch, tmp_path):
    monkeypatch.setenv("ARGUS_USERNAME_CATALOG_FILE", str(tmp_path / "absent.json"))
    get_settings.cache_clear()
    catalog.reset()
    seed = Entity.create(EntityType.USERNAME, "anna")
    await collect(UsernameHunterModule(), seed, FakeSession({}))
    assert seed.metadata["platforms_checked"] > 100 and "FileNotFoundError" in catalog.status()["error"]


async def test_the_catalog_downloads_once_and_is_cached(monkeypatch):
    monkeypatch.setenv("ARGUS_USERNAME_CATALOG_URL", "https://catalog.test/wmn-data.json")
    get_settings.cache_clear()
    catalog.reset()

    class Body:
        def __init__(self, data):
            self.data = data

        async def read(self, n):
            return self.data[:n]

    class Session:
        calls = 0

        def get(self, url, **_):
            Session.calls += 1
            response = FakeResponse(200, "")
            response.content = Body(json.dumps(WMN).encode())
            return FakeSession({".": response}).get(url)

    assert len(await catalog.community_platforms(Session())) == 4
    assert len(await catalog.community_platforms(Session())) == 4
    assert Session.calls == 1


# ---------------------------------------------------------------------------- username variants
def test_variants_are_the_handles_people_actually_use():
    assert tokens("JaneRoe_1987") == ["jane", "roe", "1987"] and tokens("Jane  Roe") == ["jane", "roe"]
    assert variants("jane.roe")[:3] == ["janeroe", "jane_roe", "jane-roe"]
    assert {"jroe", "roejane"} <= set(variants("Jane Roe"))
    assert variants("janeroe1987") == ["janeroe"]  # the same handle without the number
    assert variants("JaneRoe1987")[0] == "janeroe"  # without the number first
    assert variants("jroe1987") == ["jroe"]
    assert variants("x") == [] and variants("") == [] and len(variants("a.b.c.d.e")) <= 6
    assert all(v != "jane.roe" for v in variants("jane.roe"))


async def test_variants_are_searched_and_marked_as_possible(monkeypatch):
    monkeypatch.setattr(username_hunter, "get_platforms",
                        lambda: [Platform(name="CodeHub", category="Developer", url="https://codehub.test/{}")])  # fmt: skip
    session = FakeSession({r"codehub\.test/(jane\.roe|janeroe)$": FakeResponse(200, "<h1>profile</h1>")})
    seed = Entity.create(EntityType.USERNAME, "jane.roe")
    config = CONFIG.model_copy(update={"handle_variants": True})
    items = [x async for x in UsernameHunterModule().run(seed, session, config)]
    profiles = {e.metadata["username"]: e for e in items if isinstance(e, Entity)}
    assert set(profiles) == {"jane.roe", "janeroe"}
    assert profiles["janeroe"].metadata["variant_of"] == "jane.roe"
    assert profiles["janeroe"].confidence < profiles["jane.roe"].confidence - 0.2
    assert "janeroe" in seed.metadata["variants_checked"]
    assert any("Possibly the same person" in r.label for r in items if not isinstance(r, Entity))

    # Off by default, and never for handles found along the way.
    seed2 = Entity.create(EntityType.USERNAME, "jane.roe")
    entities, _ = await collect(UsernameHunterModule(), seed2, session)
    assert values(entities, EntityType.SOCIAL_PROFILE) == ["https://codehub.test/jane.roe"]
    deep = Entity.create(EntityType.USERNAME, "jane.roe", depth=1)
    assert len([x async for x in UsernameHunterModule().run(deep, session, config) if isinstance(x, Entity)]) == 1


# ---------------------------------------------------------------------------- profile pictures
def _picture(seed: int = 0, size: int = 200, fmt: str = "PNG", **save) -> bytes:
    import io

    from PIL import Image, ImageDraw

    img = Image.new("RGB", (200, 200), "white")
    draw = ImageDraw.Draw(img)
    if seed == 0:
        draw.ellipse((40, 30, 160, 150), fill="navy")
        draw.line((0, 0, 200, 120), fill="green", width=9)
    else:
        draw.rectangle((20, 90, 180, 120), fill="red")
        draw.ellipse((120, 10, 190, 80), fill="black")
    out = io.BytesIO()
    img.resize((size, size)).save(out, fmt, **save)
    return out.getvalue()


def test_the_same_photo_matches_across_sizes_and_formats():
    from PIL import Image

    from argus.intel.avatars import distance, fingerprint, same_picture

    original, small_jpeg, other = fingerprint(_picture()), fingerprint(_picture(size=64, fmt="JPEG", quality=55)), \
        fingerprint(_picture(1))  # fmt: skip
    assert original and small_jpeg and other
    assert same_picture(original, small_jpeg) and distance(original, small_jpeg) <= 3
    assert not same_picture(original, other)
    import io

    blank = io.BytesIO()
    Image.new("RGB", (120, 120), "#d0d0d0").save(blank, "PNG")
    assert fingerprint(blank.getvalue()) is None  # a default avatar says nothing about who someone is
    assert fingerprint(b"<svg onload=alert(1)>") is None and fingerprint(_picture(size=8)) is None
    assert not same_picture(None, original)


async def test_pictures_are_fetched_safely():
    from argus.intel.avatars import fetch_fingerprint

    session = FakeSession({r"cdn\.test/a\.png": FakeResponse(200, _picture()), r"cdn\.test/big": FakeResponse(
        200, b"x" * (2 * 1024 * 1024 + 10))})  # fmt: skip
    assert await fetch_fingerprint(session, "https://cdn.test/a.png")
    assert await fetch_fingerprint(session, "https://cdn.test/missing.png") is None
    assert await fetch_fingerprint(session, "https://cdn.test/big") is None
    assert await fetch_fingerprint(session, "http://cdn.test/a.png") is None  # HTTPS only
    assert session.requested.count("http://cdn.test/a.png") == 0


def _profile(platform: str, handle: str, picture: bytes | None, **md):
    from argus.intel.avatars import fingerprint

    return Entity.create(EntityType.SOCIAL_PROFILE, f"https://{platform.lower()}.test/{handle}", depth=1,
                         confidence=0.8, source_module="username_hunter",
                         metadata={"platform": platform, "username": handle,
                                   "avatar_hash": fingerprint(picture) if picture else None, **md})  # fmt: skip


def test_the_same_photo_links_accounts_into_one_person():
    from argus.core.graph import IntelligenceGraph
    from argus.core.models import Relation, RelationType
    from argus.intel.identity import resolve_people

    g = IntelligenceGraph("t")
    seed = Entity.create(EntityType.USERNAME, "jane.roe", depth=0)
    g.add_entity(seed, is_seed=True)
    accounts = [
        _profile("GitHub", "jane.roe", _picture()),
        _profile("Reddit", "janeroe", _picture(size=96, fmt="JPEG", quality=70), variant_of="jane.roe"),
        _profile("Twitch", "jane_roe", _picture(1), variant_of="jane.roe"),  # a different photo: still a lead
        _profile("Steam", "unrelated", _picture(size=128)),  # no relation at all, same photo
    ]
    for a in accounts:
        g.add_entity(a)
    for a in accounts[:3]:
        g.add_relation(Relation.create(seed.id, a.id, RelationType.HAS_ACCOUNT))
    people = resolve_people(g)["personas"]
    assert len(people) == 1
    by = {a["platform"]: a for a in people[0]["accounts"]}
    assert set(by) == {"GitHub", "Reddit", "Twitch", "Steam"}  # the photo pulled the Steam account in
    assert by["Reddit"]["link"] == "strong" and "GitHub" in by["Reddit"]["same_photo_as"]
    assert by["Twitch"]["link"] == "possible" and by["Twitch"]["variant_of"] == "jane.roe"
    assert by["Steam"]["same_photo_as"] == ["GitHub", "Reddit"]


def test_one_sites_shared_picture_never_links_strangers():
    from argus.core.graph import IntelligenceGraph
    from argus.intel.identity import resolve_people

    g = IntelligenceGraph("t")
    g.add_entity(Entity.create(EntityType.DOMAIN, "acme.example", depth=0), is_seed=True)
    for handle in ("alice", "bob"):  # both kept the same site's stock picture
        g.add_entity(_profile("Forum", handle, _picture()))
    people = resolve_people(g)["personas"]
    assert sorted(len(p["accounts"]) for p in people) == [1, 1]


# ---------------------------------------------------------------------------- watching accounts
async def test_observing_reads_the_profile_and_its_picture(monkeypatch):
    from argus.intel import account_watch

    session = FakeSession({
        r"api\.github\.com/users/jane-roe$": FakeResponse(200, {
            "name": "Jane Roe", "bio": "  Reporter\n at  the Gazette ", "location": "Leeds", "blog": "",
            "followers": 12, "avatar_url": "https://avatars.test/jane.png", "twitter_username": "janeroe"}),
        r"avatars\.test/jane\.png": FakeResponse(200, _picture()),
    })  # fmt: skip
    seen = await account_watch.observe(session, "GitHub", "jane-roe")
    assert seen.exists is True and seen.facts["bio"] == "Reporter at the Gazette"  # whitespace never counts
    assert seen.facts["avatar_hash"] and seen.facts["links"] == ["https://twitter.com/janeroe"]
    assert "website" not in seen.facts and seen.facts["followers"] == 12

    monkeypatch.setattr(account_watch, "all_platforms", _fake_catalog)
    forum = await account_watch.observe(FakeSession({r"forum\.test/u/anna": FakeResponse(200, "hi")}), "Forum", "anna")
    assert forum.exists is True and forum.facts == {}
    assert (await account_watch.observe(FakeSession({}), "Forum", "anna")).exists is False
    unknown = await account_watch.observe(FakeSession({}), "Nowhere", "anna")
    assert unknown.exists is None and "cannot check" in unknown.error


async def _fake_catalog(_http):
    return [Platform(name="Forum", category="Community", url="https://forum.test/u/{}", known="admin")]


def test_changes_are_described_plainly():
    from argus.intel.account_watch import describe, diff

    before = {"exists": True, "display_name": "Jane Roe", "bio": "Reporter", "avatar_hash": "aa", "followers": 10}
    after = {
        "exists": True,
        "display_name": "J. Roe",
        "avatar_hash": "bb",
        "followers": 99,
        "links": ["https://x.test/j"],
    }
    changes = {c["field"]: c for c in diff(before, after)}
    assert set(changes) == {"display_name", "bio", "avatar_hash", "links"}  # follower counts are noise
    assert describe(changes["display_name"]) == "Name: “Jane Roe” → “J. Roe”"
    assert describe(changes["bio"]) == "Bio: “Reporter” → (none)"
    assert describe(changes["avatar_hash"]) == "Profile picture changed"


@pytest.fixture
def cases_client(make_client):
    c = make_client(monitors_enabled="false", notifications_enabled="false", report_schedules_enabled="false",
                    allow_private_targets="true", capture_browser="off")  # fmt: skip
    c.post("/api/demo")
    return c


def _new_case(client, **extra):
    return client.post("/api/cases", json={"title": "Fake charity", "confirmed": True,
                                           "purpose": "Investigating a fake charity fundraising online", **extra}).json()  # fmt: skip


def test_a_watched_account_records_changes_captures_and_deletion(cases_client, monkeypatch):
    from argus.evidence.capture import Capture, build
    from argus.intel import account_watch
    from argus.intel.account_watch import Observation

    client = cases_client
    case = _new_case(client)
    script = [
        Observation(True, {"display_name": "Jane Roe", "bio": "Reporter"}),
        Observation(True, {"display_name": "Jane Roe", "bio": "Reporter"}),  # no change
        Observation(True, {"display_name": "Jane Roe", "bio": "Freelance investigator", "location": "Leeds"}),
        Observation(False),  # missing once: checked again before reporting
        Observation(False),  # missing twice: gone (the known account still answers)
        Observation(True, {"display_name": "Jane Roe"}),  # back
    ]
    observed: list[str] = []

    async def fake_observe(http, platform, handle):
        observed.append(f"{platform}/{handle}")
        return script.pop(0)

    async def fake_present(http, sig, handle):
        return True

    captured: list[str] = []

    async def fake_capture(url, settings, route=None):
        captured.append(url)
        manifest, digest = build({"kind": "web_capture", "url": url}, {"page.html": ("text/html", b"<p>profile</p>")})
        return Capture(manifest, digest, {"page.html": ("text/html", b"<p>profile</p>")}, None, [])

    monkeypatch.setattr(account_watch, "observe", fake_observe)
    monkeypatch.setattr(account_watch, "present", fake_present)
    monkeypatch.setattr(client.app.state.account_watcher, "capture", fake_capture)

    assert (
        client.post(f"/api/cases/{case['id']}/watches", json={"platform": "Nowhere", "handle": "x"}).status_code == 422
    )
    r = client.post(f"/api/cases/{case['id']}/watches", json={"platform": "github", "handle": "@jane-roe"})
    assert r.status_code == 201, r.text
    watch = r.json()
    assert watch["platform"] == "GitHub" and watch["handle"] == "jane-roe"
    assert watch["profile_url"] == "https://github.com/jane-roe" and watch["status"] == "pending"
    assert (
        client.post(f"/api/cases/{case['id']}/watches", json={"platform": "GitHub", "handle": "jane-roe"}).status_code
        == 409
    )

    check = lambda: client.post(f"/api/cases/{case['id']}/watches/{watch['id']}/check").json()  # noqa: E731
    first = check()
    assert first["status"] == "active" and first["changes_count"] == 0 and first["snapshot"]["bio"] == "Reporter"
    assert check()["changes_count"] == 0
    changed = check()
    assert changed["changes_count"] == 2 and changed["snapshot"]["location"] == "Leeds"
    missing_once = check()
    assert (
        missing_once["status"] == "active" and missing_once["missing_count"] == 1 and "again" in missing_once["message"]
    )
    gone = check()
    assert gone["status"] == "gone" and "no longer be found" in gone["message"]
    back = check()
    assert back["status"] == "active" and back["missing_count"] == 0
    assert observed == ["GitHub/jane-roe"] * 6

    history = client.get(f"/api/cases/{case['id']}/watches/{watch['id']}/history").json()
    assert len(history) == 4  # baseline, the change, gone, back (unchanged checks keep no copy)
    bio = next(c for c in history[2]["changes"] if c["field"] == "bio")
    assert bio == {"field": "bio", "label": "Bio", "before": "Reporter", "after": "Freelance investigator"}
    assert history[2]["capture_id"] and captured == ["https://github.com/jane-roe"] * 2  # change and return

    full = client.get(f"/api/cases/{case['id']}").json()
    events = [i for i in full["items"] if i["kind"] == "event"]
    assert [e["title"] for e in events] == ["GitHub @jane-roe: Bio, Location changed",
                                            "GitHub @jane-roe: The account can no longer be found (deleted, renamed or suspended)",
                                            "GitHub @jane-roe: The account is back"]  # fmt: skip
    assert "Bio: “Reporter” → “Freelance investigator”" in events[0]["body"]
    auto = [c for c in full["captures"] if c["captured_by"] == "account-watcher"]
    assert len(auto) == 2 and "profile changed" in auto[0]["note"]
    actions = [e["action"] for e in client.get("/api/audit").json()]
    assert "account_watch.change" in actions and "account_watch.create" in actions

    assert client.delete(f"/api/cases/{case['id']}/watches/{watch['id']}").status_code == 204
    assert client.get(f"/api/cases/{case['id']}/watches").json() == []


def test_a_blocked_site_is_not_reported_as_a_deletion(cases_client, monkeypatch):
    from argus.intel import account_watch
    from argus.intel.account_watch import Observation

    client = cases_client
    case = _new_case(client)
    script = [Observation(True, {}), Observation(False), Observation(False)]

    async def fake_observe(http, platform, handle):
        return script.pop(0)

    async def blocked(http, sig, handle):
        return False  # even the account known to exist "is missing": the site is blocking checks

    monkeypatch.setattr(account_watch, "observe", fake_observe)
    monkeypatch.setattr(account_watch, "present", blocked)
    watch = client.post(f"/api/cases/{case['id']}/watches", json={"platform": "GitHub", "handle": "jane"}).json()
    for _ in range(3):
        result = client.post(f"/api/cases/{case['id']}/watches/{watch['id']}/check").json()
    assert result["status"] == "error" and "not reported as deleted" in result["message"]
    assert not [i for i in client.get(f"/api/cases/{case['id']}").json()["items"] if i["kind"] == "event"]


def test_an_anonymous_case_never_watches_directly(make_client, monkeypatch):
    from argus.intel import account_watch

    routes = [{"name": "tor", "kind": "tor", "url": "http://127.0.0.1:9", "description": "Tor"}]
    client = make_client(monitors_enabled="false", allow_private_targets="true", egress_routes=json.dumps(routes))
    client.post("/api/demo")
    case = _new_case(client, opsec_mode="anonymous", egress="tor")
    watch = client.post(f"/api/cases/{case['id']}/watches", json={"platform": "GitHub", "handle": "jane"}).json()

    async def must_not_run(http, platform, handle):
        raise AssertionError("observed without the route")

    monkeypatch.setattr(account_watch, "observe", must_not_run)
    client.app.state.settings.egress_routes = []  # the operator removed the route
    result = client.post(f"/api/cases/{case['id']}/watches/{watch['id']}/check").json()
    assert result["status"] == "error" and "no longer configured" in result["message"]
    platforms = client.get("/api/watchable-platforms").json()
    assert (
        "GitHub" in platforms["detailed"] and "GitHub" not in platforms["presence"] and len(platforms["presence"]) > 100
    )


def test_due_watches_are_checked_once_by_the_scheduler(cases_client, monkeypatch):
    from argus.intel import account_watch
    from argus.intel.account_watch import Observation

    client = cases_client
    case = _new_case(client)
    calls: list[str] = []

    async def fake_observe(http, platform, handle):
        calls.append(handle)
        return Observation(True, {"bio": "hello"})

    monkeypatch.setattr(account_watch, "observe", fake_observe)
    for handle in ("one", "two"):
        client.post(f"/api/cases/{case['id']}/watches", json={"platform": "GitHub", "handle": handle})
    watcher = client.app.state.account_watcher
    assert len(client.portal.call(watcher.tick)) == 2
    assert client.portal.call(watcher.tick) == []  # next check is a day away
    assert sorted(calls) == ["one", "two"]
    watches = client.get(f"/api/cases/{case['id']}/watches").json()
    assert all(w["status"] == "active" and w["last_checked_at"] for w in watches)


def test_the_python_client_covers_watching(cases_client, monkeypatch):
    import sys
    from pathlib import Path

    from argus.intel import account_watch
    from argus.intel.account_watch import Observation

    async def fake_observe(http, platform, handle):
        return Observation(True, {"bio": "hello"})

    monkeypatch.setattr(account_watch, "observe", fake_observe)
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "clients" / "python"))
    from argus_client import ArgusClient

    argus = ArgusClient(http=cases_client)
    case = _new_case(cases_client)
    watch = argus.watch_account(case["id"], "GitLab", "jane", interval_hours=6)
    assert argus.watches(case["id"])[0]["id"] == watch["id"]
    assert argus.check_account(case["id"], watch["id"])["status"] == "active"
    assert argus.account_history(case["id"], watch["id"])[0]["facts"]["bio"] == "hello"
