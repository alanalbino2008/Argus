"""A case in time and space: coordinates, the timeline, places, address look-up, map images, exports."""

from __future__ import annotations

import csv
import io
import json
import re
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from defusedxml import ElementTree

from argus.intel.places import build_places, build_timeline, entity_position, kml, parse_coordinates, timeline_csv
from tests.test_inspect import photo


# ---------------------------------------------------------------------------- coordinates
@pytest.mark.parametrize("text, expected", [
    ("51.5007, -0.1246", (51.5007, -0.1246)),
    ("(51.5007 -0.1246)", (51.5007, -0.1246)),
    ("51°30'02.5\"N 0°07'28.6\"W", (51.500694, -0.124611)),
    ("40.7128° N, 74.0060° W", (40.7128, -74.006)),
    ("33°51\u2032S 151°12\u2032E", (-33.85, 151.2)),
    ("https://www.openstreetmap.org/?mlat=51.500700&mlon=-0.124600#map=17/51.5/-0.12", (51.5007, -0.1246)),
    ("https://www.google.com/maps/@51.5007,-0.1246,17z", (51.5007, -0.1246)),
    ("10 Downing Street, London SW1A 2AA", None),
    ("0, 0", None),  # "null island": a missing value, not a place
    ("95, 10", None),
    ("", None),
])  # fmt: skip
def test_coordinates_are_read_in_the_forms_people_paste(text, expected):
    assert parse_coordinates(text) == expected


def test_where_an_entity_is():
    assert entity_position({"value": "51.5, -0.12"}) == (51.5, -0.12, "given")
    assert entity_position({"value": "Home", "attributes": {"Lat": "51.5", "Lon": "-0.12"}}) == (51.5, -0.12, "given")
    assert (
        entity_position({"value": "x", "attributes": {"lat": "51.5", "lon": "-0.12", "geocoded_by": "look-up"}})[2]
        == "looked up"
    )
    assert entity_position(
        {"value": "x", "attributes": {"map": "https://www.google.com/maps/@48.8584,2.2945,17z"}}
    ) == (48.8584, 2.2945, "given")
    assert entity_position({"value": "x", "attributes": {"lat": "north", "lon": "-0.1"}}) is None


# ---------------------------------------------------------------------------- the timeline
def test_the_timeline_brings_everything_dated_together():
    items = [
        {
            "id": "i1",
            "kind": "event",
            "title": "Appeal posted",
            "body": "",
            "data": {},
            "occurred_at": "2024-03-02T18:30:00+00:00",
        },
        {
            "id": "i2",
            "kind": "event",
            "title": "GitHub @jane: Bio changed",
            "body": "Bio: a → b",
            "data": {"watch_id": "aw_1"},
            "occurred_at": "2024-04-01T08:00:00+00:00",
            "created_by": "account-watcher",
        },
        {
            "id": "i3",
            "kind": "event",
            "title": "Photo taken: kept.jpg",
            "body": "",
            "data": {},
            "occurred_at": "2024-02-01T10:00:00+00:00",
        },
        {"id": "i4", "kind": "note", "title": "Lead", "body": "", "data": {}, "occurred_at": None},
    ]
    captures = [
        {
            "id": "c1",
            "kind": "web",
            "title": "Their site",
            "url": "https://x.test/",
            "captured_at": "2024-05-01T12:00:00+00:00",
        },
        {"id": "c2", "kind": "upload", "title": "kept.jpg", "captured_at": "2024-05-02T12:00:00+00:00"},
    ]
    scans = [{"id": "inv_1", "target": "x.test", "status": "completed", "started_at": "2024-01-15T09:00:00+00:00"}]
    photos = [{"capture_id": "c2", "file": "kept.jpg", "taken_at": "2024-02-01T11:00:00+01:00", "time_zone_known": True},
              {"capture_id": "c3", "file": "other.jpg", "taken_at": "2023-12-24T15:00:00", "time_zone_known": False}]  # fmt: skip
    entries = build_timeline(items, captures, scans, photos)
    assert [e["kind"] for e in entries] == ["photo", "scan", "event", "event", "account", "capture", "upload"]
    assert entries[0]["title"] == "Photo taken: other.jpg" and entries[0]["approximate"] is True  # zone unknown
    assert not any(
        e["title"] == "Photo taken: kept.jpg" and e["kind"] == "photo" for e in entries
    )  # already added by hand
    assert entries[4]["by"] == "account-watcher" and entries[5]["ref"] == {"type": "capture", "id": "c1"}

    rows = list(csv.reader(io.StringIO(timeline_csv([*entries, {**entries[2], "title": "=HYPERLINK(\"http://evil\")"}])
                                       .decode("utf-8-sig"))))  # fmt: skip
    assert rows[0][0].startswith("time") and len(rows) == 9
    assert rows[-1][2].startswith("'=")  # a formula is never run by the spreadsheet


def test_places_and_the_kml_export():
    items = [
        {"id": "i1", "kind": "entity", "title": "", "body": "", "data": {"type": "location", "value": "51.5007, -0.1246"}},
        {"id": "i2", "kind": "entity", "title": "", "body": "", "data": {"type": "address", "value": "10 Downing St"}},
        {"id": "i3", "kind": "entity", "title": "", "body": "", "data": {"type": "person", "value": "Jane Roe"}},
        {"id": "i4", "kind": "entity", "title": "", "body": "", "data": {"type": "address", "value": "<b>Shed</b> & co",
                                                                       "attributes": {"lat": "51.6", "lon": "-0.2"}}},
    ]  # fmt: skip
    photos = [
        {"capture_id": "c1", "file": "IMG.jpg", "lat": 51.5, "lon": -0.12, "taken_at": "2024-06-21T13:00:00+01:00"}
    ]
    out = build_places(items, photos)
    assert [p["label"] for p in out["places"]] == ["51.5007, -0.1246", "<b>Shed</b> & co", "IMG.jpg"]
    assert out["unplaced"] == [{"id": "i2", "type": "address", "label": "10 Downing St"}]  # people are never "unplaced"
    doc = ElementTree.fromstring(kml("Case <1>", out["places"]))
    ns = {"k": "http://www.opengis.net/kml/2.2"}
    names = [n.text for n in doc.iterfind(".//k:Placemark/k:name", ns)]
    assert names == ["51.5007, -0.1246", "<b>Shed</b> & co", "IMG.jpg"]  # escaped, so it is text, not markup
    assert doc.find(".//k:Placemark/k:Point/k:coordinates", ns).text == "-0.1246,51.5007,0"


# ---------------------------------------------------------------------------- through the API
class Services(ThreadingHTTPServer):
    """A stand-in map image server and Nominatim-style geocoder."""

    daemon_threads = True

    def __init__(self):
        self.tile_requests: list[str] = []
        self.geocode_requests: list[dict[str, str]] = []
        super().__init__(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        from urllib.parse import parse_qs, urlsplit

        parts = urlsplit(self.path)
        if parts.path.startswith("/tiles/"):
            self.server.tile_requests.append(parts.path)
            body, kind = (b"not an image", "text/html") if "/9/" in parts.path else (b"\x89PNG fake tile", "image/png")
        elif parts.path == "/search":
            q = {k: v[0] for k, v in parse_qs(parts.query).items()}
            self.server.geocode_requests.append({**q, "ua": self.headers.get("User-Agent", "")})
            found = (
                []
                if "Atlantis" in q["q"]
                else [{"lat": "51.5034", "lon": "-0.1276", "display_name": "10 Downing Street, London"}]
            )
            body, kind = json.dumps(found).encode(), "application/json"
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def services():
    s = Services()
    yield s
    s.shutdown()


@pytest.fixture
def client(make_client, services):
    from argus.api import map_routes

    map_routes._tiles.clear()
    map_routes._photos.clear()
    c = make_client(monitors_enabled="false", notifications_enabled="false", report_schedules_enabled="false",
                    allow_private_targets="true", capture_browser="off",
                    map_tile_url=services.base + "/tiles/{z}/{x}/{y}.png", geocoder_url=services.base + "/search")  # fmt: skip
    c.post("/api/demo")
    return c


def new_case(client, **extra):
    return client.post("/api/cases", json={"title": "Fake charity", "confirmed": True,
                                           "purpose": "Investigating a fake charity fundraising online", **extra}).json()  # fmt: skip


def test_the_case_timeline_and_places(client):
    case = new_case(client)
    add = lambda body: client.post(f"/api/cases/{case['id']}/items", json=body).json()  # noqa: E731
    add({"kind": "entity", "data": {"type": "location", "value": "51.5007, -0.1246"}})
    downing = add({"kind": "entity", "data": {"type": "address", "value": "10 Downing Street, London"}})
    add({"kind": "event", "title": "Charity registered", "occurred_at": "2024-01-10T09:00:00Z"})
    inv = client.get("/api/investigations").json()[0]
    add({"kind": "scan", "data": {"investigation_id": inv["id"]}})
    client.post(f"/api/cases/{case['id']}/uploads", files={"file": ("IMG_1.jpg", photo(), "image/jpeg")})

    timeline = client.get(f"/api/cases/{case['id']}/timeline").json()
    kinds = [e["kind"] for e in timeline]
    assert {"event", "scan", "upload", "photo"} <= set(kinds)
    photo_entry = next(e for e in timeline if e["kind"] == "photo")
    assert photo_entry["at"] == "2024-06-21T13:00:00+01:00" and not photo_entry.get("approximate")
    moments = [datetime.fromisoformat(e["at"]) for e in timeline]
    assert moments == sorted(moments)  # oldest first, comparing real instants (offsets differ)

    places = client.get(f"/api/cases/{case['id']}/places").json()
    assert {p["kind"] for p in places["places"]} == {"entity", "photo"} and places["tiles"] and places["geocoding"]
    assert places["unplaced"] == [{"id": downing["id"], "type": "address", "label": "10 Downing Street, London"}]
    upload = next(e for e in reversed(timeline) if e["kind"] == "upload")  # facts can be dated in the future
    custody = [c["action"] for c in client.get(f"/api/evidence/{upload['ref']['id']}").json()["custody"]]
    assert "viewed" not in custody and "inspected" not in custody  # Argus reading dates is not a person viewing

    csv_export = client.get(f"/api/cases/{case['id']}/timeline.csv")
    assert csv_export.status_code == 200 and b"Charity registered" in csv_export.content
    kml_export = client.get(f"/api/cases/{case['id']}/places.kml")
    assert kml_export.headers["content-type"].startswith("application/vnd.google-earth.kml+xml")
    actions = [e["action"] for e in client.get("/api/audit").json()]
    assert "case.export_places" in actions and "case.export_timeline" in actions


def test_looking_up_an_address(client, services):
    case = new_case(client)
    downing = client.post(f"/api/cases/{case['id']}/items",
                          json={"kind": "entity", "data": {"type": "address", "value": "10 Downing Street, London"}}).json()  # fmt: skip
    nowhere = client.post(f"/api/cases/{case['id']}/items",
                          json={"kind": "entity", "data": {"type": "address", "value": "Atlantis"}}).json()  # fmt: skip
    found = client.post(f"/api/cases/{case['id']}/items/{downing['id']}/geocode")
    assert found.status_code == 200, found.text
    attrs = found.json()["data"]["attributes"]
    assert (attrs["lat"], attrs["lon"], attrs["geocoded_by"]) == ("51.5034", "-0.1276", "address look-up")
    assert (
        services.geocode_requests[0]["q"] == "10 Downing Street, London"
        and "Argus" in services.geocode_requests[0]["ua"]
    )
    place = next(
        p for p in client.get(f"/api/cases/{case['id']}/places").json()["places"] if p["ref"]["id"] == downing["id"]
    )
    assert place["how"] == "looked up" and place["detail"] == "10 Downing Street, London"
    assert client.post(f"/api/cases/{case['id']}/items/{nowhere['id']}/geocode").status_code == 404
    assert "case.geocode" in [e["action"] for e in client.get("/api/audit").json()]


def test_an_anonymous_case_never_looks_up_directly(make_client, services):
    routes = [{"name": "tor", "kind": "tor", "url": "http://127.0.0.1:9", "description": "Tor"}]
    client = make_client(monitors_enabled="false", allow_private_targets="true", geocoder_url=services.base + "/search",
                         egress_routes=json.dumps(routes))  # fmt: skip
    client.post("/api/demo")
    case = new_case(client, opsec_mode="anonymous", egress="tor")
    item = client.post(f"/api/cases/{case['id']}/items",
                       json={"kind": "entity", "data": {"type": "address", "value": "10 Downing Street"}}).json()  # fmt: skip
    client.app.state.settings.egress_routes = []  # the route was removed: refuse rather than go direct
    r = client.post(f"/api/cases/{case['id']}/items/{item['id']}/geocode")
    assert r.status_code == 422 and services.geocode_requests == []


def test_map_images_are_served_by_argus_and_cached(client, services):
    first = client.get("/api/map/tiles/3/4/2.png")
    assert first.status_code == 200 and first.content == b"\x89PNG fake tile"
    assert first.headers["cache-control"].startswith("private")
    assert client.get("/api/map/tiles/3/4/2.png").content == first.content
    assert services.tile_requests == ["/tiles/3/4/2.png"]  # the second came from the cache
    assert client.get("/api/map/tiles/3/8/0.png").status_code == 404  # x beyond 2^z
    assert client.get("/api/map/tiles/20/0/0.png").status_code == 422
    assert client.get("/api/map/tiles/9/1/1.png").status_code == 502  # the provider sent no image
    client.app.state.settings.map_tile_url = ""
    assert client.get("/api/map/tiles/2/1/1.png").status_code == 404


def test_viewers_see_the_map_but_cannot_look_up(client):
    case = new_case(client)
    item = client.post(f"/api/cases/{case['id']}/items",
                       json={"kind": "entity", "data": {"type": "address", "value": "10 Downing Street"}}).json()  # fmt: skip
    key = client.post("/api/keys", json={"name": "vic", "role": "viewer"}).json()["key"]
    viewer = {"Authorization": f"Bearer {key}"}
    assert client.get(f"/api/cases/{case['id']}/places", headers=viewer).status_code == 200
    assert client.post(f"/api/cases/{case['id']}/items/{item['id']}/geocode", headers=viewer).status_code == 403
    restricted = new_case(client, restricted=True)
    assert client.get(f"/api/cases/{restricted['id']}/timeline", headers=viewer).status_code == 404
    assert re.fullmatch(r"case_[0-9a-f]+", restricted["id"])


def test_the_python_client_covers_timeline_and_map(client):
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "clients" / "python"))
    from argus_client import ArgusClient

    argus = ArgusClient(http=client)
    case = argus.create_case("Map check", purpose="Placing the events of a story on a map")
    item = argus.add_to_case(case["id"], "entity", data={"type": "address", "value": "10 Downing Street"})
    argus.add_to_case(case["id"], "event", title="Meeting", occurred_at="2024-03-01T10:00:00Z")
    assert argus.case_timeline(case["id"])[0]["title"] == "Meeting"
    assert argus.case_places(case["id"])["unplaced"][0]["id"] == item["id"]
    assert argus.geocode(case["id"], item["id"])["data"]["attributes"]["lat"] == "51.5034"
