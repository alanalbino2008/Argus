"""A web page's history (Internet Archive) and reverse image search (TinEye), from a case."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from argus.accounts import connectors, own_keys
from argus.api.research_routes import matches
from argus.intel import page_history
from tests.test_cases import new_case

CDX_ROWS = [["timestamp", "original", "statuscode", "mimetype", "digest"],
            ["20150301120000", "https://acme.example/about", "200", "text/html", "AAA"],
            ["20190704083000", "https://acme.example/about", "200", "text/html", "BBB"],
            ["20230115101500", "https://acme.example/about", "404", "text/html", "CCC"]]  # fmt: skip
TINEYE = {"code": 200, "stats": {"total_results": 3}, "results": {"matches": [
    {"domain": "photos.example", "image_url": "https://photos.example/a.jpg", "score": 98.1, "width": 800, "height": 600,
     "backlinks": [{"url": "https://photos.example/a.jpg", "backlink": "https://photos.example/gallery/1",
                    "crawl_date": "2016-02-03"}, {"backlink": "https://photos.example/gallery/2", "crawl_date": "2014-07-08"}]},
    {"domain": "forum.example", "image_url": "https://forum.example/u.png", "score": 91.0,
     "backlinks": [{"backlink": "https://forum.example/user/jdoe", "crawl_date": "2020-01-01"}]},
]}}  # fmt: skip


class Fake(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        self.seen: list[tuple[str, dict, dict]] = []
        super().__init__(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parts = urlsplit(self.path)
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        self.server.seen.append((parts.path, query, dict(self.headers)))
        if parts.path == "/cdx/search/cdx":
            body = b"" if "nothing" in query.get("url", "") else json.dumps(CDX_ROWS).encode()
        elif parts.path == "/rest/search/":
            body = json.dumps(TINEYE).encode()
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def fake():
    server = Fake()
    yield server
    server.shutdown()


@pytest.fixture
def research(make_client, fake, monkeypatch):
    monkeypatch.setitem(connectors.BASES, "tineye", f"{fake.url}/rest")
    c = make_client(wayback_url=fake.url, allow_private_targets="true", monitors_enabled="false")
    yield c
    own_keys._keys.clear()


def test_reading_the_archive():
    assert page_history.clean_url("acme.example/about#team") == "https://acme.example/about"
    for bad in ("javascript:alert(1)", "https://user:pw@acme.example/", "not a url at all"):
        with pytest.raises(page_history.HistoryError):
            page_history.clean_url(bad)
    h = page_history.versions(CDX_ROWS, "https://web.archive.org", "https://acme.example/about")
    assert (
        len(h["versions"]) == 3
        and h["first_seen"] == "2015-03-01T12:00:00Z"
        and h["last_seen"] == "2023-01-15T10:15:00Z"
    )
    assert h["versions"][0]["archive_url"] == "https://web.archive.org/web/20150301120000/https://acme.example/about"
    assert h["versions"][2]["status"] == "404"
    assert page_history.versions([], "x", "u")["versions"] == []


def test_a_pages_history_from_a_case(research, fake):
    c = research
    case = new_case(c).json()
    r = c.get(f"/api/cases/{case['id']}/page-history", params={"url": "acme.example/about"})
    assert r.status_code == 200 and len(r.json()["versions"]) == 3
    _path, query, _headers = fake.seen[-1]
    assert query["url"] == "https://acme.example/about" and query["collapse"] == "digest"  # distinct versions only
    empty = c.get(f"/api/cases/{case['id']}/page-history", params={"url": "https://nothing.example/"})
    assert empty.status_code == 200 and empty.json()["versions"] == []
    assert c.get(f"/api/cases/{case['id']}/page-history", params={"url": "javascript:x"}).status_code == 422
    assert "case.page_history" in [e["action"] for e in c.get("/api/audit?limit=20").json()]


def test_tineye_matches():
    found = matches(TINEYE)
    assert found[0] == {"domain": "photos.example", "image_url": "https://photos.example/a.jpg", "score": 98.1,
                        "size": "800 x 600", "first_seen": "2014-07-08",
                        "pages": [{"url": "https://photos.example/gallery/1", "crawled": "2016-02-03"},
                                  {"url": "https://photos.example/gallery/2", "crawled": "2014-07-08"}]}  # fmt: skip


def test_reverse_image_search_from_a_case(research, fake):
    c = research
    case = new_case(c).json()
    assert c.get("/api/image-search").json() == {"tineye": False}
    body = {"image_url": "https://cdn.example/avatar.jpg"}
    assert c.post(f"/api/cases/{case['id']}/image-search", json=body).status_code == 409  # no key, no account
    own_keys._keys["tineye"] = "tineye-key-123456"
    assert c.get("/api/image-search").json() == {"tineye": True}
    r = c.post(f"/api/cases/{case['id']}/image-search", json=body)
    assert r.status_code == 200 and r.json()["total"] == 3 and r.json()["matches"][1]["domain"] == "forum.example"
    _path, query, headers = fake.seen[-1]
    assert query["image_url"] == "https://cdn.example/avatar.jpg" and headers.get("x-api-key") == "tineye-key-123456"
    assert c.post(f"/api/cases/{case['id']}/image-search", json={"image_url": "file:///etc/passwd"}).status_code == 422
    assert "case.image_search" in [e["action"] for e in c.get("/api/audit?limit=20").json()]


def test_switched_off(make_client):
    c = make_client(wayback_url="", monitors_enabled="false")
    case = new_case(c).json()
    assert c.get(f"/api/cases/{case['id']}/page-history", params={"url": "acme.example"}).status_code == 409
