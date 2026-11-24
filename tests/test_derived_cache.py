"""Phase 85: campaigns and TAXII collections are cached per data version and answer If-None-Match."""

from __future__ import annotations

from argus.api import campaign_routes
from argus.core.models import EntityType, generate_entity_id
from argus.storage import data_version
from tests.test_taxii import TAXII, _basic, _fill, tc  # noqa: F401  (fixture used by name)

EVIL = generate_entity_id(EntityType.IP_ADDRESS, "203.0.113.5")


def _counting(monkeypatch):
    calls = []
    real = campaign_routes.cluster

    def counted(*args):
        calls.append(1)
        return real(*args)

    monkeypatch.setattr(campaign_routes, "cluster", counted)
    return calls


def _tag(c, entity_id, value, tags):
    r = c.put(f"/api/annotations/{entity_id}", json={"entity_type": "ip_address", "value": value, "tags": tags})
    assert r.status_code == 200, r.text


def test_campaigns_are_computed_once_per_change_and_answer_304(tc, monkeypatch):  # noqa: F811
    c, _ = tc
    _fill(c)
    calls = _counting(monkeypatch)
    first = c.get("/api/campaigns")
    assert first.status_code == 200 and first.headers["etag"].startswith('W/"')
    assert first.headers["cache-control"] == "private, no-cache"
    again = c.get("/api/campaigns")
    assert again.json() == first.json() and len(calls) == 1  # served from the cache
    unchanged = c.get("/api/campaigns", headers={"If-None-Match": first.headers["etag"]})
    assert (
        unchanged.status_code == 304 and unchanged.content == b"" and unchanged.headers["etag"] == first.headers["etag"]
    )
    assert len(calls) == 1

    _tag(c, EVIL, "203.0.113.5", ["c2"])  # a change to what campaigns are made from
    changed = c.get("/api/campaigns", headers={"If-None-Match": first.headers["etag"]})
    assert changed.status_code == 200 and changed.headers["etag"] != first.headers["etag"] and len(calls) == 2
    # The tagged address links to the lookalike resolving to it: the change is in the answer, not a stale copy.
    assert changed.json()["indicators"] == first.json()["indicators"] + 1


def test_watch_runs_and_takedowns_change_the_version(tc):  # noqa: F811
    c, _ = tc
    _fill(c)
    db, ws = c.app.state.db, "ws_default"
    before = c.portal.call(data_version.current, db, ws)
    assert before > 0  # annotations, two watches and their runs were written
    watch = c.get("/api/brand-watches").json()[0]
    assert c.post(f"/api/brand-watches/{watch['id']}/run").status_code == 202
    c.portal.call(c.app.state.brand_watcher.tick)
    after_run = c.portal.call(data_version.current, db, ws)
    assert after_run > before
    assert c.delete(f"/api/brand-watches/{watch['id']}").status_code in (200, 204)
    assert c.portal.call(data_version.current, db, ws) > after_run
    assert c.portal.call(data_version.current, db, "nobody") == 0


def test_taxii_pages_carry_etags_and_answer_304(tc, monkeypatch):  # noqa: F811
    c, viewer = tc
    _fill(c)
    calls = _counting(monkeypatch)
    headers = {**_basic(viewer), "Accept": TAXII}
    url = "/taxii2/ws_default/collections/campaigns/objects/"
    first = c.get(url, headers=headers)
    assert first.status_code == 200 and first.headers["etag"]
    assert c.get(url, headers=headers).json() == first.json() and len(calls) == 1
    assert c.get(url, headers={**headers, "If-None-Match": first.headers["etag"]}).status_code == 304
    # A different page or filter is a different answer with its own ETag.
    other = c.get(url, headers={**headers, "If-None-Match": first.headers["etag"]}, params={"limit": 1})
    assert other.status_code == 200 and other.headers["etag"] != first.headers["etag"]
    manifest = c.get(url.replace("objects/", "manifest/"), headers={**headers, "If-None-Match": first.headers["etag"]})
    assert manifest.status_code == 200  # the manifest's ETag is its own

    tagged = "/taxii2/ws_default/collections/tagged/objects/"
    held = c.get(tagged, headers=headers)
    _tag(c, EVIL, "203.0.113.5", ["c2"])
    fresh = c.get(tagged, headers={**headers, "If-None-Match": held.headers["etag"]})
    assert fresh.status_code == 200 and len(fresh.json()["objects"]) > len(held.json()["objects"])
    reads = [e for e in c.get("/api/audit?limit=200").json() if e["action"] == "taxii.read"]
    assert any((e.get("details") or {}).get("not_modified") for e in reads)  # 304s are audited too


def test_helpers():
    tag = data_version.etag(3, "/api/campaigns", [])
    assert tag == data_version.etag(3, "/api/campaigns", []) and tag != data_version.etag(4, "/api/campaigns", [])
    assert data_version.not_modified(tag, tag) and data_version.not_modified(tag.removeprefix("W/"), tag)
    assert data_version.not_modified(f'"other", {tag}', tag) and data_version.not_modified("*", tag)
    assert not data_version.not_modified(None, tag) and not data_version.not_modified('"other"', tag)
    cache = data_version.VersionedCache(maxsize=2)
    cache.put("a", 1, "A1")
    assert cache.get("a", 1) == "A1" and cache.get("a", 2) is None
    cache.put("b", 1, "B")
    cache.get("a", 1)
    cache.put("c", 1, "C")  # "b" was used least recently
    assert cache.get("b", 1) is None and cache.get("a", 1) == "A1" and cache.get("c", 1) == "C"
