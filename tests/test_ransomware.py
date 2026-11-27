"""Ransomware intelligence hub: normalising the feed, stats, facets, new-group detection, and the API."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from argus.intel import ransomware as R

NOW = datetime(2026, 11, 20, tzinfo=timezone.utc)


def _day(delta):
    return (NOW - timedelta(days=delta)).date().isoformat()


RAW = [
    {"victim": "Acme Corp", "group": "lockbit3", "discovered": _day(1), "country": "US", "activity": "Manufacturing",
     "domain": "acme.example"},
    {"post_title": "Globex", "group_name": "akira", "published": _day(3), "country": "gb", "activity": "Healthcare"},
    {"victim": "Initech", "group": "akira", "discovered": _day(10), "country": "US"},
    {"victim": "Acme Corp", "group": "lockbit3", "discovered": _day(1)},  # duplicate of the first
    {"victim": "NewVictim", "group": "shinyhunters", "discovered": _day(2)},  # a group not seen before
    "garbage",
]  # fmt: skip


def test_posts_are_normalised_deduped_and_sorted():
    posts = R.recent_posts(RAW)
    assert [p["victim"] for p in posts] == ["Acme Corp", "NewVictim", "Globex", "Initech"]  # newest first, deduped
    first = posts[0]
    assert first["group"] == "lockbit3" and first["country"] == "US" and first["sector"] == "Manufacturing"
    assert first["website"] == "acme.example" and first["published"] == _day(1)


def test_filters_by_group_country_sector_and_text():
    posts = R.recent_posts(RAW)
    assert {p["victim"] for p in R.filter_posts(posts, group="akira")} == {"Globex", "Initech"}
    assert {p["victim"] for p in R.filter_posts(posts, country="US")} == {"Acme Corp", "Initech"}
    assert {p["victim"] for p in R.filter_posts(posts, sector="health")} == {"Globex"}
    assert {p["victim"] for p in R.filter_posts(posts, q="acme")} == {"Acme Corp"}


def test_facets_and_stats():
    posts = R.recent_posts(RAW)
    facets = R.facets(posts)
    assert facets["groups"][0] == {"name": "akira", "count": 2}  # busiest first
    assert {f["name"] for f in facets["countries"]} == {"US", "GB"}
    s = R.stats(posts, NOW)
    assert s["total"] == 4 and s["last_7_days"] == 3 and s["last_30_days"] == 4 and s["active_groups"] == 3
    assert len(s["by_day"]) == 14 and s["by_day"][-1]["day"] == NOW.date().isoformat()
    assert sum(d["count"] for d in s["by_day"]) == 4  # all four posts fall within the last 14 days


def test_new_group_detection():
    posts = R.recent_posts(RAW)
    known = {"lockbit3", "akira"}
    new, updated = R.detect_new_groups(posts, known)
    assert new == ["shinyhunters"] and "shinyhunters" in updated and updated >= known
    # once known, nothing new
    assert R.detect_new_groups(posts, updated)[0] == []


# ---------------------------------------------------------------------------- the API
class FakeRansomSources:
    def __init__(self, feed="https://feed.example", posts=None, roster=None):
        self.ransomware_feed = feed
        self._posts = posts if posts is not None else RAW
        self._roster = roster or [{"name": "lockbit3"}, {"name": "akira"}, {"name": "cl0p"}]

    async def recent_victims(self):
        return self._posts

    async def groups(self):
        return self._roster

    async def close(self):
        pass


@pytest.fixture
def client(make_client):
    return make_client(monitors_enabled="false", notifications_enabled="false", report_schedules_enabled="false")


def _install(client, **kw):
    client.app.state.exposure_monitor.sources = FakeRansomSources(**kw)


def test_the_hub_endpoint_returns_posts_stats_and_new_groups(client):
    _install(client)
    out = client.get("/api/ransomware").json()
    assert out["capabilities"]["ransomware"] is True
    assert out["stats"]["active_groups"] == 3 and out["roster_count"] == 3
    assert out["facets"]["groups"][0]["name"] == "akira"
    assert out["new_groups"] == ["akira", "lockbit3", "shinyhunters"]  # nothing known yet, so all are new
    assert out["posts"][0]["victim"] == "Acme Corp"
    # the snapshot is persisted: a second call reports no new groups
    assert client.get("/api/ransomware").json()["new_groups"] == []
    assert any(e["action"] == "ransomware.view" for e in client.get("/api/audit?limit=10").json())


def test_the_hub_endpoint_filters(client):
    _install(client)
    out = client.get("/api/ransomware?group=akira").json()
    assert {p["victim"] for p in out["posts"]} == {"Globex", "Initech"} and out["total_matched"] == 2
    assert client.get("/api/ransomware?country=US").json()["total_matched"] == 2
    assert client.get("/api/ransomware?q=globex").json()["total_matched"] == 1


def test_the_hub_is_off_without_a_feed(client):
    _install(client, feed="")
    out = client.get("/api/ransomware").json()
    assert out["capabilities"]["ransomware"] is False and out["posts"] == [] and out["stats"]["total"] == 0
