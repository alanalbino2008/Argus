"""Bigger username search and same-person checks: the Maigret catalog, profile pages, comparisons."""

from __future__ import annotations

import pytest

from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType, Relation, RelationType
from argus.intel.identity import resolve_people
from argus.intel.profiles import compare
from argus.modules.identity import maigret_catalog, username_hunter
from argus.modules.identity.page_profile import parse_profile_page
from argus.modules.identity.platforms import Platform
from argus.modules.identity.profile_enricher import ProfileEnricherModule
from tests.test_modules_offline import FakeResponse, FakeSession, collect

MAIGRET = {
    "engines": {"Discourse": {"site": {"checkType": "message", "presenseStrs": ["user-profile"],
                                       "absenceStrs": ["page doesn't exist"], "url": "{urlMain}/u/{username}"}}},
    "sites": {
        "ForumOne": {"engine": "Discourse", "urlMain": "https://forum.one.example", "tags": ["forum"],
                     "usernameClaimed": "alice"},
        "PhotoSite": {"checkType": "status_code", "url": "https://photo.example/{username}", "tags": ["photo"],
                      "regexCheck": "^[a-z0-9_]{3,20}$"},
        "OnlyAbsent": {"checkType": "message", "absenceStrs": ["No such user"], "url": "https://absent.example/@{username}"},
        "Redirecting": {"checkType": "response_url", "url": "https://redir.example/{username}"},
        "Retired": {"checkType": "status_code", "url": "https://old.example/{username}", "disabled": True},
        "Plaintext": {"checkType": "status_code", "url": "http://insecure.example/{username}"},
        "BadRegex": {"checkType": "status_code", "url": "https://regex.example/{username}", "regexCheck": "([a-z"},
    },
}  # fmt: skip


def test_the_maigret_catalog_is_read_safely():
    platforms, skipped = maigret_catalog.convert(MAIGRET)
    by_name = {p.name: p for p in platforms}
    assert set(by_name) == {"ForumOne", "PhotoSite", "OnlyAbsent", "BadRegex"} and skipped == 3
    forum = by_name["ForumOne"]
    assert forum.url == "https://forum.one.example/u/{}" and forum.detect == "present"
    assert forum.text == "user-profile" and forum.missing_text == "page doesn't exist" and forum.known == "alice"
    assert forum.category == "Community" and forum.source == "community"
    assert by_name["PhotoSite"].detect == "status" and by_name["PhotoSite"].valid == "^[a-z0-9_]{3,20}$"
    assert by_name["OnlyAbsent"].detect == "absent" and by_name["BadRegex"].valid is None
    assert maigret_catalog.convert({"sites": "nonsense"}) == ([], 0)
    ranked, _ = maigret_catalog.convert({"sites": {
        "Small": {"checkType": "status_code", "url": "https://small.example/{username}", "alexaRank": 900000},
        "Unranked": {"checkType": "status_code", "url": "https://unranked.example/{username}"},
        "Big": {"checkType": "status_code", "url": "https://big.example/{username}", "alexaRank": 12}}})  # fmt: skip
    assert [x.name for x in ranked] == ["Big", "Small", "Unranked"]  # the most visited first


async def test_each_site_is_checked_once_across_catalogs(monkeypatch):
    curated = [Platform(name="GitHub", category="Developer", url="https://github.com/{}")]
    community = [Platform(name="github", category="Developer", url="https://github.com/{}/", source="community"),
                 Platform(name="Forum One", category="Community", url="https://forum.one.example/u/{}", source="community")]  # fmt: skip
    extra, _ = maigret_catalog.convert(MAIGRET)

    async def fake_community(_):
        return community

    async def fake_extra(_):
        return extra

    monkeypatch.setattr(username_hunter, "get_platforms", lambda: curated)
    monkeypatch.setattr(username_hunter, "community_platforms", fake_community)
    monkeypatch.setattr(username_hunter, "extra_platforms", fake_extra)
    chosen = await username_hunter.all_platforms(FakeSession({}))
    names = [p.name for p in chosen]
    assert names[0] == "GitHub" and "github" not in names  # the hand-checked one wins
    assert "Forum One" in names and "ForumOne" not in names  # the same site from Maigret is not repeated
    assert {"PhotoSite", "OnlyAbsent"} <= set(names)


PAGE = """<html><head><title>Jane Roe (@janeroe) • PhotoSite</title>
<meta property="og:title" content="Jane Roe (@janeroe) \u2013 PhotoSite">
<meta property="og:description" content="Wildlife photographer in Leeds. Prints and workshops at janeroe.example">
<meta property="og:image" content="/avatars/jr.jpg">
<script type="application/ld+json">{"@context": "https://schema.org", "@type": "ProfilePage",
 "mainEntity": {"@type": "Person", "name": "Jane Roe", "homeLocation": {"name": "Leeds, UK"},
 "sameAs": ["https://janeroe.example", "https://photo.example/janeroe"]}}</script>
<link rel="me" href="https://mastodon.example/@janeroe"></head><body>…</body></html>"""


def test_a_profile_page_gives_name_bio_photo_and_links():
    facts = parse_profile_page(PAGE, "https://photo.example/janeroe", "janeroe", "PhotoSite")
    assert facts["display_name"] == "Jane Roe" and facts["location"] == "Leeds, UK"
    assert (
        facts["bio"].startswith("Wildlife photographer")
        and facts["avatar_url"] == "https://photo.example/avatars/jr.jpg"
    )
    assert [x["url"] for x in facts["links"]] == ["https://janeroe.example", "https://mastodon.example/@janeroe"]


@pytest.mark.parametrize("page", [
    '<title>Sign in | PhotoSite</title><meta name="description" content="Join millions of photographers. Sign up today">',
    '<meta property="og:title" content="janeroe | PhotoSite"><meta property="og:description" content="Short">',
    "<html><head><title>PhotoSite</title></head></html>",
])  # fmt: skip
def test_sign_in_pages_and_bare_handles_give_nothing(page):
    facts = parse_profile_page(page, "https://photo.example/janeroe", "janeroe", "PhotoSite")
    assert set(facts) == {"source"}


async def test_profiles_on_any_site_are_read_from_their_page():
    session = FakeSession({r"photo\.example/janeroe$": FakeResponse(200, PAGE, {"Content-Type": "text/html"})})
    profile = Entity.create(EntityType.SOCIAL_PROFILE, "https://photo.example/janeroe", label="PhotoSite: janeroe",
                            metadata={"platform": "PhotoSite", "username": "janeroe"}, confidence=0.75)  # fmt: skip
    assert ProfileEnricherModule().can_handle(profile)
    entities, _ = await collect(ProfileEnricherModule(), profile, session)
    assert profile.metadata["profile"]["display_name"] == "Jane Roe"
    assert "https://janeroe.example" in profile.metadata["profile"]["links"]
    assert "Jane Roe" in [e.value for e in entities if e.type == EntityType.PERSON]
    weak = Entity.create(EntityType.SOCIAL_PROFILE, "https://x.example/j", metadata={"platform": "X"}, confidence=0.3)
    assert not ProfileEnricherModule().can_handle(weak)  # too unlikely to be theirs to be worth reading


# ---------------------------------------------------------------------------- same person?
def p(url="", **facts):
    return {"url": url, "facts": facts, "avatar_hash": facts.pop("avatar_hash", None)}


@pytest.mark.parametrize("a, b, verdict, words", [
    (p("https://github.com/janeroe"), p("https://photo.example/janeroe", links=["https://github.com/janeroe"]), "same", "links to this one"),
    (p(website="https://janeroe.example"), p(links=["https://www.janeroe.example/"]), "same", "both link to janeroe.example"),
    (p(display_name="Jane Roe", location="Leeds"), p(display_name="ROE, Jane", location="Leeds, UK"), "same", "the same place"),
    (p(display_name="Jane Roe"), p(display_name="Jane A. Roe"), "likely", "the same name"),
    (p(display_name="Jane Roe", location="Leeds"), p(display_name="Bob Smith", location="Paris"), "different", "different names"),
    (p(bio="Wildlife photographer, prints and workshops"), p(bio="Workshops in wildlife photography and prints"), "likely", "similar bios"),
    (p(display_name="Jane Roe"), p(), "unclear", ""),
    (p(display_name="Jane Roe", website="https://linktr.ee/jr"), p(display_name="Bob Smith", website="https://linktr.ee/x"), "different", "different names"),
])  # fmt: skip
def test_comparing_two_profiles(a, b, verdict, words):
    result = compare(a, b)
    assert result["verdict"] == verdict, result
    assert words in " ".join(result["agree"] + result["conflict"])


def test_the_people_view_explains_which_accounts_are_the_same_person():
    g = IntelligenceGraph("ppl")
    handle = Entity.create(EntityType.USERNAME, "janeroe")
    github = Entity.create(EntityType.SOCIAL_PROFILE, "https://github.com/janeroe", label="GitHub: janeroe", depth=1,
                           source_module="github_hunter", confidence=0.95,
                           metadata={"platform": "GitHub", "username": "janeroe",
                                     "profile": {"display_name": "Jane Roe", "website": "https://janeroe.example",
                                                 "location": "Leeds"}})  # fmt: skip
    photo = Entity.create(EntityType.SOCIAL_PROFILE, "https://photo.example/janeroe", label="PhotoSite: janeroe",
                          depth=1, source_module="username_hunter", confidence=0.75,
                          metadata={"platform": "PhotoSite", "username": "janeroe",
                                    "profile": {"display_name": "Jane Roe", "links": ["https://janeroe.example"]}})  # fmt: skip
    other = Entity.create(EntityType.SOCIAL_PROFILE, "https://forum.example/u/janeroe", label="Forum: janeroe",
                          depth=1, source_module="username_hunter", confidence=0.75,
                          metadata={"platform": "Forum", "username": "janeroe",
                                    "profile": {"display_name": "Johan Eriksson", "location": "Stockholm"}})  # fmt: skip
    for e in (handle, github, photo, other):
        g.add_entity(e, is_seed=e.depth == 0)
    for e in (github, photo, other):
        g.add_relation(Relation.create(handle.id, e.id, RelationType.HAS_ACCOUNT, label="Registered"))
    persona = resolve_people(g)["personas"][0]
    accounts = {a["platform"]: a for a in persona["accounts"]}
    assert accounts["PhotoSite"]["link"] == "strong"  # was "probable": its profile links to her website
    assert "both link to janeroe.example" in accounts["PhotoSite"]["matches"][0]["reasons"]
    assert accounts["Forum"]["link"] == "probable" and accounts["Forum"]["doubtful"][0]["platform"] in (
        "GitHub",
        "PhotoSite",
    )
    assert "different names (Johan Eriksson / Jane Roe)" in str(accounts["Forum"]["doubtful"])


async def test_the_extra_catalog_is_capped_and_cached(tmp_path, monkeypatch):
    import json

    from argus.core.settings import get_settings

    path = tmp_path / "maigret.json"
    path.write_text(json.dumps(MAIGRET))
    monkeypatch.setenv("ARGUS_USERNAME_CATALOG_EXTRA_FILE", str(path))
    monkeypatch.setenv("ARGUS_USERNAME_CATALOG_EXTRA_LIMIT", "2")
    get_settings.cache_clear()
    maigret_catalog.reset()
    assert len(await maigret_catalog.extra_platforms(FakeSession({}))) == 2
    path.write_text("not json any more")
    assert len(await maigret_catalog.extra_platforms(FakeSession({}))) == 2  # cached
    assert maigret_catalog.status()["extra_sites"] == 4
