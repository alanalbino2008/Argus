"""Phases 105-108: more places to learn about a person, all public and passive."""

from __future__ import annotations

import hashlib
import re

import pytest

from argus.core.models import Entity, EntityType, ScanConfig
from argus.intel import subjects as S
from argus.modules.identity import git_identity, name_guesser
from argus.modules.identity.git_identity import GitIdentityModule
from argus.modules.identity.name_guesser import NameGuesserModule
from tests.test_modules_offline import FakeResponse, FakeSession, values

E = EntityType


async def run(module, entity, session, **config):
    cfg = ScanConfig(target=entity.value, target_type=entity.type, **config)
    items = [x async for x in module.run(entity, session, cfg)]
    return [x for x in items if isinstance(x, Entity)], [x for x in items if not isinstance(x, Entity)]


def md5(address: str) -> str:
    return hashlib.md5(address.encode(), usedforsecurity=False).hexdigest()


# ---------------------------------------------------------------------------- Phase 105: guesses from a name
def test_likely_handles_and_addresses():
    assert name_guesser.handles("Jane Doe")[:3] == ["janedoe", "jane.doe", "jane_doe"]
    with_year = name_guesser.handles("Jane Doe", 1984)
    assert {"janedoe84", "janedoe1984", "jdoe84"} <= set(with_year)
    assert name_guesser.handles("Zoë Ångström-Smith")[0] == "zoesmith"  # accents and double-barrelled names
    assert name_guesser.handles("Madonna") == []  # one word: nothing to build from
    emails = name_guesser.guessed_emails("Jane Doe", 1984, ["janedoe.dev"])
    assert emails[0] == "jane.doe@janedoe.dev" and "jane.doe@gmail.com" in emails
    assert len(emails) <= name_guesser.MAX_EMAILS


async def test_only_confirmed_guesses_are_kept():
    person = Entity.create(E.PERSON, "Jane Doe")
    session = FakeSession({
        r"api\.github\.com/users/janedoe$": FakeResponse(200, {"login": "janedoe", "name": "Jane Doe",
                                                               "location": "Leeds", "company": "Acme"}),
        r"api\.github\.com/users/jdoe$": FakeResponse(200, {"login": "jdoe", "name": "John Dorian"}),  # namesake
        r"gitlab\.com/api/v4/users\?username=jane\.doe$": FakeResponse(200, [{"name": "Jane Doe",
                                                                             "web_url": "https://gitlab.com/jane.doe"}]),
        rf"gravatar\.com/{md5('jane.doe@gmail.com')}\.json": FakeResponse(200, {"entry": [{"displayName": "Jane Doe"}]}),
        rf"gravatar\.com/{md5('jdoe@outlook.com')}\.json": FakeResponse(200, {"entry": [{"displayName": "jd"}]}),
        r"keyserver\.ubuntu\.com": FakeResponse(200, "info:1:2\npub:ABCDEF0123456789:1:2048:1500000000::\n"
                                                     "uid:Jane%20Doe%20<jane@doe.family>:1500000000::\n"
                                                     "pub:1111222233334444:1:2048:1500000000::\n"
                                                     "uid:Other%20Person%20<other@example.com>:1500000000::\n"),
    })  # fmt: skip
    entities, _ = await run(NameGuesserModule(), person, session, hints={"birth_year": 1984})
    profiles = values(entities, E.SOCIAL_PROFILE)
    assert profiles == ["https://github.com/janedoe", "https://gitlab.com/jane.doe"]  # not the namesake
    github = next(e for e in entities if e.value == "https://github.com/janedoe")
    assert github.metadata["guessed"] and github.metadata["profile"]["location"] == "Leeds"
    assert values(entities, E.EMAIL) == ["jane.doe@gmail.com", "jane@doe.family", "jdoe@outlook.com"]
    same = next(e for e in entities if e.value == "jane.doe@gmail.com")
    other = next(e for e in entities if e.value == "jdoe@outlook.com")
    assert same.confidence > other.confidence and same.metadata["gravatar_name"] == "Jane Doe"
    assert "other@example.com" not in values(entities, E.EMAIL)  # a key in someone else's name
    assert person.metadata["name_guesses"]["usernames"] == name_guesser.MAX_HANDLES
    assert all("reset" not in u and "signup" not in u and "register" not in u for u in session.requested)


# ---------------------------------------------------------------------------- Phase 105: public Git history
PATCH = "From 1234 Mon Sep 17 00:00:00 2001\nFrom: Jane Doe <jane@doe.family>\nDate: Tue, 3 Jan 2023 21:14:05 +0100\n"


async def test_an_email_address_leads_to_the_github_accounts_that_commit_with_it():
    mail = Entity.create(E.EMAIL, "jane@doe.family")
    session = FakeSession(
        {
            r"search/commits\?q=author-email%3Ajane%40doe\.family": FakeResponse(
                200,
                {
                    "total_count": 4,
                    "items": [{"author": {"login": "janedoe"}, "commit": {"author": {"name": "Jane Doe"}}}] * 4,
                },
            )
        }
    )
    entities, relations = await run(GitIdentityModule(), mail, session)
    (profile,) = entities
    assert profile.value == "https://github.com/janedoe" and profile.metadata["origin"].startswith("verified")
    assert mail.metadata["git_commits"] == {"found": 4, "names": ["Jane Doe"]}
    assert "(4)" in relations[0].label


async def test_a_username_leads_to_commit_addresses_and_a_time_zone():
    user = Entity.create(E.USERNAME, "janedoe")
    commit = {"sha": "abc", "commit": {"author": {"name": "Jane Doe", "email": "jane@doe.family"}}}
    hidden = {"sha": "def", "commit": {"author": {"name": "Jane Doe", "email": "1+janedoe@users.noreply.github.com"}}}
    session = FakeSession({
        r"/users/janedoe/repos": FakeResponse(200, [{"full_name": "janedoe/notes", "fork": False},
                                                    {"full_name": "janedoe/forked", "fork": True}]),
        r"/repos/janedoe/notes/commits": FakeResponse(200, [commit, hidden, commit]),
        r"github\.com/janedoe/notes/commit/\w+\.patch": FakeResponse(200, PATCH),
    })  # fmt: skip
    entities, _ = await run(GitIdentityModule(), user, session)
    assert values(entities, E.EMAIL) == ["jane@doe.family"]  # the private noreply address is skipped
    assert user.metadata["timezone"]["usual_offset"] == "+01:00" and user.metadata["git_names"] == ["Jane Doe"]
    assert not any("forked" in u for u in session.requested)
    assert git_identity.offset_from_patch("Date: Wed, 1 Feb 2023 08:00:00 -0500\n") == "-05:00"


def test_hints_for_the_modules_come_from_the_known_details():
    known = S.clean_known({"emails": ["jane@gmail.com", "jane@acme-logistics.co.uk"], "websites": ["janedoe.dev"],
                           "birth_year": 1984})  # fmt: skip
    assert S.hints({**known, "city": "Leeds"}) == {
        "domains": ["janedoe.dev", "acme-logistics.co.uk"],
        "birth_year": 1984,
        "city": "Leeds",
    }
    assert "name_guesser" in S.SEARCHES["name"]["modules"] and "git_identity" in S.SEARCHES["email"]["modules"]


# ---------------------------------------------------------------------------- Phase 106: records and the web
async def test_research_and_encyclopaedic_records_in_the_same_name():
    from argus.modules.identity.public_records import PublicRecordsModule

    person = Entity.create(E.PERSON, "Jane Doe")
    claims = {"P31": [{"mainsnak": {"datavalue": {"value": {"id": "Q5"}}}}],
              "P569": [{"mainsnak": {"datavalue": {"value": {"time": "+1951-02-03T00:00:00Z"}}}}]}  # fmt: skip
    session = FakeSession({
        r"pub\.orcid\.org": FakeResponse(200, {"expanded-result": [
            {"orcid-id": "0000-0002-1825-0097", "given-names": "Jane", "family-names": "Doe",
             "institution-name": ["University of Leeds"], "email": ["j.doe@leeds.ac.uk"]},
            {"orcid-id": "0000-0001-0000-0000", "given-names": "Janet", "family-names": "Dobbs"}]}),
        r"api\.openalex\.org/authors": FakeResponse(200, {"results": [
            {"id": "https://openalex.org/A123", "display_name": "Jane Doe", "works_count": 12,
             "last_known_institutions": [{"display_name": "University of Leeds", "country_code": "GB"}]}]}),
        r"wbsearchentities": FakeResponse(200, {"search": [{"id": "Q42", "label": "Jane Doe",
                                                            "description": "British novelist"}]}),
        r"wbgetentities": FakeResponse(200, {"entities": {"Q42": {"claims": claims}}}),
    })  # fmt: skip
    entities, _ = await run(PublicRecordsModule(), person, session)
    by_url = {e.value: e.metadata for e in entities}
    assert set(by_url) == {"https://orcid.org/0000-0002-1825-0097", "https://openalex.org/authors/A123",
                           "https://www.wikidata.org/wiki/Q42"}  # not "Janet Dobbs"  # fmt: skip
    orcid = by_url["https://orcid.org/0000-0002-1825-0097"]["profile"]
    assert orcid["company"] == "University of Leeds" and orcid["public_email"] == "j.doe@leeds.ac.uk"
    assert by_url["https://www.wikidata.org/wiki/Q42"]["profile"]["born"] == "1951"
    # Scored against a 1984-born person, the Wikidata namesake is ruled out by the year of birth.
    known = S.clean_known({"names": ["Jane Doe"], "birth_year": 1984, "employer": "University of Leeds"})
    found = {c["value"]: c for c in S.from_graph(_graph(entities), {"kind": "name", "value": "Jane Doe"}, "inv")}
    for c in found.values():
        c.update(S.score(c, known))
    assert found["https://www.wikidata.org/wiki/Q42"]["verdict"] == "unlikely"
    assert any("employer" in r for r in found["https://orcid.org/0000-0002-1825-0097"]["agree"])


def _graph(entities):
    from argus.core.graph import IntelligenceGraph

    g = IntelligenceGraph("t")
    for e in entities:
        g.add_entity(e)
    return g


async def test_developer_sites_give_profiles_and_publishing_addresses():
    from argus.modules.identity.public_records import DeveloperFootprintModule

    user = Entity.create(E.USERNAME, "janedoe")
    session = FakeSession({
        r"api\.stackexchange\.com": FakeResponse(200, {"items": [
            {"display_name": "janedoe2", "link": "https://stackoverflow.com/users/2"},
            {"display_name": "JaneDoe", "link": "https://stackoverflow.com/users/1/janedoe", "location": "Leeds"}]}),
        r"registry\.npmjs\.org": FakeResponse(200, {"objects": [
            {"package": {"name": "left-pad-2", "maintainers": [{"username": "janedoe", "email": "jane@doe.family"}]}},
            {"package": {"name": "other", "maintainers": [{"username": "someoneelse", "email": "x@y.z"}]}}]}),
    })  # fmt: skip
    entities, _ = await run(DeveloperFootprintModule(), user, session)
    assert values(entities, E.SOCIAL_PROFILE) == ["https://stackoverflow.com/users/1/janedoe",
                                                  "https://www.npmjs.com/~janedoe"]  # fmt: skip
    assert values(entities, E.EMAIL) == ["jane@doe.family"]


async def test_web_search_finds_social_profiles_for_a_name(monkeypatch):
    from argus.core.settings import get_settings
    from argus.modules.identity.web_mentions import WebMentionsModule
    from tests.test_phone import SearchSession

    monkeypatch.setenv("ARGUS_WEB_SEARCH_API_KEY", "own-search-key")
    get_settings.cache_clear()
    session = SearchSession(FakeResponse(200, {"web": {"results": [
        {"url": "https://www.instagram.com/janedoe84/", "title": "Jane Doe (@janedoe84) • Instagram photos and videos",
         "description": "1,204 Followers - Leeds"},
        {"url": "https://uk.linkedin.com/in/jane-doe-123", "title": "Jane Doe - Engineer - Acme Logistics | LinkedIn",
         "description": "Leeds, England"},
        {"url": "https://www.facebook.com/groups/leeds", "title": "Leeds group", "description": "Jane Doe posted"},
        {"url": "https://cv.example.org/jane.pdf", "title": "CV - Jane M. Doe", "description": "Engineer"},
        {"url": "https://example.org/x", "title": "Janet Doering", "description": "Not her"}]}}))  # fmt: skip
    person = Entity.create(E.PERSON, "Jane Doe")
    entities, _ = await run(WebMentionsModule(), person, session, hints={"city": "Leeds"})
    queries = [p["q"] for p in session.params]
    assert len(queries) == 3 and "site:instagram.com" in queries[0] and '"Leeds"' in queries[1]
    assert all(len(q) <= 160 for q in queries) and "site:snapchat.com" in queries[0]
    assert "filetype:pdf" in queries[2]
    profiles = {e.value: e for e in entities if e.type == E.SOCIAL_PROFILE}
    assert set(profiles) == {"https://www.instagram.com/janedoe84", "https://www.linkedin.com/in/jane-doe-123"}
    assert profiles["https://www.instagram.com/janedoe84"].metadata["profile"]["display_name"] == "Jane Doe"
    pages = values(entities, E.URL)
    assert "https://cv.example.org/jane.pdf" in pages and "https://example.org/x" not in pages
    assert "https://www.facebook.com/groups/leeds" in pages  # a mention, not a profile
    get_settings.cache_clear()


# ---------------------------------------------------------------------------- Phase 107: hidden history
OLD_PAGE = """<html><head><title>Jane Smith (@jdoe) / X</title>
<meta property="og:description" content="Nurse in Leeds. Also at instagram.com/janesmith_">
</head><body><a href="https://web.archive.org/web/20150101000000/https://www.instagram.com/janesmith_/">IG</a>
<a href="https://www.facebook.com/jane.smith.leeds">FB</a><a href="https://x.com/jdoe/status/1">a post</a></body></html>"""
NEW_PAGE = '<html><head><meta content="Jane Doe (@jdoe) / X" property="og:title"></head><body></body></html>'


async def test_archived_copies_give_earlier_names_and_accounts_once_linked():
    from argus.modules.identity.profile_history import ProfileHistoryModule, page_facts

    facts = page_facts(OLD_PAGE)
    assert facts["name"] == "Jane Smith" and "Nurse in Leeds" in facts["description"]
    assert facts["links"] == ["https://www.instagram.com/janesmith_", "https://www.facebook.com/jane.smith.leeds"]
    profile = Entity.create(E.SOCIAL_PROFILE, "https://x.com/jdoe", confidence=0.9, depth=1,
                            metadata={"profile": {"display_name": "Jane Doe"}})  # fmt: skip
    session = FakeSession({
        r"cdx/search/cdx": FakeResponse(200, [["timestamp", "statuscode", "digest"], ["20150101000000", "200", "a"],
                                              ["20190101000000", "200", "b"], ["20240101000000", "200", "c"]]),
        r"web/20150101000000id_/": FakeResponse(200, OLD_PAGE),
        r"web/20240101000000id_/": FakeResponse(200, NEW_PAGE),
    })  # fmt: skip
    entities, relations = await run(ProfileHistoryModule(), profile, session)
    history = profile.metadata["history"]
    assert history["first_archived"] == "2015-01-01" and history["versions"] == 3
    assert history["earlier_names"] == ["Jane Smith"]
    assert values(entities, E.SOCIAL_PROFILE) == ["https://www.facebook.com/jane.smith.leeds",
                                                  "https://www.instagram.com/janesmith_"]  # fmt: skip
    assert "2015-01-01" in relations[0].label
    assert all("web.archive.org" in u for u in session.requested)  # only the archive is contacted
    assert not ProfileHistoryModule().can_handle(Entity.create(E.SOCIAL_PROFILE, "https://a.b/c", confidence=0.3))


def test_time_zones_and_earlier_names_count_in_the_score():
    known = S.clean_known({"names": ["Jane Doe"], "utc_offset": "+01:00"})
    near = {"kind": "profile", "value": "https://github.com/jdoe", "grade": "strong",
            "facts": {"timezone": {"usual_offset": "+00:00"}, "archived_names": ["Jane Doe", "jd"],
                      "display_name": "jd"}}  # fmt: skip
    far = {"kind": "profile", "value": "https://github.com/jdoe2", "grade": "strong",
           "facts": {"timezone": {"usual_offset": "-05:00"}}}  # fmt: skip
    a, b = S.score(near, known), S.score(far, known)
    assert "works in the same time zone (UTC+00:00)" in a["agree"]
    assert "showed the same name in an archived copy (Jane Doe)" in a["agree"]
    assert b["conflict"] == ["works in UTC-05:00, not UTC+01:00"] and b["verdict"] == "unlikely"
    import pytest

    with pytest.raises(S.KnownDetailsError, match="UTC offset"):
        S.clean_known({"utc_offset": "CET"})
    # Confirming an account with a known time zone teaches it to the known details.
    learned = S.add_to_known(S.clean_known({"names": ["Jane Doe"]}), near)
    assert learned["utc_offset"] == "+00:00"


# ---------------------------------------------------------------------------- Phase 108: the big social networks
IG = """<html><head><meta property="og:title" content="Jane Doe (@janedoe84) &bull; Instagram photos and videos">
<meta property="og:description" content="1,204 Followers, 300 Following - Nurse, Leeds">
<meta property="og:image" content="https://scontent.cdninstagram.com/jane.jpg"></head></html>"""
FB_WALL = '<html><head><meta property="og:title" content="Log into Facebook"></head><body>login_form</body></html>'
TG = """<html><head><meta property="og:description" content="Leeds nurse. DMs open."><meta property="og:image" content="https://cdn.t.me/a.jpg"></head>
<body><div class="tgme_page_title" dir="auto"><span dir="auto">Jane D.</span></div><div class="tgme_page_extra">@janedoe84</div></body></html>"""
TG_EMPTY = '<html><head><meta property="og:title" content="Telegram: Contact @janedoe84"></head><body></body></html>'


async def test_public_profile_pages_on_the_big_networks(monkeypatch):
    from argus.modules.identity import social_pages
    from argus.modules.identity.social_pages import SocialPagesModule

    async def fingerprint(session, url):
        return "0f0f0f0f0f0f0f0f" if url else None

    monkeypatch.setattr(social_pages, "fetch_fingerprint", fingerprint)
    user = Entity.create(E.USERNAME, "janedoe84")
    session = FakeSession({
        r"instagram\.com/janedoe84": FakeResponse(200, IG),
        r"facebook\.com/janedoe84": FakeResponse(200, FB_WALL),
        r"t\.me/janedoe84": FakeResponse(200, TG),
        r"tiktok\.com/@janedoe84": FakeResponse(403, "blocked"),
    })  # fmt: skip
    entities, _ = await run(SocialPagesModule(), user, session)
    found = {e.metadata["platform"]: e for e in entities}
    assert set(found) == {"Instagram", "Telegram"}
    assert found["Instagram"].value == "https://www.instagram.com/janedoe84"
    assert found["Instagram"].metadata["profile"]["display_name"] == "Jane Doe"
    assert "Nurse, Leeds" in found["Instagram"].metadata["profile"]["bio"]
    assert found["Instagram"].metadata["avatar_hash"] == "0f0f0f0f0f0f0f0f"  # for photo matching
    assert found["Telegram"].metadata["profile"]["display_name"] == "Jane D."
    checked = user.metadata["social_pages"]
    assert checked["Facebook"] == "sign-in wall" and checked["TikTok"] == "sign-in wall"
    assert checked["Snapchat"] == "not found"
    assert all("login" not in u and "cookie" not in u for u in session.requested)
    # Telegram answers every handle; an empty page is not a profile.
    assert social_pages.read_page("Telegram", "janedoe84", TG_EMPTY) is None


async def test_a_profile_found_by_web_search_gets_its_public_details(monkeypatch):
    from argus.modules.identity import social_pages
    from argus.modules.identity.social_pages import SocialPagesModule, platform_of

    async def fingerprint(session, url):
        return "abababababababab"

    monkeypatch.setattr(social_pages, "fetch_fingerprint", fingerprint)
    assert platform_of("https://www.snapchat.com/add/jdoe") == ("Snapchat", "jdoe")
    assert platform_of("https://www.youtube.com/@JaneDoe") == ("YouTube", "JaneDoe")
    assert platform_of("https://example.com/jdoe") is None
    found = Entity.create(E.SOCIAL_PROFILE, "https://www.instagram.com/janedoe84", depth=1, confidence=0.5,
                          metadata={"platform": "Instagram", "profile": {"display_name": "Jane Doe"}})  # fmt: skip
    module = SocialPagesModule()
    assert module.can_handle(found)
    await run(module, found, FakeSession({r"instagram\.com/janedoe84": FakeResponse(200, IG)}))
    assert found.metadata["public_page"] == "found" and found.metadata["avatar_hash"] == "abababababababab"
    assert found.metadata["profile"]["avatar_url"].endswith("jane.jpg")
    assert "social_pages" in S.SEARCHES["username"]["modules"] and "social_pages" in S.SEARCHES["name"]["modules"]


# ---------------------------------------------------------------------------- Phase 109: profiles behind sign-in walls
LINKEDIN = {"data": {"lookupStatus": "found", "profile": {
    "fullName": "Jane Doe", "headline": "Logistics engineer", "summary": "Supply chains, Leeds.",
    "location": "Leeds, England, United Kingdom", "profilePictureUrl": "https://media.licdn.com/jane.jpg",
    "followerCount": 512, "currentPositions": [{"title": "Engineer", "organization": {"name": "Acme Logistics"}}],
    "positions": [{"title": "Engineer", "organizationName": "Acme Logistics"}, {"title": "Intern", "organization": {"name": "Beta Ltd"}}],
    "education": [{"schoolName": "University of Leeds"}]}}, "meta": {"creditsCharged": 5}}  # fmt: skip
X_FOUND = {"data": {"lookupStatus": "found", "profile": {"displayName": "Jane Doe", "handle": "janedoe84",
           "bio": "Nurse. Views mine.", "location": "Leeds", "website": "https://janedoe.dev",
           "avatarUrl": "https://pbs.twimg.com/jane.jpg", "metrics": {"followers": 90}}}}  # fmt: skip


@pytest.fixture
def socialfetch_key(monkeypatch):
    from argus.core.settings import get_settings

    monkeypatch.setenv("ARGUS_SOCIALFETCH_API_KEY", "sfk_test_key_123")
    monkeypatch.setenv("ARGUS_SOCIALFETCH_MAX_LOOKUPS", "3")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


async def _no_picture(session, url):
    return "1234123412341234" if url else None


async def test_a_walled_profile_is_read_through_the_viewing_service(socialfetch_key, monkeypatch):
    from argus.modules.identity import profile_viewer
    from argus.modules.identity.profile_viewer import ProfileViewerModule
    from tests.test_phone import SearchSession

    monkeypatch.setattr(profile_viewer, "fetch_fingerprint", _no_picture)
    assert ProfileViewerModule.is_configured()
    found = Entity.create(E.SOCIAL_PROFILE, "https://www.linkedin.com/in/jane-doe-123", depth=1, confidence=0.5,
                          metadata={"platform": "LinkedIn", "origin": "found by web search"})  # fmt: skip
    session = SearchSession(FakeResponse(200, LINKEDIN))
    session.routes = {r"api\.socialfetch\.dev/v2/linkedin/profiles": FakeResponse(200, LINKEDIN)}
    module = ProfileViewerModule()
    assert module.can_handle(found)
    await run(module, found, session)
    assert session.headers[0]["x-api-key"] == "sfk_test_key_123" and session.params[0] == {"handle": "jane-doe-123"}
    profile = found.metadata["profile"]
    assert profile["display_name"] == "Jane Doe" and profile["company"] == "Acme Logistics"
    assert profile["positions"] == ["Engineer at Acme Logistics", "Intern at Beta Ltd"]
    assert profile["education"] == ["University of Leeds"] and "Leeds" in profile["location"]
    assert found.confidence == 0.85 and found.metadata["avatar_hash"] == "1234123412341234"
    # Scored against the known details, the employer and town agree.
    known = S.clean_known({"names": ["Jane Doe"], "employer": "Acme Logistics", "city": "Leeds"})
    cand = S.from_graph(_graph([found]), {"kind": "name", "value": "Jane Doe"}, "inv")[0]
    assert any("employer" in r for r in S.score(cand, known)["agree"])


async def test_a_username_on_x_instagram_and_facebook_within_the_lookup_limit(socialfetch_key, monkeypatch):
    from argus.modules.identity import profile_viewer
    from argus.modules.identity.profile_viewer import ProfileViewerModule, target_of

    monkeypatch.setattr(profile_viewer, "fetch_fingerprint", _no_picture)
    session = FakeSession({
        r"api\.socialfetch\.dev/v1/twitter/profiles/janedoe84": FakeResponse(200, X_FOUND),
        r"api\.socialfetch\.dev/v2/instagram/profiles/janedoe84": FakeResponse(200, {"data": {"lookupStatus": "private"}}),
        r"api\.socialfetch\.dev/v1/facebook/profiles": FakeResponse(402, {"error": "insufficient_credits"}),
    })  # fmt: skip
    user = Entity.create(E.USERNAME, "janedoe84")
    entities, _ = await run(ProfileViewerModule(), user, session)
    assert [e.value for e in entities] == ["https://x.com/janedoe84"]
    assert entities[0].metadata["profile"]["website"] == "https://janedoe.dev"
    assert user.metadata["viewed_profiles"] == {"X": "found", "Instagram": "private", "Facebook": "no credits"}
    # Profile lookups only: never contact details, followers or stories.
    assert all(not re.search(r"/(email|phones|contact|followers|following|stories)", u) for u in session.requested)
    # The per-scan limit (3 here) stops further lookups.
    module = ProfileViewerModule()
    module.spent = 3
    entities, _ = await run(module, Entity.create(E.USERNAME, "someoneelse"), FakeSession({}))
    assert entities == [] and set(module.__dict__) >= {"spent"}
    assert target_of("https://www.linkedin.com/company/acme") is None and target_of("https://x.com/home") is None
    assert target_of("https://m.facebook.com/jane.doe.77") == (
        "Facebook",
        {"url": "https://www.facebook.com/jane.doe.77"},
    )


def test_without_a_key_it_is_off_and_never_brokered(monkeypatch):
    from argus.accounts import connect_client
    from argus.core.settings import get_settings
    from argus.modules.identity.profile_viewer import ProfileViewerModule

    monkeypatch.delenv("ARGUS_SOCIALFETCH_API_KEY", raising=False)
    monkeypatch.setenv("ARGUS_EDITION", "personal")
    monkeypatch.setenv("ARGUS_ACCOUNT_SERVER_URL", "https://accounts.example")
    get_settings.cache_clear()
    assert not ProfileViewerModule.is_configured() and connect_client.available("web_search")
    get_settings.cache_clear()


# ---------------------------------------------------------------------------- Snapchat and Telegram, in more depth
SNAP = """<html><head><meta property="og:title" content="Jane D on Snapchat">
<meta property="og:url" content="https://www.snapchat.com/@janedoe84">
<meta property="og:description" content="Jane D is on Snapchat!">
<meta property="og:image" content="https://www.snapchat.com/web-capture/www.snapchat.com/@janedoe84/preview/square.jpeg"></head>
<body><script id="__NEXT_DATA__" type="application/json">{"props": {"pageProps": {"userProfile": {"$case": "publicProfileInfo",
"publicProfileInfo": {"username": "janedoe84", "title": "Jane D", "bio": "Leeds | nurse", "websiteUrl": "janedoe.dev",
"profilePictureUrl": "https://cf-st.sc-cdn.net/jane.jpg", "subscriberCount": 1200, "address": ""}}}}}</script></body></html>"""
SNAP_TAGS_ONLY = SNAP.split("<body>")[0] + "</html>"
CHANNEL = """<div class="tgme_channel_info_counter"><span class="counter_value">1.2K</span> <span class="counter_type">subscribers</span></div>
<div class="tgme_widget_message_wrap js-widget_message_wrap"><div class="tgme_widget_message text_not_supported_wrap js-widget_message" data-post="janedoe84/7">
<div class="tgme_widget_message_text js-message_text" dir="auto">Night shift again. Follow me on <a href="https://www.instagram.com/janedoe84/">Insta</a>,
ask @leeds_nurses_uk<br/>and see <a href="https://t.me/othernews/5">this</a></div><time datetime="2026-11-20T22:15:00+00:00" class="time"></time></div></div>
<div class="tgme_widget_message_wrap js-widget_message_wrap"><div class="tgme_widget_message js-widget_message" data-post="othernews/5">
<div class="tgme_widget_message_text js-message_text" dir="auto">A forwarded post</div><time datetime="2026-11-21T10:00:00+00:00"></time></div></div>"""


def test_snapchat_profiles_come_from_the_page_data_not_its_filler():
    from argus.modules.identity.social_pages import read_page

    facts = read_page("Snapchat", "janedoe84", SNAP)
    assert facts == {"display_name": "Jane D", "bio": "Leeds | nurse", "website": "janedoe.dev", "location": "",
                     "avatar_url": "https://cf-st.sc-cdn.net/jane.jpg", "followers": 1200}  # fmt: skip
    # Without the page data: the name only; never the filler bio or the page screenshot as a picture.
    assert read_page("Snapchat", "janedoe84", SNAP_TAGS_ONLY) == {
        "display_name": "Jane D",
        "bio": "",
        "avatar_url": None,
    }
    assert read_page("Snapchat", "someoneelse", SNAP) is None


async def test_a_public_telegram_channel_gives_posts_links_and_mentions(monkeypatch):
    from argus.modules.identity import social_pages
    from argus.modules.identity.social_pages import SocialPagesModule, telegram_channel

    channel = telegram_channel(CHANNEL, "janedoe84")
    assert channel["subscribers"] == "1.2K" and len(channel["posts"]) == 1  # the forwarded post is not theirs
    post = channel["posts"][0]
    assert post["url"] == "https://t.me/janedoe84/7" and post["date"].startswith("2026-11-20T22:15")
    assert post["mentions"] == ["leeds_nurses_uk"] and "Night shift again." in post["text"]
    assert channel["post_hours_utc"] == {22: 1}

    async def fingerprint(session, url):
        return None

    monkeypatch.setattr(social_pages, "fetch_fingerprint", fingerprint)
    user = Entity.create(E.USERNAME, "janedoe84")
    session = FakeSession(
        {r"t\.me/s/janedoe84": FakeResponse(200, CHANNEL), r"t\.me/janedoe84$": FakeResponse(200, TG)}
    )
    entities, _ = await run(SocialPagesModule(), user, session)
    telegram = next(e for e in entities if e.value == "https://t.me/janedoe84")
    assert telegram.metadata["telegram_channel"]["subscribers"] == "1.2K"
    linked = [e for e in entities if e.metadata.get("origin") == "linked in their Telegram channel"]
    assert [e.value for e in linked] == ["https://www.instagram.com/janedoe84"]  # not the other channel


def test_telegram_is_searched_on_the_web_and_its_links_are_understood():
    from argus.modules.identity.web_mentions import social_profile, social_query

    assert "site:t.me" in social_query('"Jane Doe"')
    assert social_profile("https://t.me/s/janedoe84") == ("Telegram", "https://t.me/janedoe84")
    assert social_profile("https://t.me/janedoe84/12") == ("Telegram", "https://t.me/janedoe84")
    assert social_profile("https://t.me/+AbCdEf") is None and social_profile("https://t.me/joinchat/x") is None
