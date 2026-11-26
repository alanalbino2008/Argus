"""Deeper sources about a person: the same picture, deleted accounts, old pages, documents, records."""

from __future__ import annotations

import io
import zipfile

import pytest

from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType, ScanConfig
from argus.intel import subjects as S
from argus.modules.identity.deep_person import (
    ArchivedAccountsModule,
    PersonDocumentsModule,
    ReverseImageModule,
    SiteHistoryModule,
    document_text,
)
from tests.test_modules_offline import FakeResponse, FakeSession, values

E = EntityType
KNOWN = S.clean_known({"names": ["Jane Doe"], "city": "Leeds", "birth_year": 1984})


async def run(module, entity, session, **config):
    cfg = ScanConfig(target=entity.value, target_type=entity.type, **config)
    items = [x async for x in module.run(entity, session, cfg)]
    return [x for x in items if isinstance(x, Entity)], [x for x in items if not isinstance(x, Entity)]


def scored(entities, search=None):
    g = IntelligenceGraph("t")
    for e in entities:
        g.add_entity(e)
    cands = S.from_graph(g, search or {"kind": "name", "value": "Jane Doe"}, "inv")
    for c in cands:
        c.update(S.score(c, KNOWN))
    return {c["value"]: c for c in cands}


# ---------------------------------------------------------------------------- 1. the same picture elsewhere
async def test_a_confirmed_picture_is_searched_and_its_matches_become_candidates(monkeypatch):
    from argus.core.settings import get_settings

    monkeypatch.setenv("ARGUS_TINEYE_API_KEY", "tineye-key-123")
    get_settings.cache_clear()
    picture = Entity.create(E.URL, "https://scontent.cdninstagram.com/jane.jpg")
    answer = {"results": {"matches": [
        {"domain": "twitter.com", "backlinks": [{"backlink": "https://twitter.com/janesmith_old", "crawl_date": "2019-03-01"}]},
        {"domain": "leedsnurses.org", "backlinks": [{"backlink": "https://leedsnurses.org/team", "crawl_date": "2021-05-02"}]},
    ]}}  # fmt: skip
    session = FakeSession({r"api\.tineye\.com": FakeResponse(200, answer)})
    assert ReverseImageModule.is_configured()
    entities, _ = await run(ReverseImageModule(), picture, session)
    assert entities == [] and session.requested == []  # never for an ordinary URL scan
    entities, _ = await run(ReverseImageModule(), picture, session, hints={"image_search": True})
    assert values(entities, E.SOCIAL_PROFILE) == ["https://x.com/janesmith_old"]
    assert values(entities, E.URL) == ["https://leedsnurses.org/team"]
    found = scored(entities)
    x = found["https://x.com/janesmith_old"]
    assert "uses the same picture (reverse image search)" in x["agree"] and x["grade"] == "strong"
    assert found["https://leedsnurses.org/team"]["kind"] == "page"
    # Confirmed profiles' pictures become known, and are searched.
    known = S.add_to_known(KNOWN, {"kind": "profile", "value": "https://www.instagram.com/janedoe84",
                                   "facts": {"avatar_url": "https://scontent.cdninstagram.com/jane.jpg"}})  # fmt: skip
    assert known["photo_urls"] == ["https://scontent.cdninstagram.com/jane.jpg"]
    assert ("photo", "https://scontent.cdninstagram.com/jane.jpg") in [
        (x["kind"], x["value"]) for x in S.searches(known, set())
    ]
    assert S.SEARCHES["photo"]["hints"] == {"image_search": True}
    get_settings.cache_clear()


# ---------------------------------------------------------------------------- 2. deleted and renamed accounts
async def test_archived_profiles_of_a_username_are_found():
    user = Entity.create(E.USERNAME, "janedoe84")
    session = FakeSession({
        r"cdx\?url=twitter\.com%2Fjanedoe84&": FakeResponse(200, [["timestamp", "statuscode"], ["20140301000000", "200"],
                                                                  ["20170601000000", "200"]]),
        r"cdx\?url=janedoe84\.tumblr\.com": FakeResponse(200, [["timestamp", "statuscode"], ["20120101000000", "200"]]),
        r"cdx\?url=instagram\.com": FakeResponse(200, [["timestamp", "statuscode"]]),
    })  # fmt: skip
    entities, _ = await run(ArchivedAccountsModule(), user, session)
    assert values(entities, E.SOCIAL_PROFILE) == ["https://janedoe84.tumblr.com", "https://x.com/janedoe84"]
    assert user.metadata["archived_accounts"]["X"] == {
        "first": "2014-03", "last": "2017-06", "months": 2,
        "archive_url": "https://web.archive.org/web/20170601000000/twitter.com/janedoe84"}  # fmt: skip
    assert all("web.archive.org" in u for u in session.requested)
    cand = scored(entities, {"kind": "username", "value": "janedoe84"})["https://x.com/janedoe84"]
    assert cand["grade"] == "possible" and cand["facts"]["archived"]["first"] == "2014-03"
    assert "archived_accounts" in S.SEARCHES["username"]["modules"]


# ---------------------------------------------------------------------------- 3. a personal website's old pages
ABOUT = b"""<html><body><h1>About Jane</h1><p>Nurse in Leeds. Write to jane.doe@leedsnurses.org or
<a href="https://web.archive.org/web/2016/https://www.instagram.com/janesmith_/">Instagram</a>,
<a href="https://www.linkedin.com/in/jane-smith-leeds">LinkedIn</a></p></body></html>"""


async def test_old_about_pages_of_their_website():
    site = Entity.create(E.DOMAIN, "janedoe.dev")
    session = FakeSession({
        r"cdx\?url=janedoe\.dev/\*": FakeResponse(200, [["original", "timestamp"],
            ["http://janedoe.dev/about/", "20160101000000"], ["http://janedoe.dev/blog/post-1", "20160102000000"],
            ["http://janedoe.dev/cv.html", "20150101000000"]]),
        r"web/20160101000000id_/http://janedoe\.dev/about/": FakeResponse(200, ABOUT.decode()),
        r"web/20150101000000id_/": FakeResponse(200, "<p>CV: 2010-2014 St James's Hospital</p>"),
    })  # fmt: skip
    entities, _ = await run(SiteHistoryModule(), site, session)
    assert values(entities, E.EMAIL) == ["jane.doe@leedsnurses.org"]
    assert values(entities, E.SOCIAL_PROFILE) == ["https://www.instagram.com/janesmith_",
                                                  "https://www.linkedin.com/in/jane-smith-leeds"]  # fmt: skip
    assert {p["page"] for p in site.metadata["site_history"]} == {"about", "cv"}
    assert not any("blog" in u for u in session.requested)
    modules = S.SEARCHES["website"]["modules"]
    assert "site_history" in modules and "infrastructure_pivot" in modules


# ---------------------------------------------------------------------------- 4. documents
def _docx(text: str, creator: str = "Jane Doe", company: str = "St James's Hospital") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("docProps/core.xml", '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/'
                   'metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/'
                   f'dc/terms/"><dc:creator>{creator}</dc:creator><dcterms:created>2019-02-01T10:00:00Z</dcterms:created>'
                   "</cp:coreProperties>")  # fmt: skip
        z.writestr("docProps/app.xml", '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/'
                   f'extended-properties"><Company>{company}</Company></Properties>')  # fmt: skip
        z.writestr("word/document.xml", '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/'
                   f'main"><w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>')  # fmt: skip
    return buf.getvalue()


async def test_a_cv_found_by_web_search_is_read():
    doc = Entity.create(E.URL, "https://cvs.example.org/jane-doe-cv.docx", depth=1,
                        metadata={"category": "mention", "snippet": "Jane Doe, nurse, Leeds"})  # fmt: skip
    module = PersonDocumentsModule()
    assert module.can_handle(doc) and not module.can_handle(Entity.create(E.URL, "https://a.example/page", depth=1,
                                                                            metadata={"category": "mention"}))  # fmt: skip
    data = _docx("Jane Doe, Leeds. jane.doe84@gmail.com https://www.instagram.com/janedoe84")
    archived = FakeSession({
        r"archive\.org/wayback/available": FakeResponse(200, {"archived_snapshots": {"closest": {"available": True,
                                                                                               "timestamp": "20200101"}}}),
        r"web/20200101id_/": FakeResponse(200, data),
    })  # fmt: skip
    entities, _ = await run(module, doc, archived)
    info = doc.metadata["document"]
    assert info["read"] and info["from"] == "the Internet Archive's copy" and info["authors"] == ["Jane Doe"]
    assert info["company"] == "St James's Hospital" and info["emails"] == ["jane.doe84@gmail.com"]
    assert values(entities, E.EMAIL) == ["jane.doe84@gmail.com"]
    assert not any("cvs.example.org" in u and "archive" not in u for u in archived.requested)
    cand = scored([doc])["https://cvs.example.org/jane-doe-cv.docx"]
    assert cand["kind"] == "page" and "the same name (Jane Doe)" in cand["agree"]
    assert "mentions the known town (Leeds)" in cand["agree"]
    # Not archived: an anonymous case never fetches it from the site.
    unarchived = FakeSession({r"archive\.org/wayback/available": FakeResponse(200, {"archived_snapshots": {}})})
    other = Entity.create(E.URL, "https://cvs.example.org/x.pdf", depth=1, metadata={"category": "mention"})
    await run(module, other, unarchived, passive_only=True)
    assert other.metadata["document"]["read"] is False and len(unarchived.requested) == 1
    assert b"jane.doe84@gmail.com" in document_text(data)


# ---------------------------------------------------------------------------- 5. records in their name
def test_insolvency_notices_and_court_cases_become_records_to_check():
    person = Entity.create(E.PERSON, "Jane Doe", metadata={
        "insolvency_notices": [{"type": "Bankruptcy orders", "about": "Jane Doe, of Leeds, nurse", "date": "2020-01-02",
                                "url": "https://www.thegazette.co.uk/notice/1"}],
        "court_cases": [{"name": "Doe v. Acme Corp", "court": "nysd", "filed": "2018-05-01",
                         "url": "https://www.courtlistener.com/docket/1/"}]})  # fmt: skip
    found = scored([person])
    notice = found["https://www.thegazette.co.uk/notice/1"]
    assert notice["kind"] == "record" and notice["label"].startswith("Insolvency notice: Jane Doe, of Leeds")
    assert "mentions the known town (Leeds)" in notice["agree"] and notice["verdict"] in ("possible", "likely")
    court = found["https://www.courtlistener.com/docket/1/"]
    assert court["label"] == "Court case: Doe v. Acme Corp (2018-05-01)" and court["grade"] == "possible"
    assert {"gazette_insolvency", "court_records"} <= set(S.SEARCHES["name"]["modules"])
    assert S.CASE_ITEM_TYPES["record"] == "document"


@pytest.mark.parametrize("module", ["reverse_image", "archived_accounts", "site_history", "person_documents"])
def test_the_new_sources_are_registered(module):
    from argus.modules import get_module_catalog

    assert module in get_module_catalog()
