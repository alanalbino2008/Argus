"""The website crawler: robots.txt, staying on the site, and what a site publishes about its owner."""

from __future__ import annotations

import pytest

from argus.core.models import Entity, EntityType, RelationType
from argus.core.settings import get_settings
from argus.modules.discovery.site_crawler import RobotRules, SiteCrawlerModule, page_facts, social_account
from tests.test_modules_offline import FakeResponse, FakeSession, collect, values

WALLET = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"


def html(body: str, title: str = "Hope Relief") -> FakeResponse:
    return FakeResponse(200, f"<html><head><title>{title}</title></head><body>{body}</body></html>",
                        {"Content-Type": "text/html; charset=utf-8"})  # fmt: skip


@pytest.mark.parametrize("url, expected", [
    ("https://twitter.com/HopeRelief", ("X (Twitter)", "HopeRelief", "https://twitter.com/HopeRelief")),
    ("https://www.facebook.com/hope.relief/", ("Facebook", "hope.relief", "https://facebook.com/hope.relief")),
    ("https://www.linkedin.com/company/hope-relief", ("LinkedIn", "company/hope-relief", "https://linkedin.com/company/hope-relief")),
    ("https://m.youtube.com/@hoperelief", ("YouTube", "@hoperelief", "https://youtube.com/@hoperelief")),
    ("https://t.me/hoperelief_news", ("Telegram", "hoperelief_news", "https://t.me/hoperelief_news")),
    ("https://twitter.com/intent/tweet?text=hi", None),  # a share button, not an account
    ("https://www.facebook.com/sharer/sharer.php?u=x", None),
    ("https://www.instagram.com/p/Cx123/", None),  # a post
    ("https://example.org/twitter.com/x", None),
])  # fmt: skip
def test_links_to_social_accounts_are_recognised(url, expected):
    assert social_account(url) == expected


def test_robots_txt_is_obeyed():
    rules = RobotRules("""
User-agent: Googlebot
Disallow: /

User-agent: *
Disallow: /private/
Disallow: /*.php$
Allow: /private/press/
Sitemap: https://hope.test/sitemap-pages.xml
""")
    assert rules.allowed("/about") and not rules.allowed("/private/accounts")
    assert rules.allowed("/private/press/2024")  # the longer Allow wins
    assert not rules.allowed("/donate.php") and rules.allowed("/donate.php?x=1")
    assert rules.sitemaps == ["https://hope.test/sitemap-pages.xml"]
    assert not RobotRules("User-agent: Argus\nDisallow: /\n\nUser-agent: *\nDisallow:").allowed("/")  # rules for us
    assert RobotRules("").allowed("/anything")


def test_what_a_page_publishes():
    facts = page_facts(f"""<a href="mailto:info@hope.test">Write</a> Treasurer: jane [at] hope [dot] test
        Call <a href="tel:+44 20 7946 0000">us</a>. Or +1 202 555 0143. Bitcoin: {WALLET}
        <img src="logo@2x.png"> <script>gtag('config', 'G-ABC123XYZ9')</script> Press: press@other.example""")
    assert facts["emails"] == {"info@hope.test", "jane@hope.test", "press@other.example"}
    assert facts["phones"]["+442079460000"] == 0.8 and "+12025550143" in facts["phones"]
    assert [w.value for w in facts["wallets"]] == [WALLET]
    assert facts["trackers"] == {"G-ABC123XYZ9": "Google Analytics 4"}


@pytest.fixture
def crawl_settings(monkeypatch):
    monkeypatch.setenv("ARGUS_CRAWL_DELAY_SECONDS", "0")
    monkeypatch.setenv("ARGUS_CRAWL_MAX_PAGES", "10")
    get_settings.cache_clear()


def site() -> FakeSession:
    return FakeSession({
        r"^https://hope\.test/robots\.txt$": FakeResponse(200, "User-agent: *\nDisallow: /trustees-only/\n",
                                                          {"Content-Type": "text/plain"}),
        r"^https://hope\.test/sitemap\.xml$": FakeResponse(200, "<urlset><url><loc>https://hope.test/terms</loc></url>"
                                                                "</urlset>", {"Content-Type": "application/xml"}),
        r"^https://hope\.test/$": html('<a href="/about">About</a> <a href="/trustees-only/list">x</a> '
                                       '<a href="https://twitter.com/HopeRelief">X</a> '
                                       '<a href="https://www.facebook.com/sharer/sharer.php?u=1">share</a> '
                                       '<a href="https://news.example/story">press</a> <a href="/old-donate">Give</a> '
                                       '<a href="/logo.png">logo</a> <a href="javascript:alert(1)">x</a>'),
        r"^https://hope\.test/about$": html('Run by Jane Roe. <a href="/files/annual-report-2023.pdf">Report</a> '
                                            '<a href="mailto:jane.roe@gmail.com">Email</a> '
                                            '<a href="https://evil.example/">elsewhere</a>'),
        r"^https://hope\.test/old-donate$": FakeResponse(301, "", {"Location": "/donate"}),
        r"^https://hope\.test/donate$": html(f"Send Bitcoin to {WALLET}. <a href=\"tel:+447700900123\">Call</a>"),
        r"^https://hope\.test/terms$": html("Contact legal@hope.test. GTM-AB12CD3"),
    })  # fmt: skip


async def test_a_whole_site_is_read_within_its_bounds(crawl_settings):
    session = site()
    entity = Entity.create(EntityType.DOMAIN, "hope.test")
    entities, relations = await collect(SiteCrawlerModule(), entity, session)
    crawl = entity.metadata["crawl"]
    assert crawl["pages"] == 4 and crawl["blocked_by_robots"] == 1
    assert {p["url"] for p in crawl["page_list"]} == {"https://hope.test/", "https://hope.test/about",
                                                      "https://hope.test/donate", "https://hope.test/terms"}  # fmt: skip
    assert not any("trustees-only" in u or "evil.example" in u or "news.example" in u or u.endswith(".png")
                   for u in session.requested)  # robots.txt obeyed; other sites and images never fetched  # fmt: skip
    assert values(entities, EntityType.EMAIL) == ["jane.roe@gmail.com", "legal@hope.test"]
    gmail = next(e for e in entities if e.value == "jane.roe@gmail.com")
    assert gmail.metadata["found_on"] == "https://hope.test/about" and gmail.metadata["on_site_domain"] is False
    assert values(entities, EntityType.PHONE) == ["+447700900123"]
    assert values(entities, EntityType.CRYPTO_WALLET) == [WALLET]
    assert values(entities, EntityType.SOCIAL_PROFILE) == ["https://twitter.com/HopeRelief"]
    assert values(entities, EntityType.URL) == ["https://hope.test/files/annual-report-2023.pdf"]
    assert entity.metadata["tracking_ids"] == [{"id": "GTM-AB12CD3", "product": "Google Tag Manager"}]
    assert {s["site"] for s in entity.metadata["links_to_sites"]} == {"news.example", "evil.example"}
    assert not any(e.type == EntityType.DOMAIN for e in entities)  # other sites are named, never scanned
    assert any(r.type == RelationType.HAS_ACCOUNT for r in relations)


async def test_the_page_limit_is_respected(monkeypatch):
    monkeypatch.setenv("ARGUS_CRAWL_DELAY_SECONDS", "0")
    monkeypatch.setenv("ARGUS_CRAWL_MAX_PAGES", "2")
    get_settings.cache_clear()
    entity = Entity.create(EntityType.DOMAIN, "hope.test")
    await collect(SiteCrawlerModule(), entity, site())
    assert entity.metadata["crawl"]["pages"] == 2 and entity.metadata["crawl"]["limit_reached"] is True


def test_the_crawler_is_active_so_passive_and_anonymous_scans_skip_it():
    module = SiteCrawlerModule()
    assert module.active
    assert not module.can_handle(Entity.create(EntityType.DOMAIN, "impostor.test", metadata={"out_of_scope": True}))
    assert not module.can_handle(Entity.create(EntityType.DOMAIN, "far.test", depth=2))


def pdf(author: str) -> bytes:
    import io

    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    doc = canvas.Canvas(buf)
    doc.setAuthor(author)
    doc.drawString(72, 720, "Annual report")
    doc.save()
    return buf.getvalue()


async def test_documents_on_the_site_are_read_for_their_authors(crawl_settings):
    session = site()
    session.routes = {r"^https://hope\.test/files/annual-report-2023\.pdf$":
                      FakeResponse(200, pdf("Jane Roe"), {"Content-Type": "application/pdf"}), **session.routes}  # fmt: skip
    entity = Entity.create(EntityType.DOMAIN, "hope.test")
    entities, relations = await collect(SiteCrawlerModule(), entity, session)
    report = next(e for e in entities if e.type == EntityType.URL)
    assert report.metadata["document"]["authors"] == ["Jane Roe"]
    author = next(e for e in entities if e.type == EntityType.PERSON)
    assert author.value == "Jane Roe" and author.metadata["origin"] == "document metadata"
    assert any(r.label == "Document author" and r.target_id == author.id for r in relations)


def test_the_website_playbook_reports_what_the_site_publishes():
    from argus.core.graph import IntelligenceGraph
    from argus.intel import playbooks

    g = IntelligenceGraph("w")
    seed = Entity.create(EntityType.DOMAIN, "hope.test", metadata={
        "tracking_ids": [{"id": "G-ABC123XYZ9", "product": "Google Analytics 4"}],
        "crawl": {"pages": 3, "page_list": [{"url": "https://hope.test/", "title": "Home"},
                                            {"url": "https://hope.test/about-us", "title": "About"},
                                            {"url": "https://hope.test/shop", "title": "Shop"}]}})  # fmt: skip
    gmail = Entity.create(EntityType.EMAIL, "jane.roe@gmail.com", depth=1, metadata={
        "origin": "published on website", "found_on": "https://hope.test/about-us", "on_site_domain": False})  # fmt: skip
    own = Entity.create(EntityType.EMAIL, "info@hope.test", depth=1, metadata={
        "origin": "published on website", "on_site_domain": True})  # fmt: skip
    wallet = Entity.create(EntityType.CRYPTO_WALLET, WALLET, depth=1, metadata={"origin": "published on website"})
    report = Entity.create(EntityType.URL, "https://hope.test/r.pdf", label="r.pdf", depth=1, metadata={
        "origin": "published on website", "category": "document",
        "document": {"authors": ["Jane Roe"], "company": "Roe Holdings"}})  # fmt: skip
    for e in (seed, gmail, own, wallet, report):
        g.add_entity(e, is_seed=e.depth == 0)
    found = {h.title: h for h in playbooks.highlights(g)}
    outside = found["Email published on the website: jane.roe@gmail.com"]
    assert outside.level == "medium" and "personal or outside address" in outside.detail and outside.as_dict()["tick"]
    assert found["Email published on the website: info@hope.test"].level == "info"
    assert found[f"Wallet published on the website: {WALLET}"].level == "medium"
    assert found["Document offered: r.pdf"].detail == "written by Jane Roe; for Roe Holdings"
    assert "Google Analytics 4 ID on hope.test: G-ABC123XYZ9" in found
    assert playbooks.capture_urls(g, ("website", "contacts"), "hope.test", 4) == [
        "https://hope.test/",
        "https://hope.test/about-us",
    ]
