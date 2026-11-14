"""People & software intelligence: profile enrichment, lifecycle and CVE intel (no network)."""

from __future__ import annotations

from datetime import date

from argus.core.models import Entity, EntityType, RelationType
from argus.modules.base import BaseModule
from argus.modules.identity.profile_enricher import ProfileEnricherModule, _is_real_name, strip_html
from argus.modules.infrastructure.software_intel import SoftwareIntelModule, match_cycle, parse_software
from tests.test_engine import FanOutModule, make_engine
from tests.test_modules_offline import FakeResponse, FakeSession, collect, values


def profile(platform: str, handle: str, url: str | None = None) -> Entity:
    return Entity.create(
        EntityType.SOCIAL_PROFILE,
        url or f"https://example.test/{handle}",
        metadata={"platform": platform, "username": handle},
        depth=2,
    )


# ----------------------------------------------------------------------------- profiles
async def test_keybase_verified_proofs_become_linked_identities():
    session = FakeSession(
        {
            r"keybase\.io/_/api": FakeResponse(
                200,
                {
                    "them": [
                        {
                            "profile": {
                                "full_name": "Dana Whitfield",
                                "bio": "Reach me: dana@mail.example",
                                "location": "Leeds, UK",
                            },
                            "proofs_summary": {
                                "all": [
                                    {"proof_type": "github", "nametag": "dwhit"},
                                    {
                                        "proof_type": "dns",
                                        "nametag": "dana.example",
                                        "service_url": "https://dana.example",
                                    },
                                ]
                            },
                        }
                    ]
                },
            )
        }
    )
    entity = profile("Keybase", "dana")
    entities, relations = await collect(ProfileEnricherModule(), entity, session)

    assert entity.metadata["profile"]["location"] == "Leeds, UK"
    assert values(entities, EntityType.PERSON) == ["Dana Whitfield"]
    assert values(entities, EntityType.LOCATION) == ["Leeds, UK"]
    assert values(entities, EntityType.EMAIL) == ["dana@mail.example"]
    assert values(entities, EntityType.DOMAIN) == ["dana.example"]
    assert values(entities, EntityType.SOCIAL_PROFILE) == ["https://github.com/dwhit"]
    assert values(entities, EntityType.USERNAME) == ["dwhit"]  # verified -> worth hunting
    gh = next(e for e in entities if e.type == EntityType.SOCIAL_PROFILE)
    assert gh.confidence == 0.95 and gh.metadata["verified"] is True
    assert all(e.depth == 3 for e in entities)
    assert any(r.type == RelationType.LOCATED_IN for r in relations)


async def test_mastodon_distinguishes_verified_and_claimed_links():
    session = FakeSession(
        {
            r"mastodon\.social/api": FakeResponse(
                200,
                {
                    "display_name": "dana",
                    "note": "<p>Security &amp; coffee</p>",
                    "created_at": "2022-11-02T00:00:00Z",
                    "followers_count": 12,
                    "fields": [
                        {
                            "name": "Web",
                            "value": '<a href="https://blog.example">https://blog.example</a>',
                            "verified_at": "2023-01-01",
                        },
                        {"name": "GitHub", "value": "https://github.com/dwhit", "verified_at": None},
                    ],
                },
            )
        }
    )
    entity = profile("Mastodon.social", "dana")
    entities, _ = await collect(ProfileEnricherModule(), entity, session)
    assert entity.metadata["profile"]["bio"] == "Security & coffee"
    assert values(entities, EntityType.PERSON) == []  # "dana" is just the handle
    assert values(entities, EntityType.DOMAIN) == ["blog.example"]
    gh = next(e for e in entities if e.type == EntityType.SOCIAL_PROFILE)
    assert gh.metadata["verified"] is False and gh.confidence == 0.6
    assert values(entities, EntityType.USERNAME) == []  # claimed links are not proof of identity


async def test_gitlab_profile_two_step_lookup():
    session = FakeSession(
        {
            r"api/v4/users\?username=": FakeResponse(200, [{"id": 42}]),
            r"api/v4/users/42": FakeResponse(
                200,
                {
                    "name": "Dana Whitfield",
                    "organization": "Acme Corp",
                    "website_url": "https://gitlab.com/dana",  # platform host: not a personal domain
                    "public_email": "Dana@Acme.example",
                    "twitter": "danaw",
                },
            ),
        }
    )
    entities, _ = await collect(ProfileEnricherModule(), profile("GitLab", "dana"), session)
    assert values(entities, EntityType.ORGANIZATION) == ["Acme Corp"]
    assert values(entities, EntityType.EMAIL) == ["dana@acme.example"]
    assert values(entities, EntityType.DOMAIN) == []
    assert values(entities, EntityType.SOCIAL_PROFILE) == ["https://twitter.com/danaw"]


async def test_reddit_hackernews_devto_dockerhub_bluesky():
    session = FakeSession(
        {
            r"reddit\.com/user/dana/about": FakeResponse(
                200, {"data": {"created_utc": 1600000000, "total_karma": 5, "subreddit": {"title": "Dana W"}}}
            ),
            r"hacker-news": FakeResponse(
                200, {"about": "see https://dana.example.", "created": 1500000000, "karma": 9}
            ),
            r"dev\.to/api": FakeResponse(
                200, {"name": "Dana Whitfield", "github_username": "dwhit", "location": "Leeds"}
            ),
            r"hub\.docker\.com": FakeResponse(200, {"full_name": "Dana Whitfield", "company": "Acme Corp"}),
            r"bsky": FakeResponse(200, {"displayName": "Dana Whitfield", "followersCount": 3}),
        }
    )
    mod = ProfileEnricherModule()
    reddit = profile("Reddit", "dana")
    await collect(mod, reddit, session)
    assert reddit.metadata["profile"]["created_at"].startswith("2020-09-13")

    hn_entities, _ = await collect(mod, profile("HackerNews", "dana"), session)
    assert values(hn_entities, EntityType.DOMAIN) == ["dana.example"]

    dev_entities, _ = await collect(mod, profile("Dev.to", "dana"), session)
    assert values(dev_entities, EntityType.SOCIAL_PROFILE) == ["https://github.com/dwhit"]
    assert values(dev_entities, EntityType.LOCATION) == ["Leeds"]

    docker_entities, _ = await collect(mod, profile("DockerHub", "dana"), session)
    assert values(docker_entities, EntityType.ORGANIZATION) == ["Acme Corp"]

    bsky = profile("Bluesky", "dana")
    await collect(mod, bsky, session)
    assert bsky.metadata["profile"]["followers"] == 3
    assert any("dana.bsky.social" in u for u in session.requested)


async def test_missing_profile_yields_nothing_and_unknown_platform_is_skipped():
    mod = ProfileEnricherModule()
    entity = profile("Keybase", "ghost")
    assert await collect(mod, entity, FakeSession({})) == ([], [])
    assert "profile" not in entity.metadata
    assert not mod.can_handle(profile("Instagram", "dana"))


def test_name_and_html_helpers():
    assert _is_real_name("Dana Whitfield", "dana")
    assert not _is_real_name("dana", "dana")
    assert not _is_real_name("l33t h4x0r", "x")
    assert strip_html("<b>a</b> &amp; b") == "a  & b"


# ----------------------------------------------------------------------------- software
def test_parse_software_from_banners():
    assert parse_software("PHP/7.4.3") == ("php", "7.4.3")
    assert parse_software("Apache/2.4.49 (Ubuntu)") == ("apache-http-server", "2.4.49")
    assert parse_software("nginx 1.18.0") == ("nginx", "1.18.0")
    assert parse_software("Cloudflare") is None


CYCLES = [
    {"cycle": "8.3", "eol": "2027-12-31", "latest": "8.3.14"},
    {"cycle": "7.4", "eol": "2022-11-28", "latest": "7.4.33"},
    {"cycle": "1", "eol": True, "latest": "1.9"},
]


def test_match_cycle_reports_eol_and_outdated():
    info = match_cycle(CYCLES, "7.4.3", today=date(2026, 1, 1))
    assert info == {
        "version": "7.4.3",
        "cycle": "7.4",
        "eol": True,
        "eol_date": "2022-11-28",
        "latest": "7.4.33",
        "outdated": True,
    }
    current = match_cycle(CYCLES, "8.3.14", today=date(2026, 1, 1))
    assert current is not None and current["eol"] is False and current["outdated"] is False
    boolean = match_cycle(CYCLES, "1.2", today=date(2026, 1, 1))
    assert boolean is not None and boolean["eol"] is True and boolean["eol_date"] is None
    assert match_cycle(CYCLES, "5.6") is None


async def test_lifecycle_enriches_technology_and_port_and_caches_lookups():
    session = FakeSession({r"endoflife\.date/api/php\.json": FakeResponse(200, CYCLES)})
    mod = SoftwareIntelModule()
    tech = Entity.create(EntityType.TECHNOLOGY, "PHP/7.4.3")
    port = Entity.create(EntityType.PORT, "192.0.2.10:80", metadata={"product": "PHP", "version": "7.4.3"})
    assert mod.can_handle(tech) and mod.can_handle(port)
    for e in (tech, port):
        assert await collect(mod, e, session) == ([], [])  # enrichment only, no new nodes
        assert e.metadata["lifecycle"]["product"] == "php"
        assert e.metadata["lifecycle"]["eol"] is True
    assert sum("endoflife" in u for u in session.requested) == 1
    assert not mod.can_handle(Entity.create(EntityType.TECHNOLOGY, "Cloudflare"))


async def test_cve_intel_combines_kev_epss_and_nvd():
    session = FakeSession(
        {
            r"known_exploited": FakeResponse(
                200,
                {
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2024-21762",
                            "dateAdded": "2024-02-09",
                            "dueDate": "2024-02-16",
                            "knownRansomwareCampaignUse": "Known",
                            "vendorProject": "Fortinet",
                            "product": "FortiOS",
                            "vulnerabilityName": "Fortinet FortiOS Out-of-Bound Write",
                            "requiredAction": "Apply mitigations",
                        }
                    ]
                },
            ),
            r"api\.first\.org": FakeResponse(200, {"data": [{"epss": "0.94321", "percentile": "0.9991"}]}),
            r"nvd\.nist\.gov": FakeResponse(
                200,
                {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "metrics": {
                                    "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
                                },
                                "descriptions": [{"lang": "en", "value": "An out-of-bounds write."}],
                            }
                        }
                    ]
                },
            ),
        }
    )
    mod = SoftwareIntelModule()
    kev_cve = Entity.create(EntityType.VULNERABILITY, "cve-2024-21762")
    other = Entity.create(EntityType.VULNERABILITY, "CVE-2020-0001")
    await collect(mod, kev_cve, session)
    await collect(mod, other, session)

    intel = kev_cve.metadata["intel"]
    assert intel["kev"]["ransomware"] is True and intel["kev"]["product"] == "Fortinet FortiOS"
    assert intel["epss"] == 0.9432 and intel["cvss_score"] == 9.8 and intel["cvss_severity"] == "CRITICAL"
    assert intel["description"] == "An out-of-bounds write."
    assert other.metadata["intel"]["kev"] is None
    assert sum("known_exploited" in u for u in session.requested) == 1  # catalog downloaded once
    assert not mod.can_handle(Entity.create(EntityType.VULNERABILITY, "GHSA-xxxx"))


async def test_kev_outage_is_reported_not_fatal():
    mod = SoftwareIntelModule()
    cve = Entity.create(EntityType.VULNERABILITY, "CVE-2024-0001")
    await collect(mod, cve, FakeSession({r"known_exploited": FakeResponse(503, "down")}))
    assert cve.metadata["intel"]["kev"] is None


# ----------------------------------------------------------------------------- engine
class Enricher(BaseModule):
    name = "enricher"
    supported_entity_types = [EntityType.SUBDOMAIN]
    enrichment = True

    def __init__(self):
        self.seen: list[str] = []

    async def run(self, entity, session, config):
        self.seen.append(entity.value)
        entity.metadata["enriched"] = True
        return
        yield  # pragma: no cover


async def test_enrichers_run_on_leaf_entities_but_do_not_expand_them():
    fan, enricher = FanOutModule(fan=2), Enricher()
    engine = make_engine([fan, enricher], max_depth=1)
    graph = await engine.start()
    assert graph.node_count == 3
    assert len(fan.calls) == 1  # only the seed is expanded
    assert sorted(enricher.seen) == ["n0.example.com", "n1.example.com"]
    assert all(e.metadata.get("enriched") for e in graph.get_all_entities() if e.depth == 1)


def test_analyzer_flags_kev_first_and_end_of_life_software():
    from argus.core.graph import IntelligenceGraph
    from argus.modules.analytics.graph_analyzer import GraphIntelligenceAnalyzer

    g = IntelligenceGraph("t")
    g.add_entity(Entity.create(EntityType.DOMAIN, "acme.example", depth=0), is_seed=True)
    g.add_entity(Entity.create(EntityType.VULNERABILITY, "CVE-2019-0001", depth=1))
    g.add_entity(
        Entity.create(
            EntityType.VULNERABILITY, "CVE-2024-21762", depth=1, metadata={"intel": {"kev": {"ransomware": True}}}
        )
    )
    g.add_entity(
        Entity.create(
            EntityType.TECHNOLOGY,
            "PHP/7.4.3",
            depth=1,
            metadata={"lifecycle": {"eol": True, "eol_date": "2022-11-28", "product": "php", "version": "7.4.3"}},
        )
    )
    flags = GraphIntelligenceAnalyzer.analyze(g)["risk_flags"]
    assert flags[0] == "Actively exploited CVE (CISA KEV, used by ransomware): CVE-2024-21762"
    assert "End-of-life software since 2022-11-28: php 7.4.3" in flags
