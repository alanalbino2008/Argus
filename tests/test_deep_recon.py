"""Phase 10 collectors against realistic recorded-style responses (no network)."""

from __future__ import annotations

import io
import zipfile
import zlib

from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType, RelationType, ScanConfig
from argus.core.settings import get_settings
from argus.modules.discovery import cloud_storage, document_metadata, wayback
from argus.modules.discovery.cloud_storage import CloudStorageModule
from argus.modules.discovery.code_leaks import CodeLeaksModule, find_secrets
from argus.modules.discovery.document_metadata import DocumentMetadataModule, classify_author, parse_document
from argus.modules.discovery.passive_dns import PassiveDnsModule
from argus.modules.discovery.wayback import WaybackModule
from argus.modules.discovery.web_recon import WebReconModule, extract_contacts, normalise_phone
from argus.modules.identity.github_org import GitHubOrgModule, org_matches
from argus.modules.identity.pgp_keyserver import PgpKeyserverModule, parse_index
from tests.test_modules_offline import FakeResponse, FakeSession, collect, values

E = EntityType


def domain(value="acme.example", depth=0):
    return Entity.create(E.DOMAIN, value, depth=depth)


# ----------------------------------------------------------------------------- Wayback
async def test_wayback_finds_subdomains_sensitive_files_and_redacts_credentials():
    rows = [
        ["original", "timestamp", "statuscode", "mimetype"],
        ["https://acme.example/.env", "20210304000000", "200", "text/plain"],
        ["https://legacy.acme.example/admin/", "20190101000000", "200", "text/html"],
        ["https://acme.example/files/annual-report.pdf", "20220101000000", "200", "application/pdf"],
        ["https://api.acme.example/swagger.json", "20230101000000", "200", "application/json"],
        ["https://acme.example/login?user=a&token=s3cr3tvalue", "20200101000000", "200", "text/html"],
        ["https://www.acme.example/", "20200101000000", "200", "text/html"],
        ["https://evil.example/acme.example", "20200101000000", "200", "text/html"],
    ]
    seed = domain()
    entities, relations = await collect(
        WaybackModule(), seed, FakeSession({r"web\.archive\.org/cdx": FakeResponse(200, rows)})
    )
    assert values(entities, E.SUBDOMAIN) == ["api.acme.example", "legacy.acme.example"]
    urls = {e.metadata["category"]: e for e in entities if e.type == E.URL}
    assert set(urls) == {"sensitive_file", "admin_panel", "document", "api", "credential_in_url"}
    assert "s3cr3tvalue" not in urls["credential_in_url"].value and "REDACTED" in urls["credential_in_url"].value
    assert (
        urls["sensitive_file"].metadata["archive_url"]
        == "https://web.archive.org/web/20210304000000/https://acme.example/.env"
    )
    assert seed.metadata["wayback"]["first_archived"] == "2019-01-01"
    assert any(r.type == RelationType.EXPOSES for r in relations)
    assert wayback.classify("https://a.example/blog/post") is None


# ----------------------------------------------------------------------------- documents
def make_docx(
    creator="jsmith", modified_by="Jane Smith", app="Microsoft Office Word", version="16.0000", company="Acme Corp"
):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(
            "docProps/core.xml",
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">'
            f"<dc:creator>{creator}</dc:creator><cp:lastModifiedBy>{modified_by}</cp:lastModifiedBy>"
            "<dcterms:created>2021-05-04T10:00:00Z</dcterms:created></cp:coreProperties>",
        )
        z.writestr(
            "docProps/app.xml",
            '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
            f"<Application>{app}</Application><AppVersion>{version}</AppVersion><Company>{company}</Company></Properties>",
        )
    return buf.getvalue()


def test_office_and_pdf_metadata_parsing():
    facts = parse_document(make_docx())
    assert facts["authors"] == ["jsmith", "Jane Smith"]
    assert facts["software"] == ["Microsoft Office Word 2016+"] and facts["company"] == "Acme Corp"

    info = b"<< /Author (Jane Smith) /Producer (Adobe PDF Library 15.0) /CreationDate (D:20200102030405Z) >>"
    compressed = zlib.compress(b"<< /Creator (Microsoft\\256 Word 2019) >>")
    pdf = b"%PDF-1.7\n" + info + b"\n1 0 obj\nstream\n" + compressed + b"\nendstream\n"
    facts = parse_document(pdf)
    assert facts["authors"] == ["Jane Smith"] and facts["created"] == "2020-01-02"
    assert "Adobe PDF Library 15.0" in facts["software"] and any("Word 2019" in s for s in facts["software"])

    utf16 = b"%PDF-1.4\n/Author <FEFF004A006F> "
    assert parse_document(utf16)["authors"] == ["Jo"]
    assert parse_document(b"not a document") == {}


def test_hostile_documents_are_rejected():
    bomb = io.BytesIO()
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("docProps/core.xml", "<a>" + "x" * 2_000_000 + "</a>")
    assert parse_document(bomb.getvalue()) == {}
    xxe = io.BytesIO()
    with zipfile.ZipFile(xxe, "w") as z:
        z.writestr("docProps/core.xml", '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>')
    assert parse_document(xxe.getvalue()) == {}


def test_author_classification():
    assert classify_author("Jane Smith") == E.PERSON
    assert classify_author("jsmith") == E.USERNAME
    assert classify_author("Administrator") is None and classify_author("jane@acme.example") is None


async def test_document_module_reads_archived_copy_and_emits_people_and_software():
    doc = Entity.create(
        E.URL,
        "https://acme.example/files/plan.docx",
        metadata={
            "category": "document",
            "archive_url": "https://web.archive.org/web/20220101000000/https://acme.example/files/plan.docx",
        },
        depth=2,
    )
    session = FakeSession({r"web/20220101000000id_/": FakeResponse(200, make_docx())})
    entities, _ = await collect(DocumentMetadataModule(), doc, session)
    assert values(entities, E.USERNAME) == ["jsmith"] and values(entities, E.PERSON) == ["Jane Smith"]
    assert values(entities, E.TECHNOLOGY) == ["Microsoft Office Word 2016+"]
    assert values(entities, E.ORGANIZATION) == ["Acme Corp"]
    assert doc.metadata["document"]["company"] == "Acme Corp"
    assert all(u.startswith("https://web.archive.org/") for u in session.requested)  # never the target itself
    assert not DocumentMetadataModule().can_handle(
        Entity.create(E.URL, "https://a.example/x", metadata={"category": "api"})
    )
    assert document_metadata.MAX_DOCUMENT >= 10_000_000


# ----------------------------------------------------------------------------- passive DNS
async def test_passive_dns_merges_sources_and_reports_failures():
    session = FakeSession(
        {
            r"hackertarget": FakeResponse(200, "vpn.acme.example,203.0.113.5\nmail.acme.example,203.0.113.6"),
            r"otx\.alienvault": FakeResponse(
                200, {"passive_dns": [{"hostname": "vpn.acme.example"}, {"hostname": "x.other.example"}]}
            ),
            r"jldc\.me": FakeResponse(200, ["*.dev.acme.example", "VPN.acme.example."]),
            r"certspotter": FakeResponse(500, "boom"),
            r"urlscan": FakeResponse(
                200, {"results": [{"page": {"domain": "shop.acme.example"}, "task": {"domain": "acme.example"}}]}
            ),
        }
    )
    mod = PassiveDnsModule()
    seed = domain()
    entities, _ = await collect(mod, seed, session)
    assert values(entities, E.SUBDOMAIN) == [
        "dev.acme.example",
        "mail.acme.example",
        "shop.acme.example",
        "vpn.acme.example",
    ]
    vpn = next(e for e in entities if e.value == "vpn.acme.example")
    assert vpn.metadata["passive_sources"] == ["alienvault-otx", "anubis", "hackertarget"] and vpn.confidence == 0.85
    assert "certspotter" not in seed.metadata["passive_dns"]["sources_answered"]


# ----------------------------------------------------------------------------- GitHub org & code
async def test_github_org_is_used_only_when_it_points_back_to_the_domain():
    session = FakeSession(
        {
            r"search/users": FakeResponse(200, {"items": [{"login": "acme-fake"}, {"login": "acme-corp"}]}),
            r"orgs/acme-fake$": FakeResponse(200, {"login": "acme-fake", "blog": "https://not-acme.example"}),
            r"orgs/acme-corp$": FakeResponse(
                200, {"login": "acme-corp", "blog": "www.acme.example", "is_verified": True, "name": "Acme"}
            ),
            r"orgs/acme-corp/public_members": FakeResponse(200, [{"login": "dwhit"}, {"login": "sokafor"}]),
        }
    )
    entities, _ = await collect(GitHubOrgModule(), domain(), session)
    org = next(e for e in entities if e.type == E.SOCIAL_PROFILE)
    assert org.value == "https://github.com/acme-corp" and org.metadata["verified_domain"] is True
    assert values(entities, E.USERNAME) == ["dwhit", "sokafor"]
    assert all(e.depth == 2 for e in entities if e.type == E.USERNAME)
    assert org_matches({"email": "oss@acme.example"}, "acme.example")
    assert not org_matches({"blog": "https://acme.example.evil.test"}, "acme.example")


def test_secret_detection_redacts_and_ignores_placeholders():
    text = (
        'aws_key = "AKIAABCDEFGHIJKLMNOP"\npassword: changeme\npassword = "Tr0ub4dor&3x"\n'
        "-----BEGIN RSA PRIVATE KEY-----\npostgres://app:hunter22@db.acme.example/prod"
    )
    found = {f["type"]: f["preview"] for f in find_secrets(text)}
    assert found["AWS access key"] == "AKIA… (20 chars)"
    assert found["Password assignment"] == "Tr0u… (12 chars)"
    assert found["Private key"] == "PRIVATE KEY" and "Connection string" in found
    assert "hunter22" not in str(found) and "Tr0ub4dor" not in str(found)


async def test_code_leaks_requires_token_and_extracts_findings(monkeypatch):
    assert not CodeLeaksModule.is_configured()
    monkeypatch.setenv("ARGUS_GITHUB_TOKEN", "ghp_test")
    get_settings.cache_clear()
    try:
        assert CodeLeaksModule.is_configured()
        data = {
            "total_count": 2,
            "items": [
                {
                    "html_url": "https://github.com/someone/tools/blob/main/deploy.sh",
                    "path": "deploy.sh",
                    "repository": {"full_name": "someone/tools", "owner": {"login": "someone"}},
                    "text_matches": [
                        {"fragment": "ssh deploy@build01.corp.acme.example\nexport TOKEN=ghp_" + "a" * 36}
                    ],
                },
                {
                    "html_url": "https://github.com/x/y/blob/main/README.md",
                    "path": "README.md",
                    "repository": {"full_name": "x/y"},
                    "text_matches": [{"fragment": "contact jane@acme.example"}],
                },
            ],
        }
        seed = domain()
        entities, relations = await collect(
            CodeLeaksModule(), seed, FakeSession({r"search/code": FakeResponse(200, data)})
        )
        leak = next(e for e in entities if e.type == E.URL)
        assert leak.metadata["secrets"][0]["type"] == "GitHub token" and "aaaa" not in str(leak.metadata["secrets"])
        assert values(entities, E.SUBDOMAIN) == ["build01.corp.acme.example"]
        assert values(entities, E.EMAIL) == ["jane@acme.example"]
        assert seed.metadata["public_code"] == {"files": 2, "files_with_secrets": 1}
        assert any(r.type == RelationType.EXPOSES for r in relations)
    finally:
        get_settings.cache_clear()


# ----------------------------------------------------------------------------- PGP
INDEX = """info:1:2
pub:0123456789ABCDEF0123456789ABCDEF01234567:1:4096:1500000000::
uid:Dana%20Whitfield%20<dana@acme.example>:1500000000::
uid:Dana%20Whitfield%20(personal)%20<dana.w@mail.example>:1500000000::
pub:FEDCBA9876543210FEDCBA9876543210FEDCBA98:1:2048:1300000000::r
uid:Old%20Key%20<someone@else.example>:1300000000::
"""


def test_hkp_index_parsing():
    keys = parse_index(INDEX)
    assert keys[0]["key_id"] == "89ABCDEF01234567" and keys[0]["created"] == "2017-07-14"
    assert keys[0]["uids"][1] == {"name": "Dana Whitfield", "email": "dana.w@mail.example"}
    assert keys[1]["revoked"] is True


async def test_pgp_links_email_to_name_and_personal_address():
    email = Entity.create(E.EMAIL, "dana@acme.example", depth=1)
    entities, relations = await collect(
        PgpKeyserverModule(), email, FakeSession({r"keyserver": FakeResponse(200, INDEX)})
    )
    assert values(entities, E.PERSON) == ["Dana Whitfield"]
    assert values(entities, E.EMAIL) == ["dana.w@mail.example"]
    assert any(r.label == "Same PGP key" for r in relations)
    assert email.metadata["pgp_keys"][0]["key_id"] == "89ABCDEF01234567"
    assert await collect(PgpKeyserverModule(), email, FakeSession({})) == ([], [])  # 404 = no keys


# ----------------------------------------------------------------------------- web recon
async def test_web_recon_confirms_exposed_files_by_content():
    home = '<a href="mailto:press@acme.example">Press</a> <a href="tel:+44 20 7946 0958">Call</a> vendor@other.example'
    session = FakeSession(
        {
            r"well-known/security\.txt": FakeResponse(
                200, "Contact: mailto:security@acme.example\nExpires: 2027-01-01T00:00:00Z"
            ),
            r"robots\.txt": FakeResponse(200, "User-agent: *\nDisallow: /admin/\nDisallow: /blog/\nDisallow: /*.pdf"),
            r"\.git/HEAD": FakeResponse(200, "ref: refs/heads/main\n"),
            r"/\.env$": FakeResponse(200, "DB_PASSWORD=supersecret\nAPI_KEY=abc\n"),
            r"server-status": FakeResponse(200, "<html>Not found</html>"),  # soft-404: no evidence, no finding
            r"acme\.example/$": FakeResponse(200, home),
            r"/contact$": FakeResponse(200, "Call us: +1 (555) 010-0199 or 0800 123 456"),
        }
    )
    seed = domain()
    entities, _ = await collect(WebReconModule(), seed, session)
    files = {e.metadata["file"]: e for e in entities if e.type == E.URL and e.metadata["category"] == "exposed_file"}
    assert set(files) == {"Git repository metadata", "Environment file with configuration secrets"}
    env = files["Environment file with configuration secrets"].metadata["evidence"]
    assert env == "variables: API_KEY, DB_PASSWORD" and "supersecret" not in env
    assert seed.metadata["exposed_files"] == ["/.git/HEAD", "/.env"]
    assert seed.metadata["security_txt"]["present"] is True
    assert values(entities, E.EMAIL) == ["press@acme.example", "security@acme.example"]
    phones = {e.value: e.confidence for e in entities if e.type == E.PHONE}
    assert phones == {"+442079460958": 0.8, "+15550100199": 0.55}
    assert [e.value for e in entities if e.metadata.get("category") == "robots"] == ["https://acme.example/admin/"]
    assert WebReconModule.active


def test_phone_and_contact_helpers():
    assert normalise_phone("+44 (0)20 7946 0958") == "+442079460958"
    assert normalise_phone("020 7946 0958") is None  # no country code: ambiguous
    emails, _ = extract_contacts("a@acme.example b@sub.acme.example c@other.example", "acme.example")
    assert emails == {"a@acme.example", "b@sub.acme.example"}


# ----------------------------------------------------------------------------- cloud storage
async def test_cloud_storage_distinguishes_public_private_and_missing():
    listing = b"<ListBucketResult><Key>backups/db-2024.sql.gz</Key><Key>logo.png</Key></ListBucketResult>"
    session = FakeSession(
        {
            r"acme-backups\.s3": FakeResponse(200, listing),
            r"acme-prod\.s3": FakeResponse(403, b"<Code>AccessDenied</Code>"),
            r"storage\.googleapis\.com/acme-dev\?": FakeResponse(404, b"NoSuchBucket"),
        }
    )
    seed = domain("acme.example")
    entities, _ = await collect(CloudStorageModule(), seed, session)
    found = {e.metadata["bucket"]: e for e in entities}
    assert set(found) == {"acme-backups", "acme-prod"}
    assert found["acme-backups"].metadata["public_listing"] is True
    assert found["acme-backups"].metadata["sample_keys"] == ["backups/db-2024.sql.gz", "logo.png"]
    assert found["acme-prod"].metadata["public_listing"] is False and found["acme-prod"].confidence == 0.4
    assert "acme-backups" in cloud_storage.candidate_names("www.acme.example")
    assert not CloudStorageModule().can_handle(domain(depth=1))


# ----------------------------------------------------------------------------- engine
def test_corroboration_raises_confidence_and_records_sources():
    g = IntelligenceGraph("t")
    g.add_entity(Entity.create(E.SUBDOMAIN, "vpn.acme.example", source_module="subdomain_finder", confidence=0.7))
    g.add_entity(Entity.create(E.SUBDOMAIN, "vpn.acme.example", source_module="passive_dns", confidence=0.6))
    g.add_entity(Entity.create(E.SUBDOMAIN, "vpn.acme.example", source_module="passive_dns", confidence=0.6))
    e = g.get_all_entities()[0]
    assert e.metadata["sources"] == ["subdomain_finder", "passive_dns"] and e.confidence == 0.88


def test_passive_only_scans_skip_active_modules():
    from argus.core.engine import ArgusEngine
    from argus.core.events import EventBus
    from argus.modules import get_default_modules

    engine = ArgusEngine(ScanConfig(target="acme.example", target_type=E.DOMAIN, passive_only=True), bus=EventBus())
    assert engine.modules and not any(m.active for m in engine.modules.values())
    assert set(get_default_modules()) - set(engine.modules) == {
        "tls_analyzer",
        "http_fingerprint",
        "web_recon",
        "cloud_storage",
    }
