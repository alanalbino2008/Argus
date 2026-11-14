"""Document metadata (the FOCA technique): who wrote the organisation's public files, with what.

Office documents and PDFs carry hidden metadata: the author's display name or
*internal login* (``jsmith`` reveals the account-name format), the last editor,
the company, and the exact software and version used to produce them. Attackers use
this to build user lists for password spraying and to choose exploits for desktop
software. Argus reads the copy held by the Internet Archive - never the target.

Parsing is defensive: size-capped downloads, zip-bomb checks on every member, and
XML with DTDs/entities rejected outright. Only metadata is kept, never content.
"""

from __future__ import annotations

import io
import re
import zipfile
import zlib
from collections.abc import AsyncIterator
from typing import Any, ClassVar
from xml.etree.ElementTree import Element

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from argus.core.http import HttpClient, read_limited
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule

MAX_DOCUMENT = 15_000_000
MAX_XML_MEMBER = 1_000_000
MAX_PDF_STREAMS = 60
GENERIC_AUTHORS = {
    "administrator", "admin", "user", "owner", "unknown", "author", "default", "guest", "test",
    "microsoft office user", "windows user", "office", "pc", "utente", "usuario", "benutzer",
}  # fmt: skip
NS = {
    "dc": "http://purl.org/dc/elements/1.1/",
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dcterms": "http://purl.org/dc/terms/",
    "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
    "office": "urn:oasis:names:tc:opendocument:xmlns:office:1.0",
    "meta": "urn:oasis:names:tc:opendocument:xmlns:meta:1.0",
}
OOXML_APPS = {"16.0000": "2016+", "15.0000": "2013", "14.0000": "2010", "12.0000": "2007"}


def _safe_xml(data: bytes) -> Element | None:
    if len(data) > MAX_XML_MEMBER:
        return None
    try:  # defusedxml rejects DTDs, entity expansion and external entities
        return SafeET.fromstring(data, forbid_dtd=True)
    except (SafeET.ParseError, DefusedXmlException):
        return None


def _text(root: Element | None, path: str) -> str | None:
    if root is None:
        return None
    node = root.find(path, NS)
    return node.text.strip() if node is not None and node.text and node.text.strip() else None


def parse_office(data: bytes) -> dict[str, Any]:
    """OOXML (docx/xlsx/pptx) and OpenDocument (odt/ods/odp) metadata."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return {}

    def member(name: str) -> Element | None:
        try:
            info = archive.getinfo(name)
        except KeyError:
            return None
        if info.file_size > MAX_XML_MEMBER:  # zip-bomb guard: trust the declared size, then cap the read
            return None
        with archive.open(info) as fh:
            return _safe_xml(fh.read(MAX_XML_MEMBER + 1))

    core, app, odf = member("docProps/core.xml"), member("docProps/app.xml"), member("meta.xml")
    facts: dict[str, Any] = {}
    if core is not None or app is not None:
        facts["authors"] = [a for a in (_text(core, "dc:creator"), _text(core, "cp:lastModifiedBy")) if a]
        facts["title"] = _text(core, "dc:title")
        facts["created"] = _text(core, "dcterms:created")
        facts["modified"] = _text(core, "dcterms:modified")
        application, version = _text(app, "ep:Application"), _text(app, "ep:AppVersion")
        if application:
            facts["software"] = [f"{application} {OOXML_APPS.get(version or '', version or '')}".strip()]
        facts["company"] = _text(app, "ep:Company")
    elif odf is not None:
        facts["authors"] = [
            a for a in (_text(odf, "office:meta/meta:initial-creator"), _text(odf, "office:meta/dc:creator")) if a
        ]
        facts["title"] = _text(odf, "office:meta/dc:title")
        facts["created"] = _text(odf, "office:meta/meta:creation-date")
        generator = _text(odf, "office:meta/meta:generator")
        if generator:
            facts["software"] = [generator.split("$")[0].replace("/", " ").strip()]
    return {k: v for k, v in facts.items() if v}


_PDF_FIELD = re.compile(
    rb"/(Author|Creator|Producer|Title|Company|CreationDate)\s*(\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f\s]+>)"
)
_XMP_FIELD = re.compile(
    rb"<(dc:creator|xmp:CreatorTool|pdf:Producer)>\s*(?:<rdf:Seq>\s*<rdf:li[^>]*>)?([^<]{1,200})<", re.S
)
_STREAM = re.compile(rb"stream\r?\n(.{1,2000000}?)\r?\nendstream", re.S)


def _pdf_string(raw: bytes) -> str:
    if raw.startswith(b"<"):
        try:
            raw = bytes.fromhex(raw[1:-1].decode().replace(" ", "").replace("\n", ""))
        except ValueError:
            return ""
    else:
        raw = raw[1:-1]
        raw = re.sub(
            rb"\\([nrtbf()\\])",
            lambda m: {b"n": b"\n", b"r": b"", b"t": b"\t", b"b": b"", b"f": b""}.get(m.group(1), m.group(1)),
            raw,
        )
        raw = re.sub(rb"\\([0-7]{1,3})", lambda m: bytes([int(m.group(1), 8) & 0xFF]), raw)
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", errors="ignore").strip("\x00 ").strip()
    return raw.decode("latin-1", errors="ignore").strip("\x00 ").strip()


def parse_pdf(data: bytes) -> dict[str, Any]:
    if not data.startswith(b"%PDF"):
        return {}
    chunks = [data]
    for i, match in enumerate(_STREAM.finditer(data)):  # PDF 1.5+ often compresses the Info dictionary
        if i >= MAX_PDF_STREAMS:
            break
        try:
            chunks.append(zlib.decompressobj().decompress(match.group(1), MAX_XML_MEMBER))
        except zlib.error:
            continue
    fields: dict[str, list[str]] = {}
    for chunk in chunks:
        for key, raw in _PDF_FIELD.findall(chunk):
            value = _pdf_string(raw)
            if value:
                fields.setdefault(key.decode(), []).append(value)
        for key, raw in _XMP_FIELD.findall(chunk):
            value = raw.decode("utf-8", errors="ignore").strip()
            name = {b"dc:creator": "Author", b"xmp:CreatorTool": "Creator", b"pdf:Producer": "Producer"}[key]
            if value:
                fields.setdefault(name, []).append(value)
    first = {k: v[0] for k, v in fields.items()}
    created = first.get("CreationDate", "")
    m = re.match(r"D:(\d{4})(\d{2})(\d{2})", created)
    software = list(dict.fromkeys(v for k in ("Creator", "Producer") for v in fields.get(k, [])))
    facts = {
        "authors": list(dict.fromkeys(fields.get("Author", []))),
        "title": first.get("Title"),
        "company": first.get("Company"),
        "created": f"{m.group(1)}-{m.group(2)}-{m.group(3)}" if m else None,
        "software": software[:3],
    }
    return {k: v for k, v in facts.items() if v}


def parse_document(data: bytes) -> dict[str, Any]:
    return parse_pdf(data) if data.startswith(b"%PDF") else parse_office(data)


def classify_author(name: str) -> EntityType | None:
    """A real name (``Jane Smith``) or an internal account (``jsmith``, ``ACME\\jsmith``)."""
    n = name.strip()
    if not n or n.lower() in GENERIC_AUTHORS or len(n) > 60 or "@" in n:
        return None
    if " " in n and all(part[:1].isalpha() for part in n.split()) and not any(c.isdigit() for c in n):
        return EntityType.PERSON
    if re.fullmatch(r"[A-Za-z0-9._\\-]{2,40}", n):
        return EntityType.USERNAME
    return None


class DocumentMetadataModule(BaseModule):
    name = "document_metadata"
    description = "Hidden metadata in public documents: authors, internal usernames, software versions"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.URL]
    enrichment = True
    attack_techniques = ("T1593", "T1589.003", "T1592.002")
    rate_limits: ClassVar[dict[str, float]] = {"web.archive.org": 1.0}

    def can_handle(self, entity: Entity) -> bool:
        return (
            super().can_handle(entity)
            and entity.metadata.get("category") == "document"
            and bool(entity.metadata.get("archive_url"))
        )

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        # "id_" asks the archive for the original bytes, without its toolbar/rewriting.
        raw_url = re.sub(r"/web/(\d+)/", r"/web/\1id_/", entity.metadata["archive_url"], count=1)
        async with session.get(raw_url) as resp:
            if resp.status != 200:
                return
            data = await read_limited(resp, MAX_DOCUMENT)
        if not data:
            return
        facts = parse_document(data)
        if not facts:
            return
        entity.metadata["document"] = facts
        depth = entity.depth + 1

        def make(etype: EntityType, value: str, confidence: float, **md: Any) -> Entity:
            return Entity.create(
                etype, value, label=value, metadata={"origin": "document metadata", **md},
                source_module=self.name, confidence=confidence, depth=depth,
            )  # fmt: skip

        for author in facts.get("authors", [])[:3]:
            raw = author.split("\\")[-1]  # DOMAIN\user -> user
            kind = classify_author(raw)
            if kind is None:
                continue
            found = make(kind, raw, 0.6, document=entity.value)
            yield found
            yield Relation.create(entity.id, found.id, RelationType.ASSOCIATED_WITH, label="Document author")
        for software in facts.get("software", [])[:2]:
            tool = make(EntityType.TECHNOLOGY, software, 0.9, category="Desktop software")
            yield tool
            yield Relation.create(entity.id, tool.id, RelationType.USES_TECH, label="Created with")
        company = facts.get("company")
        if company and len(company) <= 100:
            org = make(EntityType.ORGANIZATION, company, 0.7)
            yield org
            yield Relation.create(entity.id, org.id, RelationType.ASSOCIATED_WITH, label="Document company")
