"""Places that publish facts about people on purpose: research records, encyclopaedic data and
developer sites.

* **ORCID** (researchers' own records): employers and education with dates, sometimes an email;
* **OpenAlex** (every published paper): the institutions an author has been at and how much they publish;
* **Wikidata** (public figures): date of birth, occupation and description;
* **Stack Exchange** (from a username): display name, location and website;
* **npm** (from a username): packages they maintain, and the address their packages are published with.

Each answer is a profile carrying the facts it states (name, employer, place, year of birth), so the
known-details scoring weighs it like any other account: a namesake with another employer or year of
birth is marked as probably someone else. Only exact-name matches are kept from the name searches.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from typing import Any, ClassVar
from urllib.parse import quote

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.intel.names import similarity
from argus.modules.base import BaseModule

SAME_NAME = 0.9
MAX_EACH = 5
JSON = {"Accept": "application/json"}


def _same(a: Any, b: str) -> bool:
    return bool(a) and similarity(str(a), b, kind="person") >= SAME_NAME


def _profile(module: str, url: str, platform: str, depth: int, facts: dict[str, Any], confidence: float = 0.6,
             **md: Any) -> Entity:  # fmt: skip
    clean = {k: v for k, v in facts.items() if v not in (None, "", [])}
    return Entity.create(EntityType.SOCIAL_PROFILE, url, label=f"{platform}: {clean.get('display_name') or url}",
                         source_module=module, confidence=confidence, depth=depth,
                         metadata={"platform": platform, "profile": clean, "origin": f"{platform} record", **md})  # fmt: skip


def orcid_records(data: Any, name: str) -> list[dict[str, Any]]:
    out = []
    for row in (data or {}).get("expanded-result") or []:
        full = f"{row.get('given-names') or ''} {row.get('family-names') or ''}".strip()
        if not _same(full, name) or not row.get("orcid-id"):
            continue
        out.append({"url": f"https://orcid.org/{row['orcid-id']}", "facts": {
            "display_name": full, "company": ", ".join((row.get("institution-name") or [])[:5]),
            "public_email": ", ".join((row.get("email") or [])[:3])}})  # fmt: skip
    return out[:MAX_EACH]


def openalex_records(data: Any, name: str) -> list[dict[str, Any]]:
    out = []
    for row in (data or {}).get("results") or []:
        if not _same(row.get("display_name"), name):
            continue
        places = [i.get("display_name") for i in row.get("last_known_institutions") or [] if i.get("display_name")]
        countries = [i.get("country_code") for i in row.get("last_known_institutions") or [] if i.get("country_code")]
        out.append({"url": str(row.get("id") or "").replace("https://openalex.org/", "https://openalex.org/authors/"),
                    "facts": {"display_name": row.get("display_name"), "company": ", ".join(places[:3]),
                              "location": ", ".join(countries[:3]), "works": row.get("works_count"),
                              "orcid": row.get("orcid")}})  # fmt: skip
    return [r for r in out if r["url"]][:MAX_EACH]


def wikidata_people(search: Any, entities: Any, name: str) -> list[dict[str, Any]]:
    out = []
    found = (entities or {}).get("entities") or {}
    for row in (search or {}).get("search") or []:
        qid = row.get("id")
        claims = (found.get(qid) or {}).get("claims") or {}
        human = any(((c.get("mainsnak") or {}).get("datavalue") or {}).get("value", {}).get("id") == "Q5"
                    for c in claims.get("P31") or [])  # fmt: skip
        if not human or not _same(row.get("label"), name):
            continue
        born = None
        for c in claims.get("P569") or []:
            value = ((c.get("mainsnak") or {}).get("datavalue") or {}).get("value") or {}
            match = re.match(r"[+-]?(\d{4})", str(value.get("time") or ""))
            born = born or (match.group(1) if match else None)
        out.append({"url": f"https://www.wikidata.org/wiki/{qid}",
                    "facts": {"display_name": row.get("label"), "bio": row.get("description") or "", "born": born}})  # fmt: skip
    return out[:MAX_EACH]


class PublicRecordsModule(BaseModule):
    name = "public_records"
    description = "Research and encyclopaedic records of a person: ORCID, OpenAlex and Wikidata"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.PERSON]
    third_party_safe = True
    attack_techniques = ("T1593", "T1589.003")
    rate_limits: ClassVar[dict[str, float]] = {"pub.orcid.org": 0.5, "api.openalex.org": 0.2, "www.wikidata.org": 0.5}

    def can_handle(self, entity: Entity) -> bool:
        return super().can_handle(entity) and entity.depth == 0 and len(entity.value.split()) >= 2

    async def _coauthors(self, session: HttpClient, url: str, name: str) -> list[str]:
        author = url.rsplit("/", 1)[-1]
        if not re.fullmatch(r"A\d{3,15}", author):
            return []
        async with session.get(f"https://api.openalex.org/works?filter=author.id:{author}&per-page=25") as resp:
            return coauthors(await resp.json(), name) if resp.status == 200 else []

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        name = entity.value.strip()
        words = name.split()
        depth = entity.depth + 1
        found: list[tuple[str, dict[str, Any]]] = []
        query = f"given-names:{quote(words[0])}+AND+family-name:{quote(words[-1])}"
        async with session.get(f"https://pub.orcid.org/v3.0/expanded-search/?q={query}&rows=20", headers=JSON) as resp:
            if resp.status == 200:
                found += [("ORCID", r) for r in orcid_records(await resp.json(), name)]
        async with session.get(f"https://api.openalex.org/authors?search={quote(name)}&per-page=20") as resp:
            if resp.status == 200:
                found += [("OpenAlex", r) for r in openalex_records(await resp.json(), name)]
        for platform, record in found:
            if platform == "OpenAlex":
                record["coauthors"] = await self._coauthors(session, record["url"], name)
        url = (f"https://www.wikidata.org/w/api.php?action=wbsearchentities&search={quote(name)}"
               "&language=en&type=item&limit=10&format=json")  # fmt: skip
        async with session.get(url) as resp:
            search = await resp.json() if resp.status == 200 else None
        ids = [r.get("id") for r in (search or {}).get("search") or [] if r.get("id")]
        if ids:
            url = (f"https://www.wikidata.org/w/api.php?action=wbgetentities&ids={'|'.join(ids[:10])}"
                   "&props=claims&format=json")  # fmt: skip
            async with session.get(url) as resp:
                if resp.status == 200:
                    found += [("Wikidata", r) for r in wikidata_people(search, await resp.json(), name)]
        entity.metadata["public_records"] = {
            p: sum(1 for q, _ in found if q == p) for p in ("ORCID", "OpenAlex", "Wikidata")
        }
        for platform, record in found:
            extra = {"coauthors": record["coauthors"]} if record.get("coauthors") else {}
            profile = _profile(self.name, record["url"], platform, depth, record["facts"], **extra)
            yield profile
            yield Relation.create(entity.id, profile.id, RelationType.HAS_ACCOUNT, confidence=0.6,
                                  label=f"{platform} record in the same name")  # fmt: skip


def coauthors(data: Any, name: str) -> list[str]:
    """The people an author published with most often (from their works' author lists)."""
    counts: dict[str, int] = {}
    for work in (data or {}).get("results") or []:
        for authorship in work.get("authorships") or []:
            other = str((authorship.get("author") or {}).get("display_name") or "").strip()
            if other and not _same(other, name):
                counts[other] = counts.get(other, 0) + 1
    return [n for n, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))][:15]


class DeveloperFootprintModule(BaseModule):
    name = "developer_footprint"
    description = "A username on Stack Exchange and npm: profile, packages, and the address packages are published with"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.USERNAME]
    third_party_safe = True
    attack_techniques = ("T1593", "T1589.002")
    rate_limits: ClassVar[dict[str, float]] = {"api.stackexchange.com": 0.5, "registry.npmjs.org": 0.2}

    def can_handle(self, entity: Entity) -> bool:
        return super().can_handle(entity) and entity.depth <= 1

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        handle = entity.value.strip().lstrip("@")
        depth = entity.depth + 1
        url = f"https://api.stackexchange.com/2.3/users?inname={quote(handle)}&site=stackoverflow&pagesize=20"
        async with session.get(url) as resp:
            data = await resp.json() if resp.status == 200 else None
        for user in (data or {}).get("items") or []:
            if str(user.get("display_name") or "").lower() != handle.lower() or not user.get("link"):
                continue  # only the exact name: "inname" also returns partial matches
            profile = _profile(self.name, str(user["link"]), "Stack Overflow", depth, {
                "display_name": user.get("display_name"), "location": user.get("location") or "",
                "website": user.get("website_url") or "", "avatar_url": user.get("profile_image"),
                "reputation": user.get("reputation")}, confidence=0.7)  # fmt: skip
            yield profile
            yield Relation.create(entity.id, profile.id, RelationType.HAS_ACCOUNT, label="Same username")
            break
        url = f"https://registry.npmjs.org/-/v1/search?text=maintainer:{quote(handle)}&size=20"
        async with session.get(url) as resp:
            data = await resp.json() if resp.status == 200 else None
        packages, emails = [], set()
        for obj in (data or {}).get("objects") or []:
            pkg = obj.get("package") or {}
            mine = [m for m in pkg.get("maintainers") or [] if str(m.get("username") or "").lower() == handle.lower()]
            if not mine:
                continue
            packages.append(pkg.get("name"))
            emails |= {str(m.get("email")).lower() for m in mine if m.get("email") and "@" in str(m.get("email"))}
        if not packages:
            return
        profile = _profile(self.name, f"https://www.npmjs.com/~{handle}", "npm", depth,
                           {"display_name": handle, "packages": packages[:10]}, confidence=0.8)  # fmt: skip
        yield profile
        yield Relation.create(
            entity.id, profile.id, RelationType.HAS_ACCOUNT, label=f"Maintains {len(packages)} npm package(s)"
        )
        for address in sorted(emails)[:3]:
            mail = Entity.create(EntityType.EMAIL, address, source_module=self.name, confidence=0.85, depth=depth,
                                 metadata={"origin": "npm package maintainer address", "username": handle})  # fmt: skip
            yield mail
            yield Relation.create(entity.id, mail.id, RelationType.BELONGS_TO, label="Publishes npm packages with")
