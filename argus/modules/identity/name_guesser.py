"""From a person's name to the usernames and email addresses they probably use, checked passively.

People build their handles and addresses from their names: ``janedoe``, ``jane.doe``, ``jdoe``,
``janedoe84``, ``jane.doe@gmail.com``. Investigators try those by hand; this module does it, and
keeps only the guesses that something public confirms, so a guess never becomes a finding by itself:

* **usernames**: each likely handle is looked up on GitHub, GitLab and Keybase, whose public APIs
  give the account's display name. Only accounts whose name matches the person's are kept (and
  graded *probable*: a namesake can have the same name);
* **email addresses**: each likely address at the common providers (and at any domain the
  investigator gave) is checked against **Gravatar**, which answers whether a public profile exists
  for that address without contacting the address, its provider or the person. Addresses with a
  profile are kept; the profile's display name is compared with the person's;
* **published keys**: the PGP keyservers are searched for the name; keys whose user ID carries the
  same name give the addresses their owner attached to them.

Nothing here signs in, probes a sign-up or password-reset page, or sends anything to the person.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import AsyncIterator
from typing import Any, ClassVar
from urllib.parse import quote

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.intel.names import similarity
from argus.modules.base import BaseModule
from argus.modules.identity.github_org import github_headers
from argus.modules.identity.pgp_keyserver import HKP, parse_index

PROVIDERS = ("gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", "proton.me", "protonmail.com")
MAX_HANDLES = 8
MAX_LOCALS = 6
MAX_EMAILS = 48
SAME_NAME = 0.9


def _ascii(text: str) -> str:
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode().lower()


def name_parts(name: str) -> tuple[str, str, str] | None:
    """(first, middle initials, last) from a full name, in plain lower-case letters; None for one word."""
    words = [w for w in re.split(r"[\s\-']+", _ascii(name)) if re.fullmatch(r"[a-z]+", w)]
    if len(words) < 2:
        return None
    return words[0], "".join(w[0] for w in words[1:-1]), words[-1]


def handles(name: str, birth_year: int | None = None) -> list[str]:
    """Likely usernames, most common patterns first."""
    parts = name_parts(name)
    if parts is None:
        return []
    first, _middle, last = parts
    base = [f"{first}{last}", f"{first}.{last}", f"{first}_{last}", f"{first[0]}{last}", f"{first}{last[0]}",
            f"{last}{first}", f"{first}-{last}", f"{last}.{first}"]  # fmt: skip
    if birth_year:
        yy = str(birth_year)[-2:]
        base[3:3] = [f"{first}{last}{yy}", f"{first}{last}{birth_year}", f"{first[0]}{last}{yy}"]
    return list(dict.fromkeys(h for h in base if 3 <= len(h) <= 39))


def email_locals(name: str, birth_year: int | None = None) -> list[str]:
    parts = name_parts(name)
    if parts is None:
        return []
    first, _middle, last = parts
    out = [f"{first}.{last}", f"{first}{last}", f"{first[0]}{last}", f"{first}_{last}", f"{first[0]}.{last}"]
    if birth_year:
        out.insert(2, f"{first}.{last}{str(birth_year)[-2:]}")
    return list(dict.fromkeys(out))[:MAX_LOCALS]


def guessed_emails(name: str, birth_year: int | None = None, domains: list[str] | tuple[str, ...] = ()) -> list[str]:
    """Likely addresses: the investigator's domains first (a work or personal domain), then the providers."""
    locals_ = email_locals(name, birth_year)
    own = [d.lower().strip() for d in domains if d and "." in d]
    out = [f"{lp}@{d}" for d in own for lp in locals_] + [f"{lp}@{d}" for d in PROVIDERS for lp in locals_]
    return list(dict.fromkeys(out))[:MAX_EMAILS]


def _same_name(a: str | None, b: str) -> bool:
    return bool(a) and similarity(str(a), b, kind="person") >= SAME_NAME


class NameGuesserModule(BaseModule):
    name = "name_guesser"
    description = ("Likely usernames and email addresses built from a person's name, kept only when a public "
                   "profile with the same name, a Gravatar profile or a published key confirms them")  # fmt: skip
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.PERSON]
    third_party_safe = True  # asks public directories; never contacts the person or their mail provider
    attack_techniques = ("T1589.002", "T1589.003", "T1593.001")
    rate_limits: ClassVar[dict[str, float]] = {"api.github.com": 1.0, "gitlab.com": 0.5, "keybase.io": 0.5,
                                               "en.gravatar.com": 0.25, "keyserver.ubuntu.com": 1.0}  # fmt: skip

    def can_handle(self, entity: Entity) -> bool:
        return super().can_handle(entity) and entity.depth == 0 and name_parts(entity.value) is not None

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        name = entity.value.strip()
        hints = config.hints or {}
        year = hints.get("birth_year") if isinstance(hints.get("birth_year"), int) else None
        depth = entity.depth + 1
        tried = {"usernames": 0, "emails": 0, "kept": 0}

        for handle in handles(name, year)[:MAX_HANDLES]:
            tried["usernames"] += 1
            for found in await self._accounts(session, handle, name):
                tried["kept"] += 1
                account = Entity.create(
                    EntityType.SOCIAL_PROFILE, found["url"], label=f"{found['platform']}: {handle}",
                    source_module=self.name, confidence=0.7, depth=depth,
                    metadata={"platform": found["platform"], "profile": found["facts"], "origin": "guessed from the name",
                              "guessed": True, "avatar_url": found["facts"].get("avatar_url")},
                )  # fmt: skip
                user = Entity.create(EntityType.USERNAME, handle, source_module=self.name, confidence=0.7, depth=depth,
                                     metadata={"origin": "guessed from the name", "guessed": True})  # fmt: skip
                yield account
                yield user
                yield Relation.create(entity.id, account.id, RelationType.HAS_ACCOUNT,
                                      label=f"Same name on {found['platform']} (guessed handle)", confidence=0.7)  # fmt: skip
                yield Relation.create(user.id, account.id, RelationType.HAS_ACCOUNT, label="Handle")

        domains = [d for d in hints.get("domains") or [] if isinstance(d, str)]
        for address in guessed_emails(name, year, domains):
            tried["emails"] += 1
            profile = await self._gravatar(session, address)
            if profile is None:
                continue
            tried["kept"] += 1
            shown = str(profile.get("displayName") or profile.get("name", {}).get("formatted") or "")
            same = _same_name(shown, name)
            mail = Entity.create(
                EntityType.EMAIL, address, source_module=self.name, confidence=0.7 if same else 0.45, depth=depth,
                metadata={"origin": "guessed from the name, Gravatar profile exists", "guessed": True,
                          "gravatar_name": shown or None},
            )  # fmt: skip
            yield mail
            yield Relation.create(entity.id, mail.id, RelationType.HAS_ACCOUNT, confidence=0.7 if same else 0.45,
                                  label="Guessed address with a Gravatar profile" + (" of the same name" if same else ""))  # fmt: skip

        async for item in self._pgp(session, entity, name, depth):
            tried["kept"] += 1
            yield item
        entity.metadata["name_guesses"] = tried

    async def _accounts(self, session: HttpClient, handle: str, name: str) -> list[dict[str, Any]]:
        found = []
        async with session.get(f"https://api.github.com/users/{quote(handle)}", headers=github_headers()) as resp:
            data = await resp.json() if resp.status == 200 else None
        if isinstance(data, dict) and _same_name(data.get("name"), name):
            found.append({"platform": "GitHub", "url": f"https://github.com/{data.get('login') or handle}",
                          "facts": {"display_name": data.get("name"), "location": data.get("location") or "",
                                    "bio": data.get("bio") or "", "website": data.get("blog") or "",
                                    "company": data.get("company") or "", "avatar_url": data.get("avatar_url")}})  # fmt: skip
        async with session.get(f"https://gitlab.com/api/v4/users?username={quote(handle)}") as resp:
            rows = await resp.json() if resp.status == 200 else None
        if isinstance(rows, list) and rows and _same_name(rows[0].get("name"), name):
            row = rows[0]
            found.append({"platform": "GitLab", "url": str(row.get("web_url") or f"https://gitlab.com/{handle}"),
                          "facts": {"display_name": row.get("name"), "avatar_url": row.get("avatar_url")}})  # fmt: skip
        url = f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={quote(handle)}&fields=profile"
        async with session.get(url) as resp:
            data = await resp.json() if resp.status == 200 else None
        them = (data or {}).get("them") if isinstance(data, dict) else None
        profile = ((them or [None])[0] or {}).get("profile") if isinstance(them, list) else None
        if isinstance(profile, dict) and _same_name(profile.get("full_name"), name):
            found.append({"platform": "Keybase", "url": f"https://keybase.io/{handle}",
                          "facts": {"display_name": profile.get("full_name"), "location": profile.get("location") or "",
                                    "bio": profile.get("bio") or ""}})  # fmt: skip
        return found

    async def _gravatar(self, session: HttpClient, address: str) -> dict[str, Any] | None:
        digest = hashlib.md5(address.encode(), usedforsecurity=False).hexdigest()
        async with session.get(f"https://en.gravatar.com/{digest}.json") as resp:
            if resp.status != 200:
                return None
            data = await resp.json()
        entries = (data or {}).get("entry") if isinstance(data, dict) else None
        return entries[0] if isinstance(entries, list) and entries and isinstance(entries[0], dict) else None

    async def _pgp(
        self, session: HttpClient, entity: Entity, name: str, depth: int
    ) -> AsyncIterator[Entity | Relation]:
        async with session.get(HKP.format(quote(name))) as resp:
            if resp.status != 200:
                return
            keys = parse_index(await resp.text())
        seen: set[str] = set()
        for key in keys[:25]:
            if not any(_same_name(u["name"], name) for u in key["uids"]):
                continue
            for uid in key["uids"][:8]:
                if uid["email"] in seen:
                    continue
                seen.add(uid["email"])
                mail = Entity.create(EntityType.EMAIL, uid["email"], source_module=self.name, confidence=0.75, depth=depth,
                                     metadata={"origin": "PGP key in the person's name", "pgp_key": key["key_id"],
                                               "key_created": key["created"], "revoked": key["revoked"]})  # fmt: skip
                yield mail
                yield Relation.create(entity.id, mail.id, RelationType.HAS_ACCOUNT, confidence=0.75,
                                      label="Published key in the same name")  # fmt: skip
