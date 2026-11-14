"""PGP keyservers: the names and other email addresses bound to a key.

A PGP key lists every identity its owner attached to it - often a real name, a work
address *and* personal addresses. Searching the public keyserver by email links
those together (one key = one owner, a strong link); searching by domain lists staff
who ever published a key with a work address.

Uses the machine-readable HKP index of keyserver.ubuntu.com (SKS-compatible network).
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any, ClassVar
from urllib.parse import quote, unquote

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule

HKP = "https://keyserver.ubuntu.com/pks/lookup?op=index&options=mr&fingerprint=on&search={}"
MAX_KEYS = 25
UID_RE = re.compile(r"^\s*(?P<name>[^<(]*?)\s*(?:\((?P<comment>[^)]*)\))?\s*<(?P<email>[^<>\s]+@[^<>\s]+)>\s*$")


def _date(value: str) -> str | None:
    return datetime.fromtimestamp(int(value), tz=timezone.utc).date().isoformat() if value.isdigit() else None


def parse_index(text: str) -> list[dict[str, Any]]:
    """Parse the HKP machine-readable index into keys with their user IDs."""
    keys: list[dict[str, Any]] = []
    for line in text.splitlines():
        parts = line.split(":")
        if parts[0] == "pub" and len(parts) >= 7:
            keys.append(
                {
                    "key_id": parts[1][-16:].upper(),
                    "created": _date(parts[4]),
                    "expires": _date(parts[5]),
                    "revoked": "r" in parts[6],
                    "expired": "e" in parts[6],
                    "uids": [],
                }
            )
        elif parts[0] == "uid" and keys and len(parts) >= 2:
            uid = unquote(parts[1])
            m = UID_RE.match(uid)
            if m:
                keys[-1]["uids"].append({"name": m.group("name").strip(), "email": m.group("email").lower()})
    return keys


class PgpKeyserverModule(BaseModule):
    name = "pgp_keyserver"
    description = "Public PGP keys: real names and linked email addresses (one key = one owner)"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.EMAIL, EntityType.DOMAIN]
    attack_techniques = ("T1589.002", "T1589.003")
    rate_limits: ClassVar[dict[str, float]] = {"keyserver.ubuntu.com": 1.0}

    def can_handle(self, entity: Entity) -> bool:
        if not super().can_handle(entity):
            return False
        return entity.type == EntityType.EMAIL or entity.depth <= 1

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        query = entity.value.strip().lower()
        async with session.get(HKP.format(quote(query))) as resp:
            if resp.status == 404:
                return  # no keys: the documented "not found" answer
            if resp.status != 200:
                self.report_error("keyserver", f"HTTP {resp.status}")
                return
            keys = parse_index(await resp.text())

        domain = query if entity.type == EntityType.DOMAIN else query.split("@", 1)[1]
        depth = entity.depth + 1
        relevant = [
            k for k in keys
            if any(u["email"] == query or u["email"].endswith("@" + domain) for u in k["uids"])
        ][:MAX_KEYS]  # fmt: skip
        if entity.type == EntityType.EMAIL:
            entity.metadata["pgp_keys"] = [
                {k: key[k] for k in ("key_id", "created", "expires", "revoked", "expired")} for key in relevant
            ]

        for key in relevant:
            key_meta = {"pgp_key": key["key_id"], "key_created": key["created"], "revoked": key["revoked"]}
            names = {u["name"] for u in key["uids"] if " " in u["name"] and not any(c.isdigit() for c in u["name"])}
            person = None
            if names:
                name = sorted(names, key=len, reverse=True)[0]
                person = Entity.create(
                    EntityType.PERSON, name, label=name, metadata={"origin": "PGP key", **key_meta},
                    source_module=self.name, confidence=0.75, depth=depth,
                )  # fmt: skip
                yield person
            for uid in key["uids"][:8]:
                if uid["email"] == query:
                    mail = entity
                else:
                    mail = Entity.create(
                        EntityType.EMAIL, uid["email"], label=uid["email"], metadata={"origin": "PGP key", **key_meta},
                        source_module=self.name, confidence=0.8, depth=depth,
                    )  # fmt: skip
                    yield mail
                    if entity.type == EntityType.EMAIL:
                        yield Relation.create(entity.id, mail.id, RelationType.ASSOCIATED_WITH, label="Same PGP key")
                    else:
                        yield Relation.create(
                            mail.id, entity.id, RelationType.ASSOCIATED_WITH, label="PGP key on domain"
                        )
                if person is not None:
                    yield Relation.create(person.id, mail.id, RelationType.HAS_ACCOUNT, label="PGP user ID")
