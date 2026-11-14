"""Cloud storage named after the target: does it exist, and is it publicly listable?

Companies name storage buckets predictably (``acme-backups``, ``acme-prod-assets``).
A bucket whose contents can be *listed* by anyone is one of the most common causes
of large data leaks. Argus derives candidate names from the target domain and asks
Amazon S3 and Google Cloud Storage about each one.

A name match does not prove ownership - anyone can create ``acme-backups`` - so
findings are marked ``ownership: unverified`` with modest confidence; a public
listing's file names usually settle it. Active (guesses names attributed to the
target), so it is skipped by passive-only scans.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator
from typing import Any, ClassVar

import aiohttp

from argus.core.http import HttpClient, read_limited
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule

SUFFIXES = ("", "-backup", "-backups", "-prod", "-dev", "-staging", "-assets", "-static", "-media",
            "-files", "-data", "-logs", "-public", "-uploads", "-cdn", "-www")  # fmt: skip
PROVIDERS = {
    "Amazon S3": "https://{}.s3.amazonaws.com/?max-keys=10",
    "Google Cloud Storage": "https://storage.googleapis.com/{}?max-keys=10",
}
BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
KEY_RE = re.compile(r"<Key>([^<]{1,200})</Key>")


def candidate_names(domain: str) -> list[str]:
    label = domain.lower().removeprefix("www.").split(".")[0]
    bases = dict.fromkeys([label, label.replace("-", ""), domain.lower().replace(".", "-")])
    names = [f"{b}{s}" for b in bases for s in SUFFIXES]
    return [n for n in dict.fromkeys(names) if BUCKET_RE.match(n)]


def interpret(status: int, body: bytes) -> dict[str, Any] | None:
    """None = no such bucket; otherwise whether it exists publicly or privately."""
    if status == 200 and b"<ListBucketResult" in body:
        return {"public_listing": True, "sample_keys": KEY_RE.findall(body.decode("utf-8", "ignore"))[:10]}
    if status in (301, 307, 400, 401, 403) and b"NoSuchBucket" not in body:
        return {"public_listing": False}
    return None


class CloudStorageModule(BaseModule):
    name = "cloud_storage"
    description = "Amazon S3 / Google Cloud Storage buckets named after the target, and whether they are public"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.DOMAIN]
    attack_techniques = ("T1593", "T1596")
    active = True

    def can_handle(self, entity: Entity) -> bool:
        return super().can_handle(entity) and entity.depth == 0

    async def _check(self, session: HttpClient, provider: str, name: str, config: ScanConfig) -> dict[str, Any] | None:
        timeout = aiohttp.ClientTimeout(total=config.timeout_seconds)
        async with session.get(PROVIDERS[provider].format(name), timeout=timeout, allow_redirects=False) as resp:
            body = (await read_limited(resp, 200_000)) or b""
            result = interpret(resp.status, body)
        return {"provider": provider, "bucket": name, **result} if result else None

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        names = candidate_names(entity.value)
        checks = [self._check(session, p, n, config) for n in names for p in PROVIDERS]
        results = await asyncio.gather(*checks, return_exceptions=True)
        errors = [r for r in results if isinstance(r, Exception)]
        if errors:
            self.report_error("cloud-storage", f"{len(errors)} of {len(checks)} checks failed: {errors[0]}")
        found = [r for r in results if isinstance(r, dict)]
        entity.metadata["cloud_storage"] = {"names_checked": len(names), "found": len(found)}
        for bucket in found:
            host = "s3.amazonaws.com" if bucket["provider"] == "Amazon S3" else "storage.googleapis.com"
            url = (
                f"https://{bucket['bucket']}.{host}/" if host.startswith("s3") else f"https://{host}/{bucket['bucket']}"
            )
            public = bucket["public_listing"]
            item = Entity.create(
                EntityType.URL,
                url,
                label=f"{bucket['provider']}: {bucket['bucket']}",
                metadata={
                    "category": "cloud_storage",
                    "provider": bucket["provider"],
                    "bucket": bucket["bucket"],
                    "public_listing": public,
                    "sample_keys": bucket.get("sample_keys", []),
                    "ownership": "unverified (name match)",
                    "live": "confirmed",
                },
                source_module=self.name,
                confidence=0.6 if public else 0.4,
                depth=entity.depth + 1,
            )
            yield item
            yield Relation.create(
                entity.id, item.id, RelationType.EXPOSES if public else RelationType.ASSOCIATED_WITH,
                label="Publicly listable storage (name match)" if public else "Storage bucket (name match)",
            )  # fmt: skip
