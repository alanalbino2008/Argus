"""Lookalike (typosquat / homograph / combosquat) domains registered against the target's brand.

For the scan's seed domain only, the module generates candidate impostor names
(``argus/intel/lookalikes.py``), finds out which really exist using DNS, and judges each one:

* **Can it do email?** An MX record means it can send and receive mail: a ready-made
  phishing domain.
* **Is it probably yours?** Organisations register their own typos defensively. If a
  lookalike shares the real domain's name servers or IP addresses, it is marked *yours*
  rather than raised as a threat.
* **Parked?** Name servers of domain-parking and resale services suggest a speculator, not
  (yet) an attacker; still worth watching.

Safety and accuracy:

* **Passive.** Only DNS questions are asked, of public resolvers. Nothing is sent to the
  lookalike's servers, and nothing at all to the target.
* **Out of scope by construction.** Lookalikes belong to third parties (possibly
  attackers). They are marked ``out_of_scope``, so the engine never runs any other module
  against them.
* **Wildcard TLDs.** Some endings answer for every name. A random, certainly-unregistered
  name is checked per TLD first; where it resolves, address answers there prove nothing and
  only name-server delegation counts.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from collections.abc import AsyncIterator
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.core.settings import get_settings
from argus.intel.lookalike_triage import dns_verdict, parent_domain
from argus.intel.lookalikes import Candidate, generate, has_sensitive_word, registrable, split_domain
from argus.modules.base import BaseModule

logger = logging.getLogger("argus.module.lookalike_domains")

CONCURRENCY = 40
TECHNIQUE_WEIGHT = {"homoglyph": 30, "combosquat": 22, "typo": 20, "doppelganger": 20, "tld": 14, "bitsquat": 10}
_parent = parent_domain


def risk_score(technique: str, sensitive: bool, mx: bool, live: bool, verdict: str) -> int:
    if verdict == "yours":
        return 5
    score = TECHNIQUE_WEIGHT.get(technique, 10) + (15 if sensitive else 0) + (35 if mx else 0) + (15 if live else 0)
    if verdict == "parked":
        score = min(score, 45 if mx else 30)
    return max(0, min(100, score))


class LookalikeDomainsModule(BaseModule):
    name = "lookalike_domains"
    description = "Registered lookalike domains (typos, homographs, brand + keyword) that could impersonate the target"
    supported_entity_types = [EntityType.DOMAIN]
    # Found through public DNS (T1596.001); the attacker's side (T1583.001, T1566) is on the attack path.
    attack_techniques = ("T1596.001",)

    def can_handle(self, entity: Entity) -> bool:
        # The seed brand only: lookalikes of discovered third-party domains (MX hosts, CDNs) are not the target's.
        return super().can_handle(entity) and entity.depth == 0

    async def _resolve(self, resolver: Any, name: str, rtype: str) -> tuple[str, list[str]]:
        """('ok', answers) | ('nx', []) | ('none', []) | ('error', [])."""
        try:
            answers = await resolver.resolve(name, rtype)
            return "ok", [str(r.to_text()).rstrip(".").lower() for r in answers]
        except dns.resolver.NXDOMAIN:
            return "nx", []
        except dns.resolver.NoAnswer:
            return "none", []
        except (dns.exception.DNSException, OSError) as exc:
            self.report_error("dns", exc)
            return "error", []

    async def _wildcard_tlds(self, resolver: Any, suffixes: set[str]) -> set[str]:
        wild = set()
        for suffix in suffixes:
            status, _ = await self._resolve(resolver, f"argus-{secrets.token_hex(8)}.{suffix}", "A")
            if status == "ok":
                wild.add(suffix)
        return wild

    async def _profile(self, resolver: Any, name: str, wildcard: bool) -> dict[str, Any] | None:
        status, ips = await self._resolve(resolver, name, "A")
        if status in ("nx", "error"):
            return None
        _, ns = await self._resolve(resolver, name, "NS")
        if wildcard and not ns:
            return None  # an address answer under a wildcard TLD proves nothing
        if status == "none" and not ns:
            return None
        _, mx = await self._resolve(resolver, name, "MX")
        mx_hosts = [m.split()[-1] for m in mx if m.split()[-1] not in ("", ".")]
        return {"ips": ips[:8], "ns": ns[:6], "mx": mx_hosts[:6]}

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        try:
            original = registrable(entity.value)
            _, suffix = split_domain(entity.value)
        except ValueError:
            return
        candidates = generate(original, limit=get_settings().lookalike_max_candidates)
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = min(config.timeout_seconds, 6.0)

        # The real domain's infrastructure: lookalikes sharing it are almost certainly defensive registrations.
        own = await self._profile(resolver, original, wildcard=False) or {"ips": [], "ns": []}
        own_ns = {_parent(n) for n in own["ns"]}
        own_ips = set(own["ips"])
        wild = await self._wildcard_tlds(resolver, {split_domain(c.domain)[1] for c in candidates})

        gate = asyncio.Semaphore(CONCURRENCY)

        async def check(candidate: Candidate) -> tuple[Candidate, dict[str, Any] | None]:
            async with gate:
                tld = split_domain(candidate.domain)[1]
                return candidate, await self._profile(resolver, candidate.domain, wildcard=tld in wild)

        results = await asyncio.gather(*(check(c) for c in candidates))
        registered = [(c, p) for c, p in results if p is not None]
        self.report_ok()

        for candidate, profile in registered:
            verdict = dns_verdict(profile, own_ns, own_ips)
            sensitive = has_sensitive_word(candidate)
            facts = {
                "of": original,
                "technique": candidate.technique,
                "detail": candidate.detail,
                "display": candidate.display,
                "verdict": verdict,
                "mx": profile["mx"],
                "ns": profile["ns"],
                "ips": profile["ips"],
                "sensitive_keyword": sensitive,
                "risk": risk_score(candidate.technique, sensitive, bool(profile["mx"]), bool(profile["ips"]), verdict),
            }
            lookalike = Entity.create(
                entity_type=EntityType.DOMAIN,
                value=candidate.domain,
                label=candidate.display,
                # out_of_scope: a third party's (possibly an attacker's) domain - never investigated further.
                metadata={"lookalike": facts, "out_of_scope": True, "sources": [self.name]},
                source_module=self.name,
                confidence=0.9 if verdict == "suspicious" else 0.7,
                depth=entity.depth + 1,
            )
            yield lookalike
            yield Relation.create(
                source_id=lookalike.id,
                target_id=entity.id,
                rel_type=RelationType.ASSOCIATED_WITH,
                label=f"Lookalike ({candidate.technique})",
                metadata={"verdict": verdict},
            )
        entity.metadata["lookalikes_checked"] = len(candidates)
        entity.metadata["lookalikes_registered"] = len(registered)
        entity.metadata["lookalikes_wildcard_tlds"] = sorted(wild)
        if suffix in wild:
            logger.info("TLD .%s answers for every name; only delegated lookalikes were counted", suffix)
