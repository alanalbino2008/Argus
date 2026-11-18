"""Who owns the internet addresses behind a target, and every other range they run.

One server's address is rarely alone. A company that runs its own network holds whole blocks of
addresses, announced to the internet under its own network number (an **autonomous system**, or
ASN). Finding those blocks maps everything the company runs online. Most websites, though, sit on a
cloud or hosting provider's addresses, shared with thousands of strangers, and those ranges say
nothing about the company.

From the official internet registries (RIPEstat and RDAP, free and public; the target is never
contacted), this module records:

* for an **IP address**: the address block it belongs to, who it is registered to, the country,
  the abuse contact, and the network (ASN) announcing it. Blocks registered to a cloud or hosting
  provider are marked **shared**;
* for a **network (ASN)**: who holds it, and every address range it announces (IPv4 and IPv6),
  with the number of addresses. Providers' networks are not expanded: their ranges are other
  people's;
* for a **company**: networks registered in its name, matched name against name (company names
  compared word by word, legal forms ignored), each a likely candidate to confirm.

Ranges are listed, never scanned: probing a whole block would touch every system on it.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
from collections.abc import AsyncIterator
from typing import Any, ClassVar
from urllib.parse import quote

import aiohttp

from argus.core.http import HttpClient, read_limited
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.intel.names import similarity
from argus.modules.base import BaseModule

RIPESTAT = "https://stat.ripe.net/data"
RDAP = "https://rdap.org"
MAX_BODY = 3_000_000
MATCH = 0.92
# Cloud, CDN and hosting networks: their addresses are rented to thousands of unrelated customers.
PROVIDERS = (
    "amazon", "aws", "google", "microsoft", "azure", "cloudflare", "akamai", "fastly", "digitalocean", "linode", "ovh", "hetzner", "oracle", "alibaba", "tencent", "vultr", "choopa", "contabo", "scaleway", "online s.a.s",
    "leaseweb", "godaddy", "bluehost", "unified layer", "hostgator", "namecheap", "ionos", "1&1", "hostinger",
    "squarespace", "wix", "automattic", "wpengine", "wp engine", "shopify", "github", "netlify", "vercel", "heroku",
    "salesforce", "incapsula", "imperva", "sucuri", "stackpath", "edgecast", "limelight", "cdn77", "bunny", "gcore",
    "rackspace", "ibm cloud", "softlayer", "kamatera", "strato", "one.com", "dreamhost", "siteground",
    "a2 hosting", "inmotion", "liquid web", "m247", "datacamp", "psychz", "colocrossing", "quadranet", "zenlayer",
)  # fmt: skip


def is_provider(*names: str | None) -> bool:
    text = " ".join(n for n in names if n).lower()
    return any(p in text for p in PROVIDERS)


def _vcard_name(entity: dict[str, Any]) -> str | None:
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] in ("fn", "org") and item[3]:
            return str(item[3])
    return None


def _vcard_email(entity: dict[str, Any]) -> str | None:
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == "email" and item[3]:
            return str(item[3])
    return None


def rdap_network(data: dict[str, Any]) -> dict[str, Any]:
    """The useful parts of an RDAP IP network answer."""
    cidrs = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}" for c in data.get("cidr0_cidrs") or []
             if (c.get("v4prefix") or c.get("v6prefix")) and c.get("length") is not None]  # fmt: skip
    if not cidrs and data.get("startAddress") and data.get("endAddress"):
        try:
            first, last = ipaddress.ip_address(data["startAddress"]), ipaddress.ip_address(data["endAddress"])
            cidrs = [str(n) for n in ipaddress.summarize_address_range(first, last)][:5]
        except (ValueError, TypeError):
            cidrs = [f"{data['startAddress']} - {data['endAddress']}"]
    registrant = abuse = None
    stack = list(data.get("entities") or [])
    while stack:
        e = stack.pop(0)
        roles = set(e.get("roles") or [])
        if "registrant" in roles and not registrant:
            registrant = _vcard_name(e)
        if "abuse" in roles and not abuse:
            abuse = _vcard_email(e)
        stack.extend(e.get("entities") or [])
    return {k: v for k, v in {
        "block": ", ".join(cidrs[:5]) or None, "name": data.get("name"), "handle": data.get("handle"),
        "registered_to": registrant, "country": data.get("country"), "abuse_contact": abuse,
        "registry": (data.get("port43") or "").replace("whois.", "").upper() or None,
    }.items() if v}  # fmt: skip


def address_count(prefixes: list[str]) -> int:
    total = 0
    for p in prefixes:
        try:
            net = ipaddress.ip_network(p, strict=False)
        except ValueError:
            continue
        if net.version == 4:
            total += net.num_addresses
    return total


class NetworkRangesModule(BaseModule):
    name = "network_ranges"
    description = "Who owns an IP's address block, every range its network announces, and a company's networks"
    supported_entity_types: ClassVar[list[EntityType]] = [
        EntityType.IP_ADDRESS,
        EntityType.ASN,
        EntityType.ORGANIZATION,
    ]
    attack_techniques = ("T1590.005", "T1590.004")
    third_party_safe = True  # public registries only; nothing is sent to the target

    def can_handle(self, entity: Entity) -> bool:
        if not super().can_handle(entity):
            return False
        if entity.type == EntityType.ORGANIZATION:  # a company's own name, not an organisation found in passing
            return entity.depth == 0 and not entity.metadata.get("out_of_scope")
        return entity.depth <= 2

    async def _json(self, session: HttpClient, url: str, config: ScanConfig) -> dict[str, Any] | None:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=config.timeout_seconds * 2),
                                   headers={"Accept": "application/json, application/rdap+json"}) as resp:  # fmt: skip
                if resp.status != 200:
                    return None
                body = await read_limited(resp, MAX_BODY)
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
            self.report_error(url.split("/")[2], exc)
            return None
        if not body:
            return None
        try:
            data = json.loads(body)
        except ValueError:
            return None
        return data if isinstance(data, dict) else None

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        if entity.type == EntityType.IP_ADDRESS:
            async for item in self._ip(entity, session, config):
                yield item
        elif entity.type == EntityType.ASN:
            await self._asn(entity, session, config)
        else:
            async for item in self._company(entity, session, config):
                yield item

    def _asn_entity(self, number: int, holder: str | None, depth: int) -> Entity:
        return Entity.create(EntityType.ASN, f"AS{number}", label=f"AS{number}" + (f" {holder}" if holder else ""),
                             source_module=self.name, depth=depth,
                             metadata={k: v for k, v in {"as_name": holder, "holder": holder,
                                                         "shared_provider": is_provider(holder)}.items() if v})  # fmt: skip

    async def _ip(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        try:
            address = ipaddress.ip_address(entity.value.strip())
        except ValueError:
            return
        if not address.is_global:
            return
        network: dict[str, Any] = {}
        rdap = await self._json(session, f"{RDAP}/ip/{address}", config)
        if rdap:
            network = rdap_network(rdap)
        overview = await self._json(session, f"{RIPESTAT}/prefix-overview/data.json?resource={address}", config)
        asns = ((overview or {}).get("data") or {}).get("asns") or []
        announced = ((overview or {}).get("data") or {}).get("resource")
        if announced:
            network["announced_as"] = announced
        holder = asns[0].get("holder") if asns else None
        network["shared_provider"] = is_provider(network.get("registered_to"), network.get("name"), holder)
        if network:
            entity.metadata["network"] = network
        self.report_ok()
        for a in asns[:2]:
            if not a.get("asn"):
                continue
            asn = self._asn_entity(int(a["asn"]), a.get("holder"), entity.depth + 1)
            yield asn
            yield Relation.create(entity.id, asn.id, RelationType.HOSTED_ON,
                                  label=f"Announced by AS{a['asn']}" + (f" ({announced})" if announced else ""))  # fmt: skip

    async def _asn(self, entity: Entity, session: HttpClient, config: ScanConfig) -> None:
        number = entity.value.upper().removeprefix("AS").strip()
        if not number.isdigit():
            return
        overview = await self._json(session, f"{RIPESTAT}/as-overview/data.json?resource=AS{number}", config)
        holder = ((overview or {}).get("data") or {}).get("holder") or entity.metadata.get("as_name")
        shared = is_provider(holder)
        info: dict[str, Any] = {"holder": holder, "shared_provider": shared}
        if shared:
            info["note"] = "A cloud or hosting provider's network: its ranges belong to its many customers"
        else:
            data = await self._json(session, f"{RIPESTAT}/announced-prefixes/data.json?resource=AS{number}", config)
            prefixes = [
                str(p.get("prefix")) for p in ((data or {}).get("data") or {}).get("prefixes") or [] if p.get("prefix")
            ]
            v4 = sorted((p for p in prefixes if ":" not in p), key=lambda p: ipaddress.ip_network(p, strict=False))
            v6 = sorted(p for p in prefixes if ":" in p)
            info.update(
                ranges_v4=v4[:200], ranges_v6=v6[:100], range_count=len(prefixes), addresses_v4=address_count(v4)
            )
        self.report_ok()
        entity.metadata["network_ranges"] = {k: v for k, v in info.items() if v not in (None, [], "")} | {
            "shared_provider": shared
        }

    async def _company(
        self, entity: Entity, session: HttpClient, config: ScanConfig
    ) -> AsyncIterator[Entity | Relation]:
        data = await self._json(session, f"{RIPESTAT}/searchcomplete/data.json?resource={quote(entity.value)}", config)
        found = []
        for category in ((data or {}).get("data") or {}).get("categories") or []:
            if category.get("category") != "ASNs":
                continue
            for s in category.get("suggestions") or []:
                value, description = str(s.get("value") or ""), str(s.get("description") or "")
                holder = description.split(" - ", 1)[-1] if " - " in description else description
                score = max(similarity(entity.value, holder, kind="company"),
                            similarity(entity.value, description, kind="company"))  # fmt: skip
                if (
                    value.upper().startswith("AS")
                    and value[2:].isdigit()
                    and score >= MATCH
                    and not is_provider(holder)
                ):
                    found.append((int(value[2:]), description, score))
        self.report_ok()
        entity.metadata["networks_checked"] = True
        for number, holder, score in found[:5]:
            asn = self._asn_entity(number, holder, entity.depth + 1)
            asn.confidence = round(score * 0.9, 2)  # a name match: likely, to be confirmed
            asn.metadata["matched_by"] = "registry name"
            yield asn
            yield Relation.create(entity.id, asn.id, RelationType.OPERATES, label="Network registered in its name")
