"""Campaigns: lookalikes, watched servers and tagged indicators that share infrastructure.

One actor rarely registers one domain. They register ten, point them at the same server, give them
the same name servers and mail host, and copy the same favicon and page. Seen one by one, that is ten
alerts; seen together, it is one campaign, and one abuse report to the host can take down all of it.

What Argus already knows is linked when two items share something a stranger would not share by
chance:

* the same **IP address**, except addresses of large CDNs (Cloudflare, Fastly), which front millions
  of unrelated sites;
* the same **name servers**, except shared DNS providers (Cloudflare, Route 53, GoDaddy…);
* the same **mail host**, except large mail providers (Google, Microsoft, Zoho…);
* the same **favicon** (served by a lookalike's site) or a distinctive identical **page title**;
* the same **fingerprint watch** (servers sharing one favicon, JARM, HASSH or certificate).

Groups of two or more linked items are campaigns, ordered by their worst severity and size. Nothing
is looked up here: clustering only uses what brand watches, fingerprint watches and the team's tags
have already recorded.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import defaultdict
from functools import lru_cache
from typing import Any

from argus.intel.lookalike_triage import SEVERITY_ORDER, parent_domain, shared_provider

# Published ranges of CDNs that front unrelated sites (https://www.cloudflare.com/ips/, Fastly's public list).
CDN_RANGES = tuple(ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23", "103.245.224.0/24",
    "104.156.80.0/20", "140.248.64.0/18", "140.248.128.0/17", "146.75.0.0/17", "151.101.0.0/16", "157.52.64.0/18",
    "167.82.0.0/17", "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20", "172.111.64.0/18", "185.31.16.0/22",
    "199.27.72.0/21", "199.232.0.0/16", "2a04:4e40::/32", "2a04:4e42::/32",
))  # fmt: skip
SHARED_MAIL = ("google.com", "googlemail.com", "outlook.com", "protection.outlook.com", "hotmail.com", "zoho.com",
               "zoho.eu", "mailgun.org", "sendgrid.net", "amazonses.com", "yandex.net", "mail.ru", "secureserver.net",
               "emailsrvr.com", "messagingengine.com", "mimecast.com", "pphosted.com", "icloud.com", "privateemail.com",
               "registrar-servers.com", "titan.email", "hostinger.com", "ovh.net", "gandi.net", "mx.cloudflare.net",
               "cloudflare.net")  # fmt: skip
GENERIC_TITLES = re.compile(r"^(index of|welcome to nginx|apache2? |iis windows|403 forbidden|404 not found|"
                            r"not found|forbidden|default (web )?page|coming soon|under construction|"
                            r"account suspended|this site can|domain (is )?(for sale|parked)|parked|loading|"
                            r"redirect|just a moment|attention required|error)", re.IGNORECASE)  # fmt: skip
LINK_LABELS = {"ip": "IP address", "ns": "Name servers", "mx": "Mail host", "favicon": "Favicon", "title": "Page title",
               "fingerprint": "Fingerprint watch"}  # fmt: skip
LINK_STRENGTH = {"favicon": 3, "fingerprint": 3, "ip": 2, "ns": 2, "mx": 2, "title": 1}


@lru_cache(maxsize=65536)  # the same addresses recur across thousands of lookalikes
def distinctive_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global and not any(ip in net for net in CDN_RANGES if net.version == ip.version)


def distinctive_title(title: str) -> str | None:
    clean = re.sub(r"\s+", " ", title or "").strip().lower()
    if len(clean) < 12 or GENERIC_TITLES.match(clean):
        return None
    return clean


def _split_server(server: str) -> str:
    if server.startswith("[") and "]:" in server:
        return server[1:].partition("]:")[0]
    return server.partition(":")[0] if server.count(":") == 1 else server


class _Union:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def cluster(
    lookalikes: list[dict[str, Any]], servers: list[dict[str, Any]], tagged: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Campaigns from the workspace's lookalikes, fingerprint-watch servers and tagged indicators.

    ``lookalikes``: {name, display, brand, severity, verdict, first_seen, triage}; ``servers``:
    {server, watch_id, label, first_seen}; ``tagged``: {value, entity_type, tags, updated_at}.
    """
    members: dict[str, dict[str, Any]] = {}
    keys: dict[tuple[str, str], set[str]] = defaultdict(set)

    for item in lookalikes:
        node = f"domain:{item['name']}"
        members[node] = {"kind": "lookalike", "value": item["name"], "display": item.get("display") or item["name"],
                         "brand": item.get("brand"), "severity": item.get("severity") or "medium",
                         "verdict": item.get("verdict") or "", "first_seen": item.get("first_seen") or "",
                         "watch_id": item.get("watch_id")}  # fmt: skip
        triage = item.get("triage") or {}
        dns, web = triage.get("dns") or {}, triage.get("web") or {}
        for ip in dns.get("ips") or []:
            if distinctive_ip(ip):
                keys[("ip", ip)].add(node)
        for ns in {parent_domain(n) for n in dns.get("ns") or []}:
            if not shared_provider(ns):
                keys[("ns", ns)].add(node)
        for mx in {parent_domain(m) for m in dns.get("mx") or []}:
            if mx not in SHARED_MAIL and not any(mx.endswith(f".{p}") for p in SHARED_MAIL):
                keys[("mx", mx)].add(node)
        if web.get("favicon_sha256"):
            keys[("favicon", web["favicon_sha256"])].add(node)
        title = distinctive_title(web.get("title") or "")
        if title:
            keys[("title", title)].add(node)

    for item in servers:
        ip = _split_server(item["server"])
        node = f"ip:{ip}"
        member = members.setdefault(node, {"kind": "server", "value": ip, "display": item["server"], "severity": "high",
                                           "verdict": "", "first_seen": item.get("first_seen") or "",
                                           "watches": [], "servers": []})  # fmt: skip
        member.setdefault("watches", []).append(item.get("label"))
        member.setdefault("servers", []).append([str(item.get("watch_id")), item["server"]])  # for STIX ids
        keys[("fingerprint", str(item.get("watch_id")))].add(node)
        if distinctive_ip(ip):
            keys[("ip", ip)].add(node)

    for item in tagged:
        value = str(item.get("value") or "").strip().lower()
        if item.get("entity_type") == "ip_address" and distinctive_ip(value):
            node = f"ip:{value}"
            keys[("ip", value)].add(node)
        elif item.get("entity_type") in ("domain", "subdomain") and value:
            node = f"domain:{value}"
        else:
            continue
        member = members.setdefault(node, {"kind": "tagged", "value": value, "display": value, "severity": "medium",
                                           "verdict": "", "first_seen": item.get("updated_at") or ""})  # fmt: skip
        member["tags"] = sorted(set(member.get("tags", [])) | set(item.get("tags") or []))
        if item.get("entity_id"):
            member["entity_id"] = item["entity_id"]  # the tagged entity (its STIX indicator's id derives from it)

    union = _Union()
    for node in members:
        union.find(node)
    for linked_nodes in keys.values():
        ordered = sorted(linked_nodes)
        for other in ordered[1:]:
            union.union(ordered[0], other)

    groups: dict[str, list[str]] = defaultdict(list)
    for node in members:
        groups[union.find(node)].append(node)
    # Every node sharing a key is in the same group: give each key to its group once, not every key to every group.
    keys_of: dict[str, list[tuple[tuple[str, str], set[str]]]] = defaultdict(list)
    for key, linked in keys.items():
        if len(linked) >= 2:
            keys_of[union.find(next(iter(linked)))].append((key, linked))
    campaigns = []
    for root, nodes in groups.items():
        if len(nodes) < 2:
            continue
        links: list[dict[str, Any]] = []
        for (kind, value), shared in keys_of[root]:
            shown = value
            if kind == "fingerprint":  # name the fingerprint, not the watch's id
                shown = next((w for n in sorted(shared) for w in members[n].get("watches") or [] if w), value)
            if kind == "favicon":
                shown = f"sha256 {value[:12]}…"
            links.append({"type": kind, "label": LINK_LABELS[kind], "value": shown,
                          "members": sorted(members[n]["value"] for n in shared)})  # fmt: skip
        links.sort(key=lambda link: (-LINK_STRENGTH[link["type"]], -len(link["members"]), link["value"]))
        people = sorted((members[n] for n in nodes), key=lambda m: (-SEVERITY_ORDER.get(m["severity"], 1), m["value"]))
        severity = people[0]["severity"]
        seen = sorted(m["first_seen"] for m in people if m["first_seen"])
        readable = {"ip": 0, "ns": 1, "title": 2, "mx": 3, "fingerprint": 4, "favicon": 5}
        anchor = min(links, key=lambda link: (readable[link["type"]], -len(link["members"])))
        campaigns.append({
            "id": "cmp_" + hashlib.sha256("|".join(sorted(nodes)).encode()).hexdigest()[:12],
            "name": f"{anchor['label']}: {anchor['value']}"[:120],
            "severity": severity,
            "size": len(nodes),
            "members": people,
            "links": links,
            "brands": sorted({m["brand"] for m in people if m.get("brand")}),
            "first_seen": seen[0] if seen else None,
            "last_seen": seen[-1] if seen else None,
        })  # fmt: skip
    campaigns.sort(key=lambda c: (-SEVERITY_ORDER.get(c["severity"], 1), -c["size"], c["name"]))
    return campaigns
