"""Infrastructure pivoting: evidence that two domains belong to the same operator.

A single known asset leads to others through things they *share*:

| Pivot | Why it links domains | Weight |
|---|---|---|
| Analytics / ad / tag IDs | One account (Google Analytics, Tag Manager, AdSense, Meta pixel) is used across an organisation's sites | 0.90 |
| Name servers under the target's own domain | ``ns1.acme.com`` serving another domain: run by the same team | 0.80 |
| Certificate organisation (``O=``) | OV/EV certificates are only issued after the organisation is verified | 0.75 |
| Other dedicated name servers | Not a big provider's; shared by a small set of domains | 0.55 |
| Same IP, few co-hosted domains | Weak on its own (shared hosting); counts only alongside other evidence | 0.40-0.45 |

Independent pieces of evidence are combined with a **noisy-OR**: ``1 - Π(1 - weight)``. Two
moderate signals together are stronger than either alone, but no amount of weak evidence
reaches certainty. Generic infrastructure (big DNS providers, CDNs, certificate organisations
of hosting companies) is excluded, because sharing it proves nothing.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

WEIGHTS = {
    "analytics": 0.90,
    "own_nameserver": 0.80,
    "certificate_org": 0.75,
    "nameserver": 0.55,
    "shared_ip": 0.40,
    "shared_ip_small": 0.45,  # still below MINIMUM: an IP never attributes a domain on its own
}
LIKELY = 0.80
MINIMUM = 0.50
MAX_COHOSTED = 15  # more domains on one IP than this means shared hosting or a CDN: not attributable
MAX_SHARED_NS = 300

TRACKER_PATTERNS = {
    "Google Analytics": re.compile(r"\b(UA-\d{4,10})-\d{1,4}\b"),  # the account, not the property
    "Google Analytics 4": re.compile(r"\b(G-[A-Z0-9]{8,12})\b"),
    "Google Tag Manager": re.compile(r"\b(GTM-[A-Z0-9]{5,8})\b"),
    "Google AdSense": re.compile(r"\b(ca-pub-\d{10,20})\b"),
    "Meta pixel": re.compile(r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{12,20})['\"]"),
}
# Providers whose name servers / certificate organisation are shared by millions of unrelated customers.
GENERIC_NS = (
    "cloudflare.com", "awsdns", "azure-dns", "googledomains.com", "google.com", "domaincontrol.com",
    "registrar-servers.com", "nsone.net", "dnsimple.com", "ultradns", "dynect.net", "akam.net", "akamai",
    "name-services.com", "hostgator.com", "bluehost.com", "ovh.net", "gandi.net", "digitalocean.com",
    "linode.com", "he.net", "wixdns.net", "squarespacedns.com", "worldnic.com", "cloudns.net", "porkbun.com",
    "hover.com", "namecheaphosting.com", "dreamhost.com", "siteground.net", "ionos", "ui-dns", "netlify",
    "vercel-dns.com", "hetzner.com", "one.com", "123-reg.co.uk", "fasthosts", "heartinternet", "tucows",
    "dns.he.net", "zoneedit.com", "afraid.org", "registrar.eu", "safenames.net", "markmonitor.com",
    "cscdns.net", "comlaude-dns", "sedoparking.com", "parkingcrew.net", "bodis.com",
)  # fmt: skip
GENERIC_CERT_ORGS = {
    "cloudflare, inc.", "amazon", "amazon.com, inc.", "google llc", "google trust services", "microsoft corporation",
    "akamai technologies, inc.", "fastly, inc.", "automattic, inc.", "wp engine", "github, inc.", "shopify inc.",
    "squarespace, inc.", "wix.com ltd.", "salesforce.com, inc.", "zendesk, inc.", "hubspot, inc.",
}  # fmt: skip


@dataclass
class Evidence:
    kind: str  # a WEIGHTS key
    value: str  # the shared thing: an ID, a name server, an organisation, an IP
    detail: str

    @property
    def weight(self) -> float:
        return WEIGHTS[self.kind]


@dataclass
class Related:
    domain: str
    evidence: list[Evidence] = field(default_factory=list)

    @property
    def confidence(self) -> float:
        # Count each kind of evidence once: three domains on one IP are not three independent proofs.
        best: dict[str, float] = {}
        for e in self.evidence:
            best[e.kind] = max(best.get(e.kind, 0.0), e.weight)
        remaining = 1.0
        for weight in best.values():
            remaining *= 1 - weight
        return round(1 - remaining, 3)

    @property
    def attribution(self) -> str:
        return "likely the same organisation" if self.confidence >= LIKELY else "possibly related"


def extract_trackers(html: str) -> dict[str, str]:
    """{id: product} for analytics/ads/tag identifiers found in a page."""
    found: dict[str, str] = {}
    for product, pattern in TRACKER_PATTERNS.items():
        for match in pattern.finditer(html):
            found.setdefault(match.group(1), product)
    return found


def is_generic_ns(host: str) -> bool:
    h = host.lower().rstrip(".")
    return any(g in h for g in GENERIC_NS)


def is_generic_org(org: str) -> bool:
    o = org.strip().lower()
    return not o or o in GENERIC_CERT_ORGS or len(o) < 3


_DOMAIN = re.compile(r"(?<![\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})(?![\w-])", re.I)


def domains_in(text: str) -> list[str]:
    """Domain names in a free-text API answer (one per line, CSV, or prose)."""
    return list(dict.fromkeys(m.group(1).lower().rstrip(".") for m in _DOMAIN.finditer(text)))


def combine(items: Iterable[tuple[str, Evidence]], exclude: set[str]) -> list[Related]:
    """Group evidence by domain, drop excluded names, keep those at or above the minimum confidence."""
    grouped: dict[str, Related] = {}
    for domain, evidence in items:
        if domain in exclude:
            continue
        grouped.setdefault(domain, Related(domain)).evidence.append(evidence)
    kept = [r for r in grouped.values() if r.confidence >= MINIMUM]
    return sorted(kept, key=lambda r: (-r.confidence, r.domain))


VISUAL = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"))


def _visual(text: str) -> str:
    """Undo common look-alike substitutions: 'acrne' and 'acm3' both read as 'acme'."""
    for fake, real in VISUAL:
        text = text.replace(fake, real)
    return text


def _distance(a: str, b: str) -> int:
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def looks_like_brand(domain_label: str, brand: str) -> bool:
    """Does a domain's label imitate the brand? (Contains it, or a part of it is a near-miss or look-alike.)"""
    label, b = _visual(domain_label.lower()), _visual(brand.lower())
    if len(b) >= 4 and (b in label or b.replace("-", "") in label.replace("-", "")):
        return True
    allowed = 1 if len(b) < 6 else 2
    parts = [label, *label.split("-")]
    return any(abs(len(p) - len(b)) <= allowed and _distance(p, b) <= allowed for p in parts if p)
