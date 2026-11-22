"""Lookalike triage: which lookalike domains are a threat now, and which are noise.

A certificate for ``acme-login.com`` says someone *can* run a site there. Triage says what is there:

**DNS (passive; always).** Asked of public resolvers, never of the lookalike's own servers:

* does it **resolve** at all (a certificate for a name with no address is a dormant registration);
* can it **send and receive email** (an MX record: a ready-made phishing sender);
* is it **yours**: sharing the real domain's name servers or addresses means a defensive registration;
* is it **parked**: name servers of parking and resale services suggest a speculator, for now.

**Web (opt-in; direct or through an anonymising route).** Visiting the site tells its operator
someone looked, from which address. When the watch allows it, Argus fetches the home page once and
records the status, the final address, the page title, whether it shows a **password field**, and its
favicon. It then compares them with the brand's own site: the **same favicon** or the **brand's
title** on someone else's domain is a clone; a clone with a password field is an **active phishing
page**.

The verdict sets the severity: active phishing is critical; a clone, or a mail-capable lookalike with
a sensitive word, is high; parked and dormant names are low; defensive registrations are not reported.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

import aiohttp
import dns.asyncresolver
import dns.exception
import dns.resolver

from argus.intel.favicon import MAX_ICON_BYTES, icon_links, sniff_image
from argus.intel.lookalikes import registrable

PARKING_NS = (
    "sedoparking.com", "parkingcrew.net", "bodis.com", "above.com", "dan.com", "afternic.com", "parklogic.com",
    "uniregistrymarket.link", "namebrightdns.com", "hugedomains.com", "domaincontrol.com.parked",
    "dsredirection.com", "parking.reg.ru", "fabulous.com", "smartname.com", "cashparking.com", "voodoo.com",
)  # fmt: skip
MAX_PAGE_BYTES = 512 * 1024
WEB_TIMEOUT = 20.0
PASSWORD_FIELD = re.compile(r"<input\b[^>]*\btype\s*=\s*['\"]?password", re.IGNORECASE)
TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
VERDICT_LABELS = {
    "phishing": "Active phishing page",
    "clone": "Copies your site",
    "mail": "Can send email",
    "live": "Live website",
    "suspicious": "Registered",
    "parked": "Parked",
    "dormant": "Not resolving",
    "yours": "Yours (defensive)",
}


def parent_domain(host: str) -> str:
    try:
        return registrable(host.rstrip("."))
    except ValueError:
        return host.rstrip(".").lower()


# DNS and hosting providers that serve millions of unrelated domains: sharing them with the brand
# proves nothing (a phishing site on Cloudflare shares the brand's Cloudflare name servers and
# anycast addresses), so they never mark a lookalike as the brand's own.
SHARED_DNS = (
    "cloudflare.com", "azure-dns.com", "azure-dns.net", "azure-dns.org", "azure-dns.info", "googledomains.com",
    "google.com", "domaincontrol.com", "registrar-servers.com", "nsone.net", "ultradns.com", "ultradns.net",
    "ultradns.org", "ultradns.biz", "dnsmadeeasy.com", "akam.net", "dynect.net", "wixdns.net", "squarespacedns.com",
    "digitalocean.com", "linode.com", "vercel-dns.com", "netlify.com", "hostinger.com", "name-services.com",
    "dns.com", "he.net", "gandi.net", "ovh.net", "hetzner.com", "namecheaphosting.com", "bluehost.com",
    "hostgator.com", "dreamhost.com", "porkbun.com", "afraid.org", "cloudns.net", "dnsimple.com", "route53.com",
)  # fmt: skip


def shared_provider(ns_parent: str) -> bool:
    return ns_parent in SHARED_DNS or ns_parent.startswith("awsdns-")


def dns_verdict(profile: dict[str, Any], own_ns: set[str], own_ips: set[str]) -> str:
    """'yours', 'parked' or 'suspicious' for a domain that exists (``profile`` from :func:`dns_profile`).

    *Yours* needs evidence a stranger could not copy: the brand's own name servers (not a shared DNS
    provider's), or its addresses when its name servers are its own (behind a shared provider, an
    address is likely a CDN's, shared with anyone)."""
    ns_parents = {parent_domain(n) for n in profile.get("ns") or []}
    own_private_ns = {n for n in own_ns if not shared_provider(n)}
    shares_ns = bool(ns_parents & own_private_ns)
    shares_ip = bool(own_ips and own_ips & set(profile.get("ips") or []))
    if shares_ns or (shares_ip and (own_private_ns or not own_ns)):
        return "yours"
    if any(n.endswith(p) or p.endswith(n) for n in ns_parents for p in PARKING_NS):
        return "parked"
    return "suspicious"


# ----------------------------------------------------------------------------- DNS
async def _resolve(resolver: Any, name: str, rtype: str) -> tuple[str, list[str]]:
    try:
        answers = await resolver.resolve(name, rtype)
        return "ok", [str(r.to_text()).rstrip(".").lower() for r in answers]
    except dns.resolver.NXDOMAIN:
        return "nx", []
    except dns.resolver.NoAnswer:
        return "none", []
    except (dns.exception.DNSException, OSError):
        return "error", []


async def dns_profile(name: str, resolver: Any | None = None) -> dict[str, Any] | None:
    """{'ips', 'ns', 'mx'} when ``name`` exists, None when it does not (or DNS failed)."""
    if resolver is None:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 6.0
    status, ips = await _resolve(resolver, name, "A")
    if status in ("nx", "error"):
        return None
    _, ns = await _resolve(resolver, name, "NS")
    if status == "none" and not ns:
        return None
    _, mx = await _resolve(resolver, name, "MX")
    mx_hosts = [m.split()[-1] for m in mx if m.split()[-1] not in ("", ".")]
    return {"ips": ips[:8], "ns": ns[:6], "mx": mx_hosts[:6]}


# ----------------------------------------------------------------------------- web
@dataclass
class WebProfile:
    reachable: bool
    status: int | None = None
    final_host: str = ""
    title: str = ""
    login_form: bool = False
    favicon_sha256: str = ""
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in ("reachable", "status", "final_host", "title", "login_form",
                                              "favicon_sha256", "error")}  # fmt: skip


async def _read(resp: Any, limit: int) -> bytes:
    data = b""
    async for chunk in resp.content.iter_chunked(64 * 1024):
        data += chunk
        if len(data) >= limit:
            break
    return data[:limit]


async def web_profile(http: Any, name: str) -> WebProfile:
    """Fetch the home page (HTTPS, then HTTP) and its favicon, once each."""
    timeout = aiohttp.ClientTimeout(total=WEB_TIMEOUT)
    last_error = ""
    for scheme in ("https", "http"):
        url = f"{scheme}://{name}/"
        try:
            async with http.get(url, timeout=timeout, allow_redirects=True) as resp:
                body = await _read(resp, MAX_PAGE_BYTES)
                final = str(resp.url)
                status = resp.status
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError) as exc:
            last_error = type(exc).__name__
            continue
        html = body.decode("utf-8", errors="replace")
        title_match = TITLE.search(html[:200_000])
        title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:200] if title_match else ""
        profile = WebProfile(True, status, urlsplit(final).hostname or "", title, bool(PASSWORD_FIELD.search(html)))
        icons = icon_links(html) or ["/favicon.ico"]
        try:
            async with http.get(urljoin(final, icons[0]), timeout=timeout) as icon_resp:
                icon = await _read(icon_resp, MAX_ICON_BYTES + 1)
            if icon_resp.status == 200 and sniff_image(icon) and len(icon) <= MAX_ICON_BYTES:
                profile.favicon_sha256 = hashlib.sha256(icon).hexdigest()
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError):
            pass
        return profile
    return WebProfile(False, error=last_error or "unreachable")


# ----------------------------------------------------------------------------- judgement
@dataclass
class Triage:
    verdict: str
    severity: str
    reasons: list[str] = field(default_factory=list)
    dns: dict[str, Any] | None = None
    web: dict[str, Any] | None = None

    def as_dict(self, checked_at: str) -> dict[str, Any]:
        return {"verdict": self.verdict, "label": VERDICT_LABELS[self.verdict], "severity": self.severity,
                "reasons": self.reasons, "dns": self.dns, "web": self.web, "checked_at": checked_at}  # fmt: skip


def _raise(severity: str, floor: str) -> str:
    return floor if SEVERITY_ORDER[floor] > SEVERITY_ORDER[severity] else severity


def _cap(severity: str, ceiling: str) -> str:
    return ceiling if SEVERITY_ORDER[severity] > SEVERITY_ORDER[ceiling] else severity


def judge(
    base_severity: str, brand: str, dns_info: dict[str, Any] | None, own: dict[str, Any],
    web: WebProfile | None, *, sensitive: bool,
) -> Triage:  # fmt: skip
    """The verdict for one lookalike. ``base_severity`` comes from how its name imitates the brand;
    ``own`` holds the brand's own name servers, addresses, page title and favicon."""
    if dns_info is None:
        return Triage("dormant", _cap(base_severity, "medium"), ["Does not resolve: registered, not (yet) in use"])
    verdict = dns_verdict(dns_info, own.get("ns") or set(), own.get("ips") or set())
    if verdict == "yours":
        return Triage("yours", "low", ["Shares your name servers or addresses: a defensive registration"], dns_info)
    reasons: list[str] = []
    severity = base_severity
    if dns_info.get("mx"):
        reasons.append("Has mail servers (MX): it can send and receive email")
        severity = _raise(severity, "high" if sensitive else "medium")
    result = "mail" if dns_info.get("mx") else "suspicious"
    if verdict == "parked":
        reasons.append("Parking or resale name servers")
        return Triage("parked", _cap(severity, "medium" if dns_info.get("mx") else "low"), reasons, dns_info)
    if web is not None and web.reachable and (web.status or 0) < 500:
        same_icon = bool(web.favicon_sha256 and web.favicon_sha256 == own.get("favicon_sha256"))
        own_title = (own.get("title") or "").strip().lower()
        title = web.title.lower()
        brand_title = bool(title and ((own_title and own_title == title) or brand in re.sub(r"[^a-z0-9]", "", title)))
        if same_icon:
            reasons.append("Serves your favicon")
        if brand_title:
            reasons.append(f"Page title imitates you: “{web.title}”")
        if web.login_form:
            reasons.append("Shows a password field")
        if (same_icon or brand_title) and web.login_form:
            return Triage("phishing", "critical", reasons, dns_info, web.as_dict())
        if same_icon or brand_title:
            return Triage("clone", _raise(severity, "high"), reasons, dns_info, web.as_dict())
        reasons.append(f"Website answers ({web.status})")
        return Triage("live" if result == "suspicious" else result, severity, reasons, dns_info, web.as_dict())
    if web is not None:
        reasons.append(f"Website did not answer ({web.error or web.status})" if not web.reachable
                       else f"Website error ({web.status})")  # fmt: skip
    if not reasons:
        reasons.append("Resolves")
    return Triage(result, severity, reasons, dns_info, web.as_dict() if web else None)
