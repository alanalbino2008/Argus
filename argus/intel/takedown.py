"""Takedown requests: report a lookalike domain to the companies that can switch it off.

Two companies can take a phishing domain down: its **registrar** (who can suspend the name) and its
**host** (who can remove the site). Both publish an abuse contact in RDAP, the successor of WHOIS:

* the domain's RDAP record names the registrar, its IANA id, and the registrar's abuse email;
* each address's RDAP record names the network's owner and its abuse email.

Argus looks them up (RDAP goes to the registries, never to the lookalike), then drafts one abuse
report with the evidence triage found: when the domain got its first certificate, what it imitates,
whether it copies the brand's site and asks for a password, and where it is hosted. **Argus does not
send it**: the analyst sends it from their own mailbox (abuse desks answer people, and reply to the
sender), then marks it reported. Argus keeps checking the domain and records when it goes down.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

import aiohttp

from argus.modules.infrastructure.network_ranges import rdap_network

RDAP = "https://rdap.org"
HEADERS = {"Accept": "application/rdap+json, application/json"}
MAX_HOSTS = 3  # addresses looked up per domain
STATUSES = ("drafted", "reported", "down", "closed")


def _vcard(entity: dict[str, Any], field: str) -> str | None:
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == field and item[3]:
            value = str(item[3])
            return value.removeprefix("tel:") if field == "tel" else value
    return None


def parse_domain_rdap(data: dict[str, Any]) -> dict[str, Any]:
    """Registrar, its IANA id and abuse contact, the domain's dates and status, from an RDAP domain answer."""
    out: dict[str, Any] = {"statuses": list(data.get("status") or [])}
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events") or [] if isinstance(e, dict)}
    out["registered"], out["expires"] = events.get("registration"), events.get("expiration")
    stack = [(e, False) for e in data.get("entities") or []]
    while stack:
        entity, under_registrar = stack.pop(0)
        roles = set(entity.get("roles") or [])
        if "registrar" in roles:
            out.setdefault("registrar", _vcard(entity, "fn"))
            iana = next(
                (p.get("identifier") for p in entity.get("publicIds") or [] if "IANA" in str(p.get("type"))), None
            )
            if iana:
                out.setdefault("registrar_iana_id", str(iana))
        if "abuse" in roles and (under_registrar or "abuse_email" not in out):
            email = _vcard(entity, "email")
            if email:
                out["abuse_email"] = email
                out["abuse_phone"] = _vcard(entity, "tel")
        stack.extend((e, under_registrar or "registrar" in roles) for e in entity.get("entities") or [])
    return {k: v for k, v in out.items() if v}


async def _rdap(http: Any, path: str) -> dict[str, Any] | None:
    try:
        async with http.get(f"{RDAP}/{path}", headers=HEADERS, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status != 200:
                return None
            data = await resp.json(content_type=None)
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


async def contacts(http: Any, domain: str, ips: list[str]) -> dict[str, Any]:
    """Who to report ``domain`` to: its registrar and the networks hosting ``ips``."""
    registrar = parse_domain_rdap(await _rdap(http, f"domain/{domain}") or {})
    hosts = []
    for ip in ips[:MAX_HOSTS]:
        try:
            if not ipaddress.ip_address(ip).is_global:
                continue
        except ValueError:
            continue
        network = rdap_network(await _rdap(http, f"ip/{ip}") or {})
        hosts.append({"ip": ip, "network": network.get("registered_to") or network.get("name"),
                      "abuse_email": network.get("abuse_contact")})  # fmt: skip
    return {"registrar": registrar, "hosts": hosts}


def recipients(found: dict[str, Any]) -> list[str]:
    emails = [found.get("registrar", {}).get("abuse_email")] + [h.get("abuse_email") for h in found.get("hosts") or []]
    return list(dict.fromkeys(e.lower() for e in emails if e))


def draft(
    *, domain: str, display: str, brand: str, finding: dict[str, Any], triage: dict[str, Any] | None,
    found: dict[str, Any], organisation: str,
) -> dict[str, Any]:  # fmt: skip
    """The abuse report: recipients, subject and body (plain text, for any mail client)."""
    triage = triage or {}
    web = triage.get("web") or {}
    dns = triage.get("dns") or {}
    verdict = triage.get("verdict") or finding.get("verdict") or ""
    what = {"phishing": "a phishing page impersonating", "clone": "a copy of the website of",
            "mail": "a domain set up to send email impersonating"}.get(verdict, "a domain impersonating")  # fmt: skip
    shown = f"{display} ({domain})" if display != domain else domain
    lines = [
        "Hello,",
        "",
        (
            f"We are reporting {shown}, {what} {organisation}, whose official domain is {brand}. "
            if organisation
            else f"We are reporting {shown}, {what} {brand}. "
        )
        + "It is not ours and was registered without our permission. We ask you to "
        + ("suspend the domain." if not found.get("hosts") else "suspend the domain and remove the content it hosts."),
        "",
        "Evidence:",
        f"- Imitation: {finding.get('technique') or 'lookalike'} ({finding.get('detail') or 'resembles our name'}).",
    ]
    if finding.get("not_before"):
        lines.append(f"- First certificate: issued {str(finding['not_before'])[:10]}"
                     + (f" by {finding['issuer']}" if finding.get("issuer") else "")
                     + (f"; {finding['link']}" if finding.get("link") else "") + ".")  # fmt: skip
    lines.extend(f"- {reason}." for reason in triage.get("reasons") or [] if reason != "Resolves")
    if web.get("title"):
        lines.append(f"- Page title: “{web['title']}” (https://{web.get('final_host') or domain}/).")
    if dns.get("ips"):
        lines.append(f"- Addresses: {', '.join(dns['ips'][:5])}.")
    if dns.get("mx"):
        lines.append(f"- Mail servers: {', '.join(dns['mx'][:5])}.")
    hosts = finding.get("hosts") or []
    if len(hosts) > 1:
        lines.append(f"- Host names on its certificates: {', '.join(hosts[:8])}.")
    registrar = found.get("registrar") or {}
    if registrar.get("registrar"):
        lines.append(f"- Registrar: {registrar['registrar']}"
                     + (f" (IANA {registrar['registrar_iana_id']})" if registrar.get("registrar_iana_id") else "")
                     + (f"; registered {str(registrar['registered'])[:10]}" if registrar.get("registered") else "") + ".")  # fmt: skip
    lines.extend(
        f"- Hosting network for {h['ip']}: {h['network']}." for h in found.get("hosts") or [] if h.get("network")
    )
    lines += [
        "",
        "Please let us know what action you take. Thank you.",
        "",
        organisation or "[Your name, organisation and how to reach you]",
    ]
    subject = f"Abuse report: {domain} impersonates {brand}" + (" (phishing)" if verdict == "phishing" else "")
    return {"to": recipients(found), "subject": subject, "body": "\n".join(lines)}


def went_down(triage: dict[str, Any], web_checked: bool, previous_misses: int) -> tuple[bool, int]:
    """(down, misses): down when the name stops resolving, or the website has been gone on two runs."""
    if triage.get("verdict") == "dormant":
        return True, previous_misses + 1
    web = triage.get("web")
    if web_checked and web is not None:
        gone = not web.get("reachable") or (web.get("status") or 0) in (404, 410, 451)
        misses = previous_misses + 1 if gone else 0
        return misses >= 2, misses
    return False, 0
