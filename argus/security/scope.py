"""Is this a sensible target? Guidance shown *before* a scan starts.

Argus already **blocks** what must never be scanned from a server (private, loopback and
cloud-metadata addresses; see ``network.py``). This module adds **judgement**: targets that
are technically reachable but legally or ethically sensitive. It warns rather than blocks,
because authorised testers legitimately assess government sites, large companies (via bug
bounty programmes) and their own staff. The warning codes are recorded in the audit log with
the scan, so it is always visible that the person was told.

In the UK, unauthorised access to computer material is an offence under the Computer Misuse
Act 1990; investigating an individual processes personal data under UK GDPR. Passive OSINT
is lower-risk than active testing, but the right habit is the same: have permission first.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from argus.core.models import EntityType

PUBLIC_SECTOR_SUFFIXES = (
    ".gov", ".mil", ".gov.uk", ".mod.uk", ".police.uk", ".nhs.uk", ".nhs.net", ".parliament.uk",
    ".gov.scot", ".gov.wales", ".gc.ca", ".gov.au", ".govt.nz", ".europa.eu", ".int",
)  # fmt: skip
ACADEMIC_SUFFIXES = (".ac.uk", ".edu")
RESERVED_SUFFIXES = (".example", ".test", ".invalid", ".localhost")
RESERVED_NAMES = {"example.com", "example.org", "example.net"}
# Large organisations people often type as a "test": most run bug bounty programmes with a
# written scope, which is the only way to assess them lawfully.
WELL_KNOWN = {
    "google.com", "youtube.com", "gmail.com", "microsoft.com", "live.com", "outlook.com", "office.com",
    "azure.com", "amazon.com", "amazonaws.com", "apple.com", "icloud.com", "facebook.com", "instagram.com",
    "whatsapp.com", "meta.com", "x.com", "twitter.com", "linkedin.com", "github.com", "gitlab.com",
    "cloudflare.com", "akamai.com", "netflix.com", "paypal.com", "ebay.com", "tiktok.com", "reddit.com",
    "wikipedia.org", "yahoo.com", "bbc.co.uk", "adobe.com", "oracle.com", "ibm.com", "salesforce.com",
    "shopify.com", "dropbox.com", "zoom.us", "slack.com", "atlassian.com", "spotify.com", "anthropic.com",
    "openai.com", "tesla.com", "uber.com", "airbnb.com", "booking.com", "hsbc.com", "barclays.co.uk",
}  # fmt: skip
PERSONAL_TYPES = {EntityType.EMAIL, EntityType.USERNAME, EntityType.PHONE, EntityType.PERSON}


@dataclass(frozen=True)
class ScopeWarning:
    code: str
    level: str  # "danger" (needs explicit written permission), "warning", "info"
    title: str
    message: str


def _host(target: str, target_type: EntityType) -> str | None:
    t = target.strip().lower().rstrip(".")
    if target_type == EntityType.EMAIL and "@" in t:
        return t.rsplit("@", 1)[1]
    if target_type in (EntityType.DOMAIN, EntityType.SUBDOMAIN):
        return t
    return None


def _under(host: str, suffixes: tuple[str, ...]) -> bool:
    """``host`` is one of the zones (e.g. nhs.uk itself) or inside one (www.nhs.uk)."""
    return any(host == s.lstrip(".") or host.endswith(s) for s in suffixes)


def _matches(host: str, names: set[str]) -> str | None:
    return next((n for n in names if host == n or host.endswith("." + n)), None)


def assess(target: str, target_type: EntityType, *, passive_only: bool, active_checks: int) -> list[ScopeWarning]:
    warnings: list[ScopeWarning] = []
    host = _host(target, target_type)
    if host:
        if host in RESERVED_NAMES or _under(host, RESERVED_SUFFIXES):
            warnings.append(ScopeWarning(
                "reserved", "info", "A placeholder domain",
                f"{host} is reserved for documentation and examples, so there is little to find. To see what Argus can "
                "do without scanning anything, open the demo.",
            ))  # fmt: skip
        elif _under(host, PUBLIC_SECTOR_SUFFIXES):
            warnings.append(ScopeWarning(
                "public_sector", "danger", "A government or public-sector domain",
                f"{host} belongs to a government, military, police or health organisation. Assess it only with written "
                "authorisation from that organisation (for example an official vulnerability disclosure programme), "
                "and stay within its stated scope.",
            ))  # fmt: skip
        elif match := _matches(host, WELL_KNOWN):
            warnings.append(ScopeWarning(
                "third_party", "danger", "A large organisation's domain",
                f"{match} belongs to a large organisation. Many run bug bounty programmes: assess it only if it is "
                "explicitly in a programme's scope, and follow that programme's rules. Otherwise, choose a domain you own.",
            ))  # fmt: skip
        elif _under(host, ACADEMIC_SUFFIXES):
            warnings.append(ScopeWarning(
                "academic", "warning", "A university or college domain",
                f"{host} is an academic institution. Get permission from its IT security team first, even as a student "
                "there.",
            ))  # fmt: skip
    if target_type in PERSONAL_TYPES:
        warnings.append(ScopeWarning(
            "personal_data", "warning", "Investigating a person",
            "This target identifies an individual, so the results are personal data. You need a lawful basis under "
            "UK GDPR, such as the person's own request or a security engagement that covers the organisation's staff. "
            "Argus pseudonymises people in reports by default.",
        ))  # fmt: skip
    if target_type == EntityType.IP_ADDRESS:
        warnings.append(ScopeWarning(
            "shared_ip", "info", "IP addresses can be shared",
            "Cloud and shared hosting put many unrelated organisations on one address. Make sure this address is "
            "yours, or within the scope you were given.",
        ))  # fmt: skip
    if not passive_only and active_checks:
        warnings.append(ScopeWarning(
            "active_contact", "info", "Some checks contact the target",
            f"{active_checks} check(s) send ordinary single requests to the target's own servers (a TLS handshake, "
            "an HTTP request). Choose passive mode to use public sources only.",
        ))  # fmt: skip
    return warnings


def as_dicts(warnings: list[ScopeWarning]) -> list[dict[str, str]]:
    return [asdict(w) for w in warnings]
