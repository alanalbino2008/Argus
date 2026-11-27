"""Breach and dark-web exposure: what the sources report, turned into findings with a severity.

Four kinds of finding, from four kinds of evidence:

| Kind | Evidence | Severity |
|---|---|---|
| ``stealer_log`` | an employee's credentials captured by infostealer malware | critical |
| ``ransomware_post`` | the organisation (or a supplier) named on a ransomware group's leak site | critical (recent, matched by domain), high (by name only), medium (older than a year) |
| ``breach_account`` | an employee's address in a data breach | high (passwords, added in the last year), medium (passwords, older), low (no passwords) |
| ``domain_breach`` | the organisation (or a supplier) was itself the breached company | high (added in the last year), medium (older) |

**Ethics and data minimisation.** Only metadata is ever collected: which account, which breach,
which data classes, when. No passwords, cookies or leaked files, and nothing is fetched from
criminal infrastructure: ransomware leak sites are read through a public research feed that
indexes them. Staff addresses are personal data (UK GDPR), so they are masked everywhere by
default; revealing or exporting them is a separate, audited action for analysts.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
RECENT = timedelta(days=365)
PASSWORD_CLASSES = {"passwords", "password hints", "auth tokens", "historical passwords"}
KINDS = ("stealer_log", "ransomware_post", "domain_breach", "breach_account", "darkweb_mention", "paste_leak")
KIND_LABEL = {
    "stealer_log": "infostealer infection",
    "ransomware_post": "ransomware leak-site post",
    "domain_breach": "breach of the organisation",
    "breach_account": "breached staff account",
    "darkweb_mention": "dark-web index mention",
    "paste_leak": "paste / leak-forum post",
}
# Words that turn a bare mention into a likely leak (raise the severity).
LEAK_TERMS = (
    "dump", "combolist", "combo", "database", "db leak", "leaked", "leak", "breach", "fullz", "cvv",
    "credential", "password", "stealer", "logs", "rdp", "accounts", "base", "sql", "exfil", "0day",
)  # fmt: skip
_LEGAL_SUFFIX = re.compile(
    r"\b(inc|incorporated|ltd|limited|llc|plc|gmbh|ag|sa|sas|srl|bv|nv|co|corp|corporation|company|group|holdings?)\b\.?"
)


@dataclass
class Finding:
    """One piece of exposure, identified by a stable ``key`` so a re-check never duplicates it."""

    key: str
    kind: str
    severity: str
    title: str
    subject: str  # the domain it concerns
    account: str | None = None  # an email address (personal data: masked unless revealed)
    occurred_at: str | None = None  # when it happened (breach date, post date), if known
    details: dict[str, Any] = field(default_factory=dict)


def parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip().replace(" ", "T", 1)
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            moment = datetime.fromisoformat(text[:10])
        except ValueError:
            return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def recent(value: Any, now: datetime) -> bool:
    moment = parse_time(value)
    return moment is not None and now - moment <= RECENT


def mask_email(email: str) -> str:
    """'alice.smith@acme.com' -> 'a•••h@acme.com': enough to recognise, not to identify."""
    local, _, domain = email.partition("@")
    if not domain:
        return "•••"
    shown = f"{local[0]}•••{local[-1]}" if len(local) > 2 else f"{local[:1]}•••"
    return f"{shown}@{domain}"


def normalise_name(name: str) -> str:
    text = re.sub(r"[^a-z0-9 ]+", " ", name.lower())
    return re.sub(r"\s+", " ", _LEGAL_SUFFIX.sub(" ", text)).strip()


def host_of(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    host = urlsplit(text if "://" in text else f"//{text}").hostname or ""
    return host.removeprefix("www.").rstrip(".")


def same_organisation_domain(host: str, domain: str) -> bool:
    return bool(host) and (host == domain or host.endswith(f".{domain}"))


# ---------------------------------------------------------------------------- severity rules
def breach_severity(meta: dict[str, Any], now: datetime) -> str:
    classes = {str(c).lower() for c in meta.get("DataClasses") or []}
    if meta.get("IsSpamList"):
        return "low"
    if classes & PASSWORD_CLASSES:
        return "high" if recent(meta.get("AddedDate") or meta.get("BreachDate"), now) else "medium"
    return "low"


def breach_summary(meta: dict[str, Any]) -> dict[str, Any]:
    return {
        "breach": meta.get("Name"),
        "breach_title": meta.get("Title") or meta.get("Name"),
        "breach_date": meta.get("BreachDate"),
        "added_date": meta.get("AddedDate"),
        "data_classes": list(meta.get("DataClasses") or [])[:20],
        "verified": bool(meta.get("IsVerified")),
        "breached_domain": meta.get("Domain") or None,
        "pwn_count": meta.get("PwnCount"),
    }


# ---------------------------------------------------------------------------- findings from sources
def account_findings(
    domain: str, accounts: dict[str, list[str]], catalogue: dict[str, dict[str, Any]], now: datetime
) -> list[Finding]:
    """HIBP domain search: ``{"alias": ["Breach1", ...]}`` for addresses at ``domain``."""
    findings = []
    for alias, breaches in accounts.items():
        email = f"{alias.strip().lower()}@{domain}"
        for name in breaches:
            meta = catalogue.get(name, {"Name": name})
            severity = breach_severity(meta, now)
            findings.append(Finding(
                key=f"ba:{domain}:{email}:{name}", kind="breach_account", severity=severity,
                title=f"Staff account exposed in the {meta.get('Title') or name} breach", subject=domain,
                account=email, occurred_at=meta.get("BreachDate"), details=breach_summary(meta),
            ))  # fmt: skip
    return findings


def stealer_findings(domain: str, infections: dict[str, list[str]]) -> list[Finding]:
    """HIBP stealer logs: ``{"alias": ["website.com", ...]}``: where the stolen credentials work."""
    findings = []
    for alias, websites in infections.items():
        email = f"{alias.strip().lower()}@{domain}"
        sites = sorted({host_of(w) or str(w) for w in websites})[:50]
        findings.append(Finding(
            key=f"sl:{domain}:{email}", kind="stealer_log", severity="critical",
            title="Staff credentials captured by infostealer malware", subject=domain, account=email,
            details={"websites": sites, "website_count": len(sites)},
        ))  # fmt: skip
    return findings


def email_stealer_findings(email: str, sites: list[str]) -> list[Finding]:
    """One infostealer finding for an email selector: the sites its captured credentials unlock."""
    clean = sorted({host_of(s) or str(s) for s in sites if s})[:50]
    if not clean:
        return []
    return [Finding(
        key=f"sl:{email.lower()}", kind="stealer_log", severity="critical",
        title="Credentials captured by infostealer malware", subject=email, account=email,
        details={"websites": clean, "website_count": len(clean)},
    )]  # fmt: skip


def domain_breach_findings(
    domain: str, catalogue: dict[str, dict[str, Any]], now: datetime, *, subject_name: str | None = None
) -> list[Finding]:
    """Breaches of the organisation itself: catalogue entries whose breached site is ``domain``."""
    findings = []
    for meta in catalogue.values():
        if not same_organisation_domain(host_of(meta.get("Domain")), domain):
            continue
        severity = "high" if recent(meta.get("AddedDate") or meta.get("BreachDate"), now) else "medium"
        findings.append(Finding(
            key=f"db:{domain}:{meta.get('Name')}", kind="domain_breach", severity=severity,
            title=f"{subject_name or domain} was breached: {meta.get('Title') or meta.get('Name')}",
            subject=domain, occurred_at=meta.get("BreachDate"), details=breach_summary(meta),
        ))  # fmt: skip
    return findings


def _victim_fields(post: dict[str, Any]) -> dict[str, Any]:
    """Ransomware feed records vary between versions: read the fields tolerantly."""
    return {
        "victim": str(post.get("victim") or post.get("post_title") or post.get("name") or "").strip(),
        "group": str(post.get("group") or post.get("group_name") or "unknown").strip(),
        "website": post.get("domain") or post.get("website") or post.get("url") or "",
        "published": post.get("discovered") or post.get("published") or post.get("date") or post.get("attackdate"),
        "attack_date": post.get("attackdate") or post.get("attack_date"),
        "country": post.get("country") or None,
        "sector": post.get("activity") or post.get("sector") or None,
        "id": post.get("id") or post.get("post_url") or None,
    }


def ransomware_findings(
    domain: str, posts: list[dict[str, Any]], now: datetime, *, names: tuple[str, ...] = ()
) -> list[Finding]:
    """Leak-site posts naming the organisation: matched by domain, or (less certainly) by exact name."""
    wanted = {normalise_name(n) for n in names if normalise_name(n)}
    findings, seen = [], set()
    for post in posts:
        if not isinstance(post, dict):
            continue
        f = _victim_fields(post)
        by_domain = same_organisation_domain(host_of(f["website"]), domain) or same_organisation_domain(
            host_of(f["victim"]), domain
        )
        by_name = not by_domain and bool(wanted) and normalise_name(f["victim"]) in wanted
        if not (by_domain or by_name):
            continue
        key = f"rw:{domain}:{normalise_name(f['group'])}:{normalise_name(f['victim'])}:{str(f['published'])[:10]}"
        if key in seen:
            continue
        seen.add(key)
        severity = ("critical" if by_domain else "high") if recent(f["published"], now) else "medium"
        findings.append(Finding(
            key=key, kind="ransomware_post", severity=severity,
            title=f"Named on the {f['group']} ransomware leak site" + ("" if by_domain else " (matched by name)"),
            subject=domain, occurred_at=str(f["published"])[:10] if f["published"] else None,
            details={**f, "match": "domain" if by_domain else "name"},
        ))  # fmt: skip
    return findings


# ---------------------------------------------------------------------------- dark web & pastes
def _leak_signal(*texts: str) -> bool:
    """Does any text read like a credential leak rather than a passing mention?"""
    blob = " ".join(t.lower() for t in texts if t)
    return any(re.search(rf"\b{re.escape(term)}\b", blob) for term in LEAK_TERMS)


def _mention_severity(selector: str, texts: tuple[str, ...], when: Any, now: datetime) -> str:
    """Conservative: a bare mention is low; leak-looking or recent raises it."""
    leak = _leak_signal(*texts)
    fresh = recent(when, now)
    if leak and fresh:
        return "high"
    if leak or fresh:
        return "medium"
    return "low"


def darkweb_findings(selector: str, hits: list[dict[str, Any]], now: datetime) -> list[Finding]:
    """Onion-index listings mentioning the selector (read from the clearnet index, never the onion)."""
    findings, seen = [], set()
    for h in hits:
        if not isinstance(h, dict):
            continue
        onion, title, snippet = str(h.get("onion") or ""), str(h.get("title") or ""), str(h.get("snippet") or "")
        when = h.get("date")
        # The listing's identity is its onion address. Not its date: an index reports when it last crawled a
        # page, which moves on every crawl and would re-announce the same listing as new each time.
        key = f"dw:{selector.lower()}:{onion}" if onion else f"dw:{selector.lower()}:{title}:{str(when or '')[:10]}"
        if key in seen:
            continue
        seen.add(key)
        severity = _mention_severity(selector, (title, snippet), when, now)
        findings.append(Finding(
            key=key, kind="darkweb_mention", severity=severity,
            title=f"“{selector}” on a dark-web site: {title[:120]}" if title else f"“{selector}” on a dark-web site",
            subject=selector, occurred_at=str(when)[:10] if when else None,
            details={"onion": onion[:300], "is_onion": bool(h.get("is_onion")), "snippet": snippet[:500],
                     "source": str(h.get("source") or "dark-web index")[:60], "leak_signal": _leak_signal(title, snippet)},
        ))  # fmt: skip
    return findings


def paste_findings(selector: str, hits: list[dict[str, Any]], now: datetime) -> list[Finding]:
    """Paste-site and leak-forum posts mentioning the selector."""
    findings, seen = [], set()
    for h in hits:
        if not isinstance(h, dict):
            continue
        url, title, snippet = str(h.get("url") or ""), str(h.get("title") or ""), str(h.get("snippet") or "")
        when = h.get("date")
        key = f"pl:{selector.lower()}:{url}" if url else f"pl:{selector.lower()}:{title}:{str(when or '')[:10]}"
        if key in seen:
            continue
        seen.add(key)
        severity = _mention_severity(selector, (title, snippet), when, now)
        findings.append(Finding(
            key=key, kind="paste_leak", severity=severity,
            title=f"“{selector}” in a paste/leak-forum post: {title[:120]}" if title else f"“{selector}” in a paste",
            subject=selector, occurred_at=str(when)[:10] if when else None,
            details={"url": url[:300], "snippet": snippet[:500], "source": str(h.get("source") or "paste site")[:60],
                     "leak_signal": _leak_signal(title, snippet)},
        ))  # fmt: skip
    return findings


# ---------------------------------------------------------------------------- reporting
def worst(severities: list[str]) -> str:
    return max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0)) if severities else "low"


def headline(domain: str, new: list[dict[str, Any]], *, baseline: bool, subject_name: str | None = None) -> str:
    """One line for an alert about the new findings of one check."""
    by_kind: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in new:
        by_kind[f["kind"]].append(f)
    who = subject_name or domain
    parts = []
    if by_kind["ransomware_post"]:
        groups = sorted({f["details"].get("group", "?") for f in by_kind["ransomware_post"]})
        parts.append(f"named on the {', '.join(groups)} ransomware leak site")
    if by_kind["stealer_log"]:
        n = len(by_kind["stealer_log"])
        parts.append(f"{n} staff account{'s' if n != 1 else ''} in infostealer logs")
    if by_kind["domain_breach"]:
        titles = sorted({f["details"].get("breach_title", "?") for f in by_kind["domain_breach"]})
        parts.append(f"breached ({', '.join(titles[:3])})")
    if by_kind["breach_account"]:
        accounts = {f.get("account") for f in by_kind["breach_account"]}
        breaches = sorted({f["details"].get("breach_title", "?") for f in by_kind["breach_account"]})
        parts.append(f"{len(accounts)} staff account{'s' if len(accounts) != 1 else ''} in "
                     f"{'a new breach' if len(breaches) == 1 else f'{len(breaches)} breaches'} ({', '.join(breaches[:3])})")  # fmt: skip
    if by_kind["darkweb_mention"]:
        n = len(by_kind["darkweb_mention"])
        parts.append(f"{n} dark-web site mention{'s' if n != 1 else ''}")
    if by_kind["paste_leak"]:
        n = len(by_kind["paste_leak"])
        parts.append(f"{n} paste/leak-forum post{'s' if n != 1 else ''}")
    prefix = "First exposure check" if baseline else "New exposure"
    return f"{prefix} for {who}: " + "; ".join(parts)


def summarise(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts for the page and for alerts (open findings only)."""
    open_ = [f for f in findings if f["status"] == "open"]
    return {
        "open": len(open_),
        "by_kind": {k: sum(1 for f in open_ if f["kind"] == k) for k in KINDS},
        "by_severity": {s: sum(1 for f in open_ if f["severity"] == s) for s in ("critical", "high", "medium", "low")},
        "accounts": len({f["account"] for f in open_ if f.get("account")}),
    }


# ---------------------------------------------------------------------------- demonstration data
def demo_findings(domain: str, now: datetime) -> list[Finding]:
    """Fictional exposure for the demo organisation, built by the same rules as real checks.

    Every name is invented and the domain is a reserved ``.example`` one, so nothing here
    describes a real person, breach or ransomware victim.
    """
    day = timedelta(days=1)
    catalogue = {
        "ExampleCRM": {"Name": "ExampleCRM", "Title": "ExampleCRM", "BreachDate": (now - 40 * day).date().isoformat(),
                       "AddedDate": (now - 20 * day).isoformat(), "IsVerified": True, "PwnCount": 1_200_000,
                       "DataClasses": ["Email addresses", "Passwords", "Names"]},
        "DemoForum": {"Name": "DemoForum", "Title": "Demo Forum", "BreachDate": "2019-06-01",
                      "AddedDate": "2020-02-11T00:00:00Z", "IsVerified": True, "PwnCount": 300_000,
                      "DataClasses": ["Email addresses", "Passwords", "Usernames"]},
        "SampleShop": {"Name": "SampleShop", "Title": "Sample Shop", "BreachDate": "2023-03-14",
                       "AddedDate": "2023-05-02T00:00:00Z", "IsVerified": True, "PwnCount": 2_400_000,
                       "DataClasses": ["Email addresses", "Phone numbers", "Physical addresses"]},
    }  # fmt: skip
    accounts = {
        "j.doe": ["ExampleCRM", "DemoForum"], "finance": ["ExampleCRM"], "a.morgan": ["SampleShop"],
        "it-helpdesk": ["DemoForum"], "s.patel": ["SampleShop", "ExampleCRM"],
    }  # fmt: skip
    infections = {"r.chen": ["vpn.acme-corp.example", "login.example-saas.example", "mail.acme-corp.example"]}
    posts = [{"victim": domain, "group": "demolocker", "discovered": (now - 3 * day).isoformat(),
              "country": "GB", "activity": "Manufacturing", "id": "demo-post-1"}]  # fmt: skip
    return (
        stealer_findings(domain, infections)
        + ransomware_findings(domain, posts, now)
        + account_findings(domain, accounts, catalogue, now)
    )
