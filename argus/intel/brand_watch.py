"""Brand watch: lookalike domains as soon as they get a certificate.

A phishing site needs HTTPS, and every publicly trusted certificate is published in Certificate
Transparency logs, usually before the site is used. So a certificate for ``acme-login.com`` or
``acrne.com`` is often the first public sign of a campaign against Acme.

Each run asks two Certificate Transparency services:

* **crt.sh, by keyword**: every unexpired certificate whose names contain the brand (``acme-login.net``,
  ``acme.evil.example``…). crt.sh is free and often overloaded; when it fails the run is partial
  and is retried within the hour.
* **Cert Spotter, by name**: the lookalikes a keyword cannot find (typos, look-alike letters,
  Cyrillic homographs encoded as ``xn--``), a few per run from the lookalike generator's list
  (most dangerous first), so every candidate is checked over the days.

Each certificate name is **classified**: the brand's own domains (and the ones the team lists as
its own) are ignored; the rest are matched against the lookalike techniques of
:mod:`argus.intel.lookalikes`. The first successful run records what already exists, and only
alerts on certificates issued in the last 14 days; after that, every new lookalike name is
announced, once per run.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any

import aiohttp

from argus.accounts import features
from argus.core.settings import Settings
from argus.intel import lookalike_triage, visual
from argus.intel.account_watch import client as outbound_client
from argus.intel.lookalike_triage import Triage, judge
from argus.intel.lookalikes import SENSITIVE_WORDS, Candidate, generate, registrable, split_domain
from argus.observability import metrics
from argus.storage.brand_watch_repo import BrandWatchRepository

logger = logging.getLogger("argus.brand_watch")
CRTSH = "https://crt.sh/"
CERTSPOTTER = "https://api.certspotter.com/v1/issuances"
MIN_KEYWORD = 4  # shorter brands ("hp") match too much of the internet to search by keyword
EXACT_PER_RUN = 10  # Cert Spotter look-ups per run without an API key (its free tier is small)
EXACT_PER_RUN_WITH_KEY = 40
CANDIDATES = 400  # lookalikes cycled through by name
MAX_CERTS = 20000  # crt.sh rows read per run
FRESH = timedelta(days=14)  # on the first run, only certificates this recent are news
RETRY = timedelta(hours=1)
VISUAL_PER_RUN = 8  # lookalike pages rendered and compared per run (a browser render takes seconds)
REFERENCES_EVERY = timedelta(days=7)  # the brand's own pages are re-rendered this often
RETRIAGE_PER_RUN = 25  # known lookalikes re-checked per run (oldest check first): parked ones go live later
ALERT_SAMPLE = 20
MAX_HOSTS = 10
POLL_SECONDS = 300.0
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
HOSTNAME = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$")


class SourceFailed(Exception):
    pass


@dataclass(frozen=True)
class Certificate:
    names: tuple[str, ...]
    issuer: str
    not_before: str  # ISO date-time
    link: str
    source: str


@dataclass(frozen=True)
class Finding:
    """One lookalike *domain* (a registration someone made), with the host names certified under it."""

    name: str  # the registrable domain, ASCII (punycode for IDN)
    display: str  # as a person sees it (Unicode for homographs)
    registrable: str
    technique: str
    detail: str
    severity: str
    issuer: str
    not_before: str  # its earliest certificate seen: when the domain first went live with HTTPS
    link: str
    source: str
    hosts: tuple[str, ...] = ()  # host names seen on its certificates (up to MAX_HOSTS)
    host_count: int = 0
    verdict: str = ""  # from triage: phishing, clone, mail, live, suspicious, parked, dormant
    reasons: tuple[str, ...] = ()
    escalated_from: str = ""  # set when a known lookalike got worse (e.g. parked -> phishing)


# ----------------------------------------------------------------------------- classification
def own_domains(domain: str, allow: list[str]) -> set[str]:
    return {registrable(d) for d in [domain, *allow] if d}


def candidate_map(domain: str) -> dict[str, Candidate]:
    return {c.domain: c for c in generate(domain, limit=3000)}


def _display(name: str) -> str:
    if "xn--" not in name:
        return name
    try:
        return name.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return name


def _sensitive(text: str) -> str | None:
    parts = set(re.split(r"[.\-]", text))
    return next((w for w in sorted(SENSITIVE_WORDS) if w in parts or (len(w) > 3 and w in text)), None)


def classify(
    name: str, brand: str, own: set[str], candidates: dict[str, Candidate]
) -> tuple[str, str, str, str] | None:
    """(registrable, technique, detail, severity) when ``name`` imitates the brand; None otherwise."""
    name = name.strip().lower().lstrip("*.").rstrip(".")
    if not HOSTNAME.match(name):
        return None
    try:
        reg = registrable(name)
        label, suffix = split_domain(reg)
    except ValueError:
        return None
    if reg in own:
        return None
    word = _sensitive(name)
    candidate = candidates.get(reg)
    if candidate is not None:
        technique, detail = candidate.technique, candidate.detail
        if technique == "homoglyph":
            severity = "high"
        elif technique == "combosquat":
            severity = "high" if word else "medium"
        else:
            severity = "high" if word else "medium"
        return reg, technique, detail, severity
    if label == brand:
        return reg, "tld", f"the brand under .{suffix}", "high" if word else "medium"
    if brand in label:
        return (
            reg,
            "combosquat",
            f"contains '{brand}'" + (f" and '{word}'" if word else ""),
            "high" if word else "medium",
        )
    if brand in name.split("."):
        detail = f"'{brand}' used as a subdomain of {reg}"
        return reg, "subdomain", detail, "high" if word else "medium"
    return None


def findings_from(
    certs: list[Certificate], domain: str, allow: list[str], candidates: dict[str, Candidate]
) -> list[Finding]:
    """Lookalike domains in ``certs``, one per registrable domain: ``login.secure-acme.com`` and
    ``api.secure-acme.com`` are one registration, reported once with its worst host name."""
    brand = split_domain(registrable(domain))[0]
    own = own_domains(domain, allow)
    best: dict[str, tuple[str, str, str, str]] = {}  # registrable -> (host, technique, detail, severity)
    hosts: dict[str, set[str]] = {}
    first: dict[str, Certificate] = {}
    for cert in certs:
        for raw in cert.names:
            name = raw.strip().lower().lstrip("*.").rstrip(".")
            hit = classify(name, brand, own, candidates)
            if hit is None:
                continue
            reg, technique, detail, severity = hit
            hosts.setdefault(reg, set()).add(name)
            current = best.get(reg)
            if current is None or SEVERITY_ORDER[severity] > SEVERITY_ORDER[current[3]]:
                best[reg] = (name, technique, detail, severity)
            if reg not in first or (cert.not_before and cert.not_before < first[reg].not_before):
                first[reg] = cert
    found = []
    for reg, (_host, technique, detail, severity) in best.items():
        cert = first[reg]
        names = sorted(hosts[reg], key=lambda h: (h != reg, len(h), h))
        found.append(Finding(reg, _display(reg), reg, technique, detail, severity, cert.issuer, cert.not_before,
                             cert.link, cert.source, tuple(_display(h) for h in names[:MAX_HOSTS]), len(names)))  # fmt: skip
    order = {t: i for i, t in enumerate(("homoglyph", "combosquat", "subdomain", "typo", "tld", "doppelganger"))}
    return sorted(found, key=lambda f: (-SEVERITY_ORDER[f.severity], order.get(f.technique, 9), f.name))


def exact_candidates(domain: str, candidates: dict[str, Candidate], keyword_ran: bool) -> list[str]:
    """Lookalikes to look up by name, most dangerous first. When the keyword search ran, the ones it
    already covers (names containing the brand) are skipped."""
    brand = split_domain(registrable(domain))[0]
    names = []
    for c in candidates.values():
        label = split_domain(c.domain)[0]
        if keyword_ran and brand in label:
            continue
        names.append(c.domain)
    return names[:CANDIDATES]


# ----------------------------------------------------------------------------- sources
async def crtsh(http: Any, brand: str) -> list[Certificate]:
    params = {"q": f"%{brand}%", "output": "json", "exclude": "expired", "deduplicate": "Y"}
    try:
        async with http.get(CRTSH, params=params, timeout=aiohttp.ClientTimeout(total=90)) as resp:
            if resp.status != 200:
                raise SourceFailed(f"crt.sh answered {resp.status}")
            rows = await resp.json(content_type=None)
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError) as exc:
        raise SourceFailed(f"crt.sh could not be reached ({type(exc).__name__})") from exc
    if not isinstance(rows, list):
        raise SourceFailed("crt.sh sent an unexpected answer")
    certs = []
    for row in rows[:MAX_CERTS]:
        if not isinstance(row, dict):
            continue
        names = tuple({*str(row.get("name_value") or "").split("\n"), str(row.get("common_name") or "")} - {""})
        certs.append(Certificate(names, str(row.get("issuer_name") or ""), str(row.get("not_before") or ""),
                                 f"https://crt.sh/?id={row.get('id')}", "crt.sh"))  # fmt: skip
    return certs


async def certspotter(http: Any, name: str, key: str) -> list[Certificate]:
    params = [("domain", name), ("include_subdomains", "true"), ("expand", "dns_names"), ("expand", "issuer")]
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    try:
        async with http.get(CERTSPOTTER, params=params, headers=headers) as resp:
            if resp.status == 429:
                raise SourceFailed("Cert Spotter's free limit was reached: the rest are checked next time")
            if resp.status != 200:
                raise SourceFailed(f"Cert Spotter answered {resp.status}")
            rows = await resp.json(content_type=None)
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError) as exc:
        raise SourceFailed(f"Cert Spotter could not be reached ({type(exc).__name__})") from exc
    certs = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        issuer = row.get("issuer") or {}
        certs.append(Certificate(tuple(row.get("dns_names") or ()), str(issuer.get("friendly_name") or issuer.get("name") or ""),
                                 str(row.get("not_before") or ""), f"https://crt.sh/?q={row.get('cert_sha256', '')}",
                                 "Cert Spotter"))  # fmt: skip
    return certs


# ----------------------------------------------------------------------------- alerting
def alert_summary(watch: dict[str, Any], news: list[Finding], baseline: bool) -> dict[str, Any]:
    return {
        "brand_watch": {
            "id": watch["id"],
            "domain": watch["domain"],
            "baseline": baseline,
            "new_count": len(news),
            "findings": [asdict(f) for f in news[:ALERT_SAMPLE]],
        }
    }


def alert_headline(watch: dict[str, Any], news: list[Finding]) -> str:
    names = ", ".join(f.display for f in news[:3]) + (f" and {len(news) - 3} more" if len(news) > 3 else "")
    plural = "s" if len(news) != 1 else ""
    if news and all(f.verdict == "taken_down" for f in news):
        return f"Taken down: {names} (lookalike{plural} of {watch['domain']})"
    if any(f.verdict == "phishing" for f in news):
        return f"Active phishing page{plural} imitating {watch['domain']}: {names}"
    if news and all(f.escalated_from for f in news):
        return f"Lookalike domain{plural} of {watch['domain']} became more dangerous: {names}"
    return f"Lookalike domain{plural} of {watch['domain']} in Certificate Transparency: {names}"


def worst(news: list[Finding]) -> str:
    return max((f.severity for f in news), key=lambda s: SEVERITY_ORDER[s], default="medium")


def _recent(value: str, now: datetime) -> bool:
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return now - moment <= FRESH


# ----------------------------------------------------------------------------- the watcher
RaiseAlert = Callable[[dict[str, Any], list[Finding], bool], Awaitable[dict[str, Any] | None]]


class BrandWatcher:
    def __init__(
        self,
        repo: BrandWatchRepository,
        settings: Settings,
        *,
        raise_alert: RaiseAlert,
        http_factory: Callable[[], Any] | None = None,
        poll_seconds: float = POLL_SECONDS,
    ):
        self.repo = repo
        self.settings = settings
        self.raise_alert = raise_alert
        # (kind, watch, event, message): the workspace's alert when a watch keeps failing (Phase 87)
        self.health_alert: Callable[[str, dict[str, Any], str, str], Awaitable[Any]] | None = None
        self.http_factory = http_factory or (lambda: outbound_client(settings, None))
        self.web_factory: Callable[[str], Any] = self._web_client  # route name or "direct" -> HTTP client
        self.dns_lookup: Callable[[str], Awaitable[dict[str, Any] | None]] = lookalike_triage.dns_profile
        self.web_lookup: Callable[[Any, str], Awaitable[Any]] = lookalike_triage.web_profile
        self.screenshot: Callable[[str, str], Awaitable[bytes | None]] = self._screenshot  # (url, mode) -> PNG
        self.poll_seconds = poll_seconds
        self._running: set[asyncio.Task[Any]] = set()

    def _web_client(self, route_name: str) -> Any:
        from fastapi import HTTPException

        from argus.api.opsec_routes import find_route

        try:  # find_route answers an unknown name with an HTTP error, meant for API callers
            route = None if route_name == "direct" else find_route(self.settings, route_name)
        except HTTPException as exc:
            raise SourceFailed(f"The route '{route_name}' is not configured any more") from exc
        return outbound_client(self.settings, route)

    async def _screenshot(self, url: str, mode: str) -> bytes | None:
        """The page as the headless browser shows it, through the watch's route (None without a browser)."""
        from argus.api.opsec_routes import find_route
        from argus.evidence.capture import find_browser, render
        from argus.evidence.guard_proxy import GuardProxy

        browser = find_browser(self.settings)
        if browser is None:
            return None
        from fastapi import HTTPException

        try:
            route = None if mode == "direct" else find_route(self.settings, mode)
        except HTTPException:  # the watch's route was removed from the settings: no render
            return None
        async with GuardProxy(allow_private=self.settings.allow_private_targets, upstream=route) as proxy:
            shot: bytes | None = (await render(url, browser, self.settings, proxy))["screenshot"]
        return shot

    async def _references(self, watch: dict[str, Any], mode: str) -> list[dict[str, Any]] | None:
        """Fingerprints of the brand's own pages; None when the stored ones are still current."""
        urls = watch.get("reference_urls") or [f"https://{watch['domain']}/"]
        stored = watch.get("visual_refs") or []
        now = datetime.now(timezone.utc)
        fresh = [
            r
            for r in stored
            if r.get("captured_at") and now - datetime.fromisoformat(r["captured_at"]) < REFERENCES_EVERY
        ]
        if stored and [r["url"] for r in stored] == urls and len(fresh) == len(stored):
            return None
        refs = []
        for url in urls:
            shot = await self.screenshot(url, mode)
            print_ = visual.fingerprint(shot) if shot else None
            if print_ is not None and not print_.blank:
                refs.append({"url": url, "fingerprint": print_.as_dict(), "captured_at": now.isoformat()})
        return refs

    async def triage(
        self, watch: dict[str, Any], findings: dict[str, Finding]
    ) -> tuple[dict[str, Triage], str | None, list[dict[str, Any]] | None]:
        """Triage ``findings`` (name -> finding). Returns the verdicts, a problem if the web check failed,
        and the brand's reference pages when they were (re)rendered."""
        domain = watch["domain"]
        brand = split_domain(domain)[0]
        own_dns = await self.dns_lookup(domain) or {}
        own: dict[str, Any] = {"ns": {lookalike_triage.parent_domain(n) for n in own_dns.get("ns") or []},
                               "ips": set(own_dns.get("ips") or [])}  # fmt: skip
        dns_results = {}
        gate = asyncio.Semaphore(10)

        async def lookup(name: str) -> None:
            async with gate:
                dns_results[name] = await self.dns_lookup(name)

        await asyncio.gather(*(lookup(n) for n in findings))
        web_results: dict[str, Any] = {}
        problem = None
        mode = watch.get("web_check") or "off"
        live = [n for n, d in dns_results.items() if d and d.get("ips")]
        if mode != "off" and live:
            try:
                async with self.web_factory(mode) as http:
                    mine = await self.web_lookup(http, domain)
                    own["title"], own["favicon_sha256"] = mine.title, mine.favicon_sha256
                    for name in live:
                        web_results[name] = await self.web_lookup(http, name)
            except SourceFailed as exc:
                problem = str(exc)
        # What the pages look like: the brand's own (references) against the live lookalikes, newest first.
        matches: dict[str, dict[str, Any]] = {}
        new_refs = None
        reachable = [n for n in live if getattr(web_results.get(n), "reachable", False)][:VISUAL_PER_RUN]
        if mode != "off" and reachable and problem is None:
            try:
                new_refs = await self._references(watch, mode)
                refs = new_refs if new_refs is not None else watch.get("visual_refs") or []
                if refs:
                    for name in reachable:
                        host = web_results[name].final_host or name
                        shot = await self.screenshot(f"https://{host}/", mode)
                        page = visual.fingerprint(shot) if shot else None
                        best = visual.best_match(page, refs) if page is not None else None
                        if best is not None:
                            matches[name] = best
            except (SourceFailed, OSError, ValueError) as exc:  # visual checks never break the triage
                logger.warning("Visual comparison for %s failed: %s", domain, exc)
        verdicts = {}
        for name, finding in findings.items():
            sensitive = bool(_sensitive(name))
            verdicts[name] = judge(finding.severity, brand, dns_results.get(name), own, web_results.get(name),
                                   sensitive=sensitive, visual=matches.get(name))  # fmt: skip
        return verdicts, problem, new_refs

    async def _follow_takedowns(
        self,
        watch: dict[str, Any],
        tracked: list[str],
        triaged: dict[str, dict[str, Any]],
        to_check: dict[str, Finding],
        records: dict[str, dict[str, Any]],
    ) -> list[Finding]:
        """Mark open takedowns whose domain went down; returns them (for a low-severity alert)."""
        from argus.intel import takedown

        down = []
        web_checked = (watch.get("web_check") or "off") != "off"
        for name in tracked:
            record = records.get(name) or {}
            gone, misses = takedown.went_down(triaged[name], web_checked, int(record.get("misses") or 0))
            if gone:
                stamp = datetime.now(timezone.utc).isoformat()
                await self.repo.put_takedown(watch["id"], None, name, {"status": "down", "down_at": stamp, "misses": misses},
                                             {"event": "down", "by": "Argus", "verdict": triaged[name]["verdict"]})  # fmt: skip
                down.append(replace(to_check[name], severity="low", verdict="taken_down",
                                    reasons=(f"Down: {triaged[name]['label'].lower()}",)))  # fmt: skip
            elif misses != int(record.get("misses") or 0):
                await self.repo.put_takedown(
                    watch["id"], None, name, {"misses": misses}, {"event": "check", "by": "Argus"}
                )
        return down

    async def takedown_contacts(self, domain: str, ips: list[str]) -> dict[str, Any]:
        """Registrar and host abuse contacts (RDAP goes to the registries, not to the lookalike)."""
        from argus.intel import takedown

        async with outbound_client(self.settings, None) as http:
            return await takedown.contacts(http, domain, ips)

    async def _report_health(self, watch: dict[str, Any], event: str | None, message: str) -> None:
        """Tell the workspace its watch keeps failing, was paused or works again (never breaks the run)."""
        if event and self.health_alert is not None:
            try:
                await self.health_alert("brand", watch, event, message)
            except Exception:
                logger.exception("Raising the health alert for brand watch %s failed", watch["id"])

    def _key(self) -> str:
        value = getattr(self.settings, "certspotter_api_key", None)
        return value.get_secret_value().strip() if value else ""

    async def tick(self) -> list[dict[str, Any]]:
        outcomes: list[dict[str, Any]] = []
        if not features.allows("monitoring"):
            return outcomes
        for watch in await self.repo.due():
            if not await self.repo.claim(watch["id"]):
                continue  # another replica took it
            outcomes.append(await self.check(watch))
        return outcomes

    def kick(self) -> None:
        task = asyncio.create_task(self.tick(), name="brand-watch")
        self._running.add(task)
        task.add_done_callback(self._running.discard)

    async def run_forever(self) -> None:
        while True:
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Brand watch tick failed")
            await asyncio.sleep(self.poll_seconds)

    async def check(self, watch: dict[str, Any]) -> dict[str, Any]:
        started = time.monotonic()
        status = "error"
        try:
            outcome = await self._check(watch)
            status = outcome["status"]
            return outcome
        finally:
            metrics.watch_run("brand", status, time.monotonic() - started)

    async def _check(self, watch: dict[str, Any]) -> dict[str, Any]:
        domain = watch["domain"]
        brand = split_domain(domain)[0]
        candidates = candidate_map(domain)
        certs: list[Certificate] = []
        sources: dict[str, Any] = {}
        key = self._key()
        per_run = EXACT_PER_RUN_WITH_KEY if key else EXACT_PER_RUN
        cursor = watch.get("cursor", 0)
        async with self.http_factory() as http:
            keyword_ran = False
            if len(brand) >= MIN_KEYWORD:
                try:
                    found = await crtsh(http, brand)
                    certs += found
                    keyword_ran = True
                    sources["crt.sh"] = {"status": "ok", "certificates": len(found)}
                except SourceFailed as exc:
                    sources["crt.sh"] = {"status": "error", "message": str(exc)}
            else:
                sources["crt.sh"] = {"status": "skipped", "message": f"'{brand}' is too short to search by keyword"}
            names = exact_candidates(domain, candidates, keyword_ran)
            looked = 0
            spotter: dict[str, Any] = {"status": "ok", "looked_up": 0}
            for i in range(min(per_run, len(names))):
                name = names[(cursor + i) % len(names)]
                try:
                    certs += await certspotter(http, name, key)
                    looked += 1
                except SourceFailed as exc:
                    spotter = {"status": "error" if not looked else "partial", "message": str(exc)}
                    break
            spotter["looked_up"] = looked
            if names:
                spotter["of"] = len(names)
            sources["Cert Spotter"] = spotter
            cursor = (cursor + looked) % len(names) if names else 0

        ran = [s for s in sources.values() if s["status"] in ("ok", "partial")]
        failed = [s for s in sources.values() if s["status"] == "error"]
        status = "error" if not ran else "partial" if failed else "ok"
        problems = "; ".join(s["message"] for s in failed)
        for source, outcome in sources.items():
            if outcome["status"] in ("error", "partial"):
                metrics.WATCH_SOURCE_ERRORS.labels(source).inc()
        if status == "error":
            health = await self.repo.record(
                watch["id"], status=status, sources=sources, message=problems, retry_in=RETRY
            )
            await self._report_health(watch, health, problems)
            return {"watch_id": watch["id"], "status": status, "new": 0, "alert": None}

        baseline = not watch.get("baselined")
        now = datetime.now(timezone.utc)
        lookalike_findings = findings_from(certs, domain, watch.get("allow") or [], candidates)
        already = await self.repo.known_names(watch["id"], [f.name for f in lookalike_findings])
        fresh: list[Finding] = [f for f in lookalike_findings if f.name not in already]
        # Triage the new lookalikes, those with an open takedown, and the known ones checked longest ago.
        fresh_names = {f.name for f in fresh}
        tracked = [n for n in await self.repo.open_takedowns(watch["id"]) if n not in fresh_names]
        stale = tracked + await self.repo.stale(watch["id"], RETRIAGE_PER_RUN, exclude={*fresh_names, *tracked})
        rows = await self.repo.lookalikes(watch["id"], stale)
        previous = {name: row.get("triage") or {} for name, row in rows.items()}
        to_check: dict[str, Finding] = {f.name: f for f in fresh}
        for name in stale:
            info = rows.get(name) or {}
            base = previous.get(name, {}).get("base_severity") or info.get("severity") or "medium"
            to_check[name] = Finding(name, str(info.get("display") or name), name, str(info.get("technique") or ""),
                                     str(info.get("detail") or ""), base, str(info.get("issuer") or ""),
                                     str(info.get("not_before") or ""), str(info.get("link") or ""),
                                     str(info.get("source") or ""))  # fmt: skip
        verdicts, web_problem, new_refs = await self.triage(watch, to_check)
        stamp = now.isoformat()
        triaged = {name: {**t.as_dict(stamp), "base_severity": to_check[name].severity} for name, t in verdicts.items()}
        fresh = [replace(f, severity=verdicts[f.name].severity, verdict=verdicts[f.name].verdict,
                         reasons=tuple(verdicts[f.name].reasons)) for f in fresh]  # fmt: skip
        reportable = [f for f in fresh if f.verdict != "yours"]
        for f in reportable:
            metrics.LOOKALIKES_FOUND.labels(f.severity).inc()
        news = [f for f in reportable if not baseline or _recent(f.not_before, now) or f.verdict == "phishing"]
        for name in stale:
            before, after = previous.get(name) or {}, verdicts[name]
            if (before and after.verdict != "yours" and SEVERITY_ORDER[after.severity] >= SEVERITY_ORDER["high"]
                    and SEVERITY_ORDER[after.severity] > SEVERITY_ORDER.get(before.get("severity", "low"), 0)):  # fmt: skip
                news.append(replace(to_check[name], severity=after.severity, verdict=after.verdict,
                                    reasons=tuple(after.reasons), escalated_from=str(before.get("verdict"))))  # fmt: skip
        news.sort(key=lambda f: -SEVERITY_ORDER[f.severity])
        taken_down = await self._follow_takedowns(
            watch, tracked, triaged, to_check, {n: rows.get(n, {}).get("takedown") or {} for n in tracked}
        )
        if taken_down and not news:
            news = taken_down
        if web_problem:
            problems = "; ".join(p for p in (problems, web_problem) if p)
        alert = None
        if news:
            try:
                alert = await self.raise_alert(watch, news, baseline)
            except Exception:  # the findings are still recorded below
                logger.exception("Raising the alert for brand watch %s failed", watch["id"])
        message = (f"Baseline: {len(fresh)} existing lookalike domain(s) recorded" if baseline
                   else f"{len(fresh)} new lookalike domain(s)")  # fmt: skip
        if problems:
            message += f" ({problems})"
        health = await self.repo.record(
            watch["id"], status=status, sources=sources, message=message, new=[asdict(f) for f in fresh], cursor=cursor, alerted=alert is not None,
            retry_in=RETRY if failed else None, triage=triaged, visual_refs=new_refs,
        )  # fmt: skip
        await self._report_health(watch, health, message)
        logger.info("Brand watch %s (%s): %s", watch["id"], domain, message)
        return {"watch_id": watch["id"], "status": status, "baseline": baseline, "new": len(news),
                "recorded": len(fresh), "alert": alert["id"] if alert else None}  # fmt: skip
