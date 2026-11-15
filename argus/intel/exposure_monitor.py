"""The exposure loop: every replica runs one; each due watch is claimed by exactly one replica.

A check of a **domain** asks every source about it:
* breached addresses (HIBP domain search);
* infostealer logs;
* breaches of the organisation itself (the HIBP catalogue);
* ransomware leak-site posts naming it.

The **supplier sweep** asks the two public sources (breach catalogue, ransomware leak sites)
about every supplier in the register.

**Alerts.** The first check of a watch is a *baseline*. It alerts only about serious findings
(high or critical), since years-old breaches are history, not news. After that, every new finding
is announced, in one alert per check. Alerts never contain staff addresses: they travel to Slack,
Teams, email and SIEMs, and the addresses stay in Argus.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any

from argus.core.settings import Settings
from argus.intel.breach_sources import BreachSources, SourceError, SourceUnavailable
from argus.intel.exposure import (
    SEVERITY_ORDER,
    Finding,
    account_findings,
    domain_breach_findings,
    headline,
    ransomware_findings,
    stealer_findings,
    worst,
)
from argus.observability import metrics
from argus.storage.exposure_repo import ExposureRepository

logger = logging.getLogger("argus.exposure")
PURGE_EVERY = 6 * 3600.0
MAX_SUPPLIERS = 500
SupplierLister = Callable[[str], Any]  # workspace id -> awaitable list of supplier dicts


class ExposureMonitor:
    def __init__(
        self,
        repo: ExposureRepository,
        settings: Settings,
        *,
        suppliers: SupplierLister,
        sources: BreachSources | None = None,
        on_new: Callable[[str, list[dict[str, Any]]], Awaitable[None]] | None = None,
    ):
        self.repo = repo
        self.settings = settings
        self.suppliers = suppliers
        self.sources = sources or BreachSources(settings)
        self.on_new = on_new  # e.g. open remediation tasks for qualifying findings
        self._last_purge = 0.0
        self._running: set[asyncio.Task[Any]] = set()

    # ------------------------------------------------------------------ the loop
    async def tick(self) -> list[dict[str, Any]]:
        """Check every due watch this replica manages to claim; returns their outcomes."""
        outcomes = []
        for watch in await self.repo.due():
            if not await self.repo.claim(watch["id"]):
                continue  # another replica took it
            outcomes.append(await self.check(watch))
        if time.monotonic() - self._last_purge > PURGE_EVERY:
            self._last_purge = time.monotonic()
            await self.repo.purge(older_than_days=self.settings.exposure_retention_days)
        return outcomes

    def kick(self) -> None:
        """Run a tick soon, in the background (after "check now")."""
        task = asyncio.create_task(self.tick(), name="exposure-check")
        self._running.add(task)
        task.add_done_callback(self._running.discard)

    async def run_forever(self) -> None:
        try:
            while True:
                try:
                    await self.tick()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("Exposure tick failed")
                await asyncio.sleep(self.settings.exposure_poll_seconds)
        finally:
            await self.sources.close()

    # ------------------------------------------------------------------ one check
    async def check(self, watch: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        report: dict[str, Any] = {}
        findings: list[Finding] = []
        supplier_ids: dict[str, str] = {}
        names: dict[str, str] = {}

        async def ask(name: str, call: Any) -> Any:
            try:
                result = await call
            except SourceUnavailable as exc:
                report[name] = {"status": "unavailable", "message": str(exc)}
                return None
            except SourceError as exc:
                report[name] = {"status": "error", "message": str(exc)}
                metrics.EXPOSURE_SOURCE_ERRORS.labels(name).inc()
                return None
            except Exception as exc:  # a bug in one source must not stop the others
                logger.exception("Exposure source %s failed", name)
                report[name] = {"status": "error", "message": f"Internal error ({type(exc).__name__})"}
                return None
            previous = report.get(name, {})
            report[name] = {"status": "ok", "found": previous.get("found", 0) + (len(result) if result else 0)}
            return result

        catalogue = await ask("breach_catalogue", self.sources.catalogue()) or {}
        if watch["scope"] == "domain":
            domain, organisation = watch["domain"], watch["organisation"]
            names[domain] = organisation
            findings += domain_breach_findings(domain, catalogue, now, subject_name=organisation or None)
            accounts = await ask("domain_search", self.sources.domain_accounts(domain))
            if accounts:
                findings += account_findings(domain, accounts, catalogue, now)
            infections = await ask("stealer_logs", self.sources.stealer_accounts(domain))
            if infections:
                findings += stealer_findings(domain, infections)
            for keyword in dict.fromkeys(k for k in (domain, organisation) if k):
                posts = await ask("ransomware", self.sources.ransomware_posts(keyword))
                if posts:
                    findings += ransomware_findings(domain, posts, now, names=(organisation,) if organisation else ())
        else:
            for supplier in (await self.suppliers(watch["workspace_id"]))[:MAX_SUPPLIERS]:
                domain = supplier["domain"]
                supplier_ids[domain], names[domain] = supplier["id"], supplier["name"]
                findings += domain_breach_findings(domain, catalogue, now, subject_name=supplier["name"])
                for keyword in dict.fromkeys((domain, supplier["name"])):
                    posts = await ask("ransomware", self.sources.ransomware_posts(keyword))
                    if posts:
                        findings += ransomware_findings(domain, posts, now, names=(supplier["name"],))

        statuses = [r["status"] for r in report.values()]
        ran = [s for s in statuses if s == "ok"]
        status = "error" if not ran else "partial" if "error" in statuses else "ok"
        problems = [f"{name}: {r['message']}" for name, r in report.items() if r["status"] == "error"]
        message = "; ".join(problems) or f"{len(findings)} finding(s) from {len(ran)} source(s)"

        unique = list({f.key: f for f in findings}.values())
        new, alert = await self.repo.record_check(
            watch, unique, status=status, message=message, sources=report, supplier_ids=supplier_ids,
            subject_names=names, alert=lambda fresh, baseline: self._alert(watch, fresh, baseline),
            public_url=self.settings.public_url,
        )  # fmt: skip
        metrics.EXPOSURE_CHECKS.labels(watch["scope"], status).inc()
        if new:
            metrics.EXPOSURE_FINDINGS.inc(len(new))
            if self.on_new is not None:
                try:
                    await self.on_new(watch["workspace_id"], new)
                except Exception:  # remediation automation must never break exposure checks
                    logger.exception("Opening remediation tasks for watch %s failed", watch["id"])
        logger.info("Exposure check %s (%s): %s, %d new", watch["id"], watch["domain"] or "suppliers", status, len(new))
        return {"watch_id": watch["id"], "status": status, "new": len(new), "alert": alert["id"] if alert else None}

    # ------------------------------------------------------------------ alerting
    def _alert(self, watch: dict[str, Any], fresh: list[dict[str, Any]], baseline: bool) -> dict[str, Any] | None:
        news = [f for f in fresh if not baseline or SEVERITY_ORDER[f["severity"]] >= SEVERITY_ORDER["high"]]
        if not news:
            return None
        by_subject: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for f in news:
            by_subject[f["subject"]].append(f)
        if watch["scope"] == "domain":
            text = headline(watch["domain"], news, baseline=baseline, subject_name=watch["organisation"] or None)
        else:
            ordered = sorted(by_subject.items(), key=lambda kv: -SEVERITY_ORDER[worst([f["severity"] for f in kv[1]])])
            text = " · ".join(
                headline(subject, items, baseline=baseline, subject_name=f"supplier {items[0]['subject_name']}")
                for subject, items in ordered[:3]
            ) + (f" · and {len(ordered) - 3} more supplier(s)" if len(ordered) > 3 else "")
        counts = {k: sum(1 for f in news if f["kind"] == k) for k in {f["kind"] for f in news}}
        return {
            "target": watch["domain"] or "supplier register",
            "severity": worst([f["severity"] for f in news]),
            "headline": text,
            "summary": {
                "summary": {},
                "exposure": {
                    "watch_id": watch["id"],
                    "scope": watch["scope"],
                    "baseline": baseline,
                    "counts": counts,
                    "subjects": sorted(by_subject)[:20],
                    "accounts": len({f["account"] for f in news if f.get("account")}),
                },
            },
        }
