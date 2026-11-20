"""Alerts for the owner: an email when something needs attention, and when it's fixed.

Every few minutes (one server at a time, when there are several), Argus:

* **runs the owner console's health checks**: database, payments and the Stripe webhook,
  email, backups, disk space, background work. A check that turns to a problem is emailed
  straight away; while it lasts, a reminder once a day; when it's fixed, a short "fixed" email.
  Warnings (things to look at, not broken) are shown in the console only.
* **looks at what happened since last time** in the audit log: disputes opened or lost, failed
  payments (once per customer every few days), and each new paying customer (if wanted).
* **sends a daily summary** (if wanted) at the chosen hour: sign-ups, new customers, payments,
  disputes, refunds and how the server is doing.

Several problems found at once go in one email. What was sent is kept (the last 50) and shown
under Alerts in the owner console.
"""

from __future__ import annotations

import asyncio
import logging
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from argus.accounts import owner as owner_mod

logger = logging.getLogger("argus.alerts")
STATE_KEY = "owner_alerts"
LOCK = 0x4152_4755_414C_5254  # "ARGUALRT": one replica at a time
REMIND_EVERY = timedelta(hours=24)
PAST_DUE_QUIET = timedelta(days=3)
HISTORY = 50
PAYMENT_EVENTS = ("billing.dispute_opened", "billing.dispute_lost", "billing.subscription")
SUMMARY_EVENTS = ("account.signup", "billing.subscription", "billing.credits_purchased", "billing.refund",
                  "billing.dispute_opened", "billing.dispute_lost", "billing.dispute_won")  # fmt: skip


def _now() -> datetime:
    return datetime.now(timezone.utc)


class OwnerAlerts:
    def __init__(self, app: Any):
        self.app = app

    @property
    def settings(self) -> Any:
        return self.app.state.settings

    async def recipient(self) -> str:
        if self.settings.owner_alert_email:
            return str(self.settings.owner_alert_email)
        owner = await self.app.state.owner.get()
        return str((owner or {}).get("email") or self.settings.owner_email or "")

    async def _state(self) -> dict[str, Any]:
        return await self.app.state.app_state.get(STATE_KEY) or {}

    async def history(self) -> list[dict[str, Any]]:
        return list((await self._state()).get("history") or [])

    # ------------------------------------------------------------------ the loop
    async def run_forever(self) -> None:
        await asyncio.sleep(90)  # let everything start (and report healthy) first
        while True:
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Owner alerts check failed")
            await asyncio.sleep(self.settings.owner_alert_check_seconds)

    async def tick(self, now: datetime | None = None) -> list[dict[str, Any]]:
        """One round: returns the emails sent (subject and lines)."""
        if not self.settings.owner_alerts_enabled:
            return []
        to = await self.recipient()
        if not to:
            return []
        now = now or _now()
        async with self.app.state.db.cluster_lock(LOCK):
            state = await self._state()
            sent = []
            for subject, lines in [*await self._health(state, now), *await self._events(state, now),
                                   *await self._summary(state, now)]:  # fmt: skip
                await owner_mod.alert(self.app, to, subject, lines, security=False, wait=True)
                sent.append({"at": now.isoformat(), "subject": subject, "lines": lines})
            state["history"] = (sent[::-1] + list(state.get("history") or []))[:HISTORY]
            await self.app.state.app_state.set(STATE_KEY, state)
        return sent

    # ------------------------------------------------------------------ health
    async def _health(self, state: dict[str, Any], now: datetime) -> list[tuple[str, list[str]]]:
        from argus.api.owner_console_routes import health

        checks = {c["name"]: c for c in await health(self.app)}
        known: dict[str, Any] = state.setdefault("checks", {})
        broken, fixed, still = [], [], []
        for name, check in checks.items():
            before = known.get(name) or {}
            if check["status"] == "error":
                if before.get("status") != "error":
                    broken.append(check)
                    known[name] = {"status": "error", "since": now.isoformat(), "notified_at": now.isoformat()}
                elif now - datetime.fromisoformat(before["notified_at"]) >= REMIND_EVERY:
                    still.append({**check, "since": before.get("since")})
                    known[name] = {**before, "notified_at": now.isoformat()}
            else:
                if before.get("status") == "error":
                    fixed.append(check)
                known[name] = {"status": check["status"], "since": now.isoformat()}
        for name in [n for n in known if n not in checks]:  # checks that no longer apply
            del known[name]
        emails = []
        if broken or still:
            problems = broken + still
            subject = (f"Problem: {problems[0]['name']}" if len(problems) == 1 else
                       f"{len(problems)} problems need attention")  # fmt: skip
            lines = [f"• {c['name']}: {c['detail']}" + (f"\n  What to do: {c['fix']}" if c.get("fix") else "") +
                     (f"\n  (since {str(c['since'])[:16].replace('T', ' ')} UTC)" if c.get("since") else "")
                     for c in problems]  # fmt: skip
            emails.append((subject, ["Argus found something that isn't working:", *lines,
                                     f"Details: {self._console()}"]))  # fmt: skip
        if fixed:
            emails.append((f"Fixed: {', '.join(c['name'] for c in fixed)}",
                           [f"• {c['name']} is working again: {c['detail']}" for c in fixed]))  # fmt: skip
        return emails

    def _console(self) -> str:
        return f"{(self.settings.public_url or '').rstrip('/')}/admin"

    # ------------------------------------------------------------------ business events
    async def _events(self, state: dict[str, Any], now: datetime) -> list[tuple[str, list[str]]]:
        audit = self.app.state.audit
        if "cursor" not in state:  # first run: start from now, never alert about the past
            state["cursor"] = await audit.last_id()
            return []
        events = await audit.events(after_id=int(state["cursor"]), actions=PAYMENT_EVENTS, limit=500)
        if events:
            state["cursor"] = events[-1]["id"]
        if not self.settings.account_service_enabled:
            return []
        quiet: dict[str, str] = state.setdefault("past_due", {})
        customers: list[str] = state.setdefault("customers", [])
        emails = []
        for event in events:
            details, account_id = event.get("details") or {}, event.get("resource")
            who = await self._who(account_id)
            if event["action"] == "billing.dispute_opened" and self.settings.owner_alert_payments:
                emails.append((f"Payment disputed by {who}",
                               [f"{who} disputed a payment (reason: {details.get('reason') or 'not given'}).",
                                "Their account is on hold and the credits from that payment are held until "
                                "it's settled. Answer the dispute in your Stripe dashboard, with evidence, "
                                "before Stripe's deadline."]))  # fmt: skip
            elif event["action"] == "billing.dispute_lost" and self.settings.owner_alert_payments:
                emails.append((f"Dispute lost: {who}",
                               [f"The bank decided {who}'s dispute against you. Their account stays on hold: "
                                "decide in the Business page whether to lift it."]))  # fmt: skip
            elif event["action"] == "billing.subscription":
                status, plan = details.get("status"), details.get("plan")
                if status == "past_due" and self.settings.owner_alert_payments and account_id:
                    last = quiet.get(account_id)
                    if not last or now - datetime.fromisoformat(last) >= PAST_DUE_QUIET:
                        quiet[account_id] = now.isoformat()
                        emails.append((f"Payment failed: {who}",
                                       [f"{who}'s payment for the {plan} plan failed. Stripe retries it and "
                                        "they've been emailed; they keep full access meanwhile."]))  # fmt: skip
                elif status == "active" and plan not in (None, "trial") and account_id and account_id not in customers:
                    customers.append(account_id)
                    if self.settings.owner_alert_new_customers:
                        emails.append((f"New customer: {who} ({plan})", [f"{who} is now paying for the {plan} plan."]))
        state["customers"] = customers[-5000:]
        for account_id in [a for a, at in quiet.items() if now - datetime.fromisoformat(at) > PAST_DUE_QUIET * 10]:
            del quiet[account_id]
        return emails

    async def _who(self, account_id: str | None) -> str:
        if not account_id:
            return "A customer"
        account = await self.app.state.subscribers.get(account_id)
        return str((account or {}).get("email") or "A customer")

    # ------------------------------------------------------------------ daily summary
    async def _summary(self, state: dict[str, Any], now: datetime) -> list[tuple[str, list[str]]]:
        today = now.date().isoformat()
        if not self.settings.owner_daily_summary or now.hour < self.settings.owner_summary_hour:
            return []
        if state.get("summary_on") == today:
            return []
        state["summary_on"] = today
        return [(f"Daily summary, {today}", await self.summary_lines(now))]

    async def summary_lines(self, now: datetime | None = None) -> list[str]:
        from argus.api.owner_console_routes import health

        now = now or _now()
        events = await self.app.state.audit.events(since=now - timedelta(days=1), actions=SUMMARY_EVENTS, limit=5000)
        counts = Counter(e["action"] for e in events)
        paying = sum(1 for e in events if e["action"] == "billing.subscription"
                     and (e.get("details") or {}).get("status") == "active")  # fmt: skip
        failed = sum(1 for e in events if e["action"] == "billing.subscription"
                     and (e.get("details") or {}).get("status") == "past_due")  # fmt: skip
        checks = await health(self.app)
        problems = [c for c in checks if c["status"] == "error"]
        warnings = [c for c in checks if c["status"] == "warn"]
        lines = ["The last 24 hours:"]
        if self.settings.account_service_enabled:
            lines += [f"• New accounts: {counts['account.signup']}",
                      f"• Subscription payments and renewals: {paying}" + (f" (failed: {failed})" if failed else ""),
                      f"• Credit packs bought: {counts['billing.credits_purchased']}",
                      f"• Refunds: {counts['billing.refund']}",
                      f"• Disputes: {counts['billing.dispute_opened']} opened, {counts['billing.dispute_won']} won, "
                      f"{counts['billing.dispute_lost']} lost"]  # fmt: skip
        lines.append("Health: " + ("everything is working" if not problems and not warnings else
                                   f"{len(problems)} problem(s), {len(warnings)} thing(s) to check"))  # fmt: skip
        lines += [f"• {c['name']}: {c['detail']}" for c in problems + warnings]
        lines.append(f"Owner console: {self._console()}")
        return lines
