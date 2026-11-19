"""The business at a glance, for the operator of the account service.

Worked out from the accounts, the credit ledger and Stripe's prices; nothing here touches
customers' cases (the account service never has them).

* **Customers**: how many are paying, on trial, behind with a payment, cancelled or suspended,
  and on which plan.
* **Monthly recurring revenue**: paying subscriptions times their plan's price in Stripe (yearly
  prices count a twelfth a month). Credit packs sold in the period are shown separately.
* **Sign-ups**: new accounts per week for twelve weeks, and how many of them now pay; and the
  share of finished trials that became paying customers.
* **Credits**: credits used in the period by source (failed lookups that were refunded don't
  count), credits bought, and the accounts using the most.
* **Needs attention**: payments failing, trials ending in the next three days, trials that ended
  without paying, accounts locked after wrong passwords, and paying customers with no credits left.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from argus.accounts.connectors import LABELS

PAYING = ("active", "past_due")
PER_MONTH = {"month": 1.0, "year": 1 / 12, "week": 52 / 12, "day": 365 / 12}


def paying(account: dict[str, Any]) -> bool:
    return account["status"] in PAYING and account["plan"] != "trial"


def source(detail: str) -> str:
    """``companies_house/officers failed`` -> ``companies_house``."""
    return (detail or "").split("/", 1)[0].split(" ", 1)[0] or "other"


def source_label(key: str) -> str:
    return "AI analyst" if key == "ai" else LABELS.get(key, key.replace("_", " "))


def monthly(price: dict[str, Any] | None) -> float | None:
    """A price's amount per month, in the currency's smallest unit (pence, cents)."""
    if not price or price.get("amount") is None:
        return None
    return float(price["amount"]) * PER_MONTH.get(str(price.get("interval") or "month"), 1.0)


def _week(day: datetime) -> datetime:
    start = day.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    return start - timedelta(days=start.weekday())


def summary(accounts: list[dict[str, Any]], ledger: list[dict[str, Any]], *, plan_prices: dict[str, Any],
            pack_prices: dict[int, Any], days: int, trial_days: int, now: datetime | None = None) -> dict[str, Any]:  # fmt: skip
    now = now or datetime.now(timezone.utc)
    by_id = {a["id"]: a for a in accounts}

    # ------------------------------------------------------------ customers
    statuses = Counter(a["status"] for a in accounts)
    customers = [a for a in accounts if paying(a)]
    plans = Counter(a["plan"] for a in customers)

    # ------------------------------------------------------------ revenue
    by_plan, currencies = [], set()
    total = 0.0
    priced = True
    for plan, count in sorted(plans.items()):
        price = plan_prices.get(plan)
        each = monthly(price)
        if each is None or price is None:
            priced = False
        else:
            currencies.add(price["currency"])
            total += each * count
        by_plan.append({"plan": plan, "customers": count, "monthly": round(each * count) if each is not None else None,
                        "currency": price.get("currency") if price else None})  # fmt: skip
    mrr = {"amount": round(total), "currency": next(iter(currencies)) if len(currencies) == 1 else None,
           "complete": priced, "by_plan": by_plan}  # fmt: skip

    # ------------------------------------------------------------ credits
    start = now - timedelta(days=days)
    period = [e for e in ledger if e["at"] and e["at"] >= start]
    used: dict[str, int] = defaultdict(int)
    per_account: dict[str, int] = defaultdict(int)
    packs: Counter[int] = Counter()
    bought = 0
    for e in period:
        if e["kind"] in ("usage", "refund"):  # a refund gives back a failed lookup: net it off
            used[source(e["detail"])] -= e["delta"]
            per_account[e["account_id"]] -= e["delta"]
        elif e["kind"] == "purchase":
            bought += e["delta"]
            if e["detail"].startswith("credit pack "):
                packs[e["delta"]] += 1
    sources: list[dict[str, Any]] = sorted(
        ({"source": k, "label": source_label(k), "credits": v} for k, v in used.items() if v > 0),
        key=lambda r: -int(r["credits"]),
    )
    top = sorted(((k, v) for k, v in per_account.items() if v > 0), key=lambda kv: -kv[1])[:10]
    pack_sales = []
    for credits, count in sorted(packs.items()):
        price = pack_prices.get(credits)
        pack_sales.append({"credits": credits, "sold": count, "currency": price.get("currency") if price else None,
                           "revenue": round(price["amount"] * count) if price and price.get("amount") is not None
                           else None})  # fmt: skip

    # ------------------------------------------------------------ sign-ups
    this_week = _week(now)
    weeks = [this_week - timedelta(weeks=i) for i in range(11, -1, -1)]
    signups = []
    for w in weeks:
        cohort = [a for a in accounts if a["created"] and w <= a["created"] < w + timedelta(weeks=1)]
        signups.append(
            {"week": w.date().isoformat(), "accounts": len(cohort), "paying": sum(paying(a) for a in cohort)}
        )
    finished = [a for a in accounts if a["created"] and a["created"] <= now - timedelta(days=trial_days)]
    converted = sum(1 for a in finished if a["plan"] != "trial")

    # ------------------------------------------------------------ needs attention
    month = now.strftime("%Y-%m")

    def row(a: dict[str, Any], why: str) -> dict[str, Any]:
        return {"id": a["id"], "email": a["email"], "name": a["name"], "plan": a["plan"], "status": a["status"],
                "valid_until": a["valid_until"], "why": why}  # fmt: skip

    attention = [row(a, "payment failing") for a in accounts if a["status"] == "past_due"]
    attention += [row(a, "trial ends soon") for a in accounts if a["status"] == "trialing" and a["until"]
                  and now < a["until"] <= now + timedelta(days=3)]  # fmt: skip
    attention += [row(a, "trial ended without paying") for a in accounts if a["plan"] == "trial" and a["until"]
                  and now - timedelta(days=14) <= a["until"] <= now]  # fmt: skip
    attention += [row(a, "locked after wrong passwords") for a in accounts
                  if a["locked_until"] and datetime.fromisoformat(a["locked_until"]) > now]  # fmt: skip
    attention += [row(a, "out of credits") for a in customers if a["allowance_month"] == month
                  and a["allowance_remaining"] == 0 and a["purchased_credits"] == 0]  # fmt: skip

    return {
        "period_days": days,
        "generated_at": now.isoformat(),
        "customers": {
            "accounts": len(accounts), "paying": len(customers), "trialing": statuses.get("trialing", 0),
            "past_due": statuses.get("past_due", 0), "cancelled": statuses.get("cancelled", 0),
            "suspended": statuses.get("suspended", 0), "plans": dict(plans),
        },
        "mrr": mrr,
        "signups": {"weeks": signups, "trials_finished": len(finished), "converted": converted,
                    "conversion": round(converted / len(finished), 3) if finished else None},
        "credits": {"used": sum(r["credits"] for r in sources), "by_source": sources, "bought": bought,
                    "pack_sales": pack_sales,
                    "top_accounts": [{"id": k, "email": by_id[k]["email"] if k in by_id else k, "credits": v}
                                     for k, v in top]},
        "attention": attention,
    }  # fmt: skip
