"""The operator's business dashboard (account service, platform admins only).

* ``GET /api/business/summary?days=30``: customers, monthly recurring revenue, sign-ups and
  conversion, credits used by source, credit packs sold, and accounts needing attention;
* ``GET /api/business/accounts``: the accounts, searchable and filterable;
* ``GET /api/business/accounts.csv``: the same as a spreadsheet (for accounts and tax).

Changing an account (plan, status, credits, computers) uses the existing ``/api/accounts``
endpoints, which are audited.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response

from argus.accounts import business
from argus.accounts import stripe_billing as stripe
from argus.api.account_routes import _service
from argus.api.billing_routes import _price
from argus.api.deps import audit, require_platform_admin
from argus.security.auth import Principal

router = APIRouter(prefix="/api/business", tags=["business"])
STATUSES = ("trialing", "active", "past_due", "cancelled", "suspended")


async def _prices(settings: Any) -> tuple[dict[str, Any], dict[int, Any]]:
    if not stripe.enabled(settings):
        return {}, {}
    plans = {plan: await _price(settings, pid) for plan, pid in stripe.plan_prices(settings).items()}
    packs = {credits: await _price(settings, pid) for credits, pid in stripe.credit_packs(settings).items()}
    return plans, packs


@router.get("/summary")
async def business_summary(request: Request, days: int = Query(30, ge=7, le=365),
                           _: Principal = Depends(require_platform_admin)):  # fmt: skip
    """The business at a glance."""
    repo, _private = _service(request)
    settings = request.app.state.settings
    accounts = await repo.overview()
    now = datetime.now(timezone.utc)
    ledger = await request.app.state.credits.since(now - timedelta(days=days))
    plans, packs = await _prices(settings)
    out = business.summary(accounts, ledger, plan_prices=plans, pack_prices=packs, days=days,
                           trial_days=settings.trial_days, now=now, payments=await repo.payments(limit=10_000))  # fmt: skip
    out["payments_enabled"] = stripe.enabled(settings)
    return out


def _matches(account: dict[str, Any], q: str, status: str, plan: str) -> bool:
    text = f"{account['email']} {account['name']} {account['id']} {account['billing_reference']}".lower()
    return ((not q or q.lower() in text) and (not status or account["status"] == status)
            and (not plan or account["plan"] == plan))  # fmt: skip


def _public(account: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in account.items() if k not in ("created", "until")}


async def _filtered(request: Request, q: str, status: str, plan: str) -> list[dict[str, Any]]:
    repo, _private = _service(request)
    accounts = sorted(await repo.overview(), key=lambda a: a["created_at"] or "", reverse=True)
    return [_public(a) for a in accounts if _matches(a, q.strip(), status, plan)]


@router.get("/accounts")
async def business_accounts(request: Request, q: str = Query("", max_length=200),
                            status: str = Query("", pattern=r"^(|trialing|active|past_due|cancelled|suspended)$"),
                            plan: str = Query("", pattern=r"^(|trial|byok|personal|professional|business)$"),
                            limit: int = Query(200, ge=1, le=1000),
                            _: Principal = Depends(require_platform_admin)):  # fmt: skip
    """Accounts, newest first, with search (email, name, id or Stripe customer) and filters."""
    found = await _filtered(request, q, status, plan)
    return {"total": len(found), "accounts": found[:limit]}


def _cell(value: Any) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text  # no spreadsheet formulas


@router.get("/accounts.csv")
async def business_accounts_csv(request: Request, q: str = Query("", max_length=200),
                                status: str = Query("", pattern=r"^(|trialing|active|past_due|cancelled|suspended)$"),
                                plan: str = Query("", pattern=r"^(|trial|byok|personal|professional|business)$"),
                                principal: Principal = Depends(require_platform_admin)):  # fmt: skip
    """The accounts as a CSV file. Contains customers' emails: handle it as personal data."""
    found = await _filtered(request, q, status, plan)
    columns = ["id", "email", "name", "plan", "status", "valid_until", "created_at", "last_login_at",
               "billing_reference", "allowance_remaining", "purchased_credits", "max_devices"]  # fmt: skip
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(columns)
    for a in found:
        writer.writerow([_cell(a.get(c)) for c in columns])
    await audit(request, principal, "business.export_accounts", "accounts", details={"rows": len(found)})
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return Response(buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="argus-accounts-{stamp}.csv"'})  # fmt: skip
