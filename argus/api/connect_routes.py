"""Argus Connect on the account service: brokered lookups paid for in Argus credits.

Argus Personal calls ``POST /api/connect/{provider}`` with its licence and a named lookup. The
service:

1. checks the licence (signature, this computer still signed in, subscription current);
2. takes the lookup's price in credits, atomically, so two lookups at once cannot overspend;
3. runs the lookup with the operator's key (a fixed URL on the source's own host);
4. refunds the credits if the source failed, and returns the answer with the new balance.

The lookup and its parameters are written to the account service's log as the ledger detail
(provider and lookup name only, never the query text), so customers can see what they spent
credits on without their searches being kept.
"""

from __future__ import annotations

from typing import Any

import aiohttp
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from argus.accounts.connectors import CATALOGUE, LABELS, ConnectError, build, call_source, operation
from argus.accounts.licence import FULL_STATUSES, LicenceError, load_private_key, verify
from argus.api.deps import audit, client_ip, require_platform_admin
from argus.intel.analyst import BASE_CREDITS, TASKS, AnalystError, price, run_task
from argus.security.auth import Principal
from argus.security.ratelimit import SlidingWindowLimiter

router = APIRouter(prefix="/api", tags=["accounts"])
_per_account = SlidingWindowLimiter(limit=120, window=60)
KEYS = {"companies_house": "companies_house_api_key", "web_search": "web_search_api_key"}


class ConnectRequest(BaseModel):
    licence: str = Field(max_length=8192)
    operation: str = Field(max_length=64)
    params: dict[str, Any] = Field(default_factory=dict)


class BalanceRequest(BaseModel):
    licence: str = Field(max_length=8192)


class AnalystConnectRequest(BaseModel):
    licence: str = Field(max_length=8192)
    material: str = Field(max_length=2_100_000)


class CreditsRequest(BaseModel):
    amount: int = Field(ge=-1_000_000, le=1_000_000)
    kind: str = Field(default="purchase", pattern="^(purchase|adjustment)$")
    detail: str = Field(default="", max_length=200)


def _price_list() -> dict[str, Any]:
    prices = {provider: {"label": LABELS[provider], "lookups": {name: op.credits for name, op in ops.items()}}
              for provider, ops in CATALOGUE.items()}  # fmt: skip
    prices["ai"] = {"label": "AI analyst (from; larger cases cost more)", "lookups": dict(BASE_CREDITS)}
    return prices


async def _customer(request: Request, token: str) -> dict[str, Any]:
    settings = request.app.state.settings
    if not settings.account_service_enabled or not settings.licence_signing_key:
        raise HTTPException(status_code=404, detail="Not found")
    private = load_private_key(settings.licence_signing_key.get_secret_value())
    issuer = (settings.public_url or str(request.base_url)).rstrip("/")
    try:
        payload = verify(token, private.public_key(), issuer=issuer)
    except LicenceError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    repo = request.app.state.subscribers
    account = await repo.get(payload["sub"])
    if account is None or not await repo.device_active(account["id"], payload["device"]):
        raise HTTPException(status_code=401, detail="This computer is not signed in to the account")
    if account["status"] not in FULL_STATUSES:
        raise HTTPException(
            status_code=402, detail=f"Your subscription is {account['status']}: renew to use Argus Connect"
        )
    if not _per_account.hit(account["id"]):
        raise HTTPException(status_code=429, detail="Too many lookups; wait a minute")
    return account


@router.post("/connect/balance")
async def connect_balance(body: BalanceRequest, request: Request):
    """The account's credits and what each lookup costs."""
    account = await _customer(request, body.licence)
    return {"credits": await request.app.state.credits.balance(account["id"]), "prices": _price_list()}


@router.post("/connect/{provider}")
async def connect_lookup(provider: str, body: ConnectRequest, request: Request):
    """Run one named lookup on a premium source, paid for in credits."""
    account = await _customer(request, body.licence)
    try:
        op = operation(provider, body.operation)
        build(provider, body.operation, body.params)  # invalid details are refused before any credit is taken
    except ConnectError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.detail) from exc
    settings = request.app.state.settings
    key_setting = getattr(settings, KEYS.get(provider, ""), None)
    key = key_setting.get_secret_value() if key_setting else ""
    if not key:
        raise HTTPException(status_code=503, detail=f"{LABELS[provider]} is not available on this service")
    detail = f"{provider}/{body.operation}"
    charge = await request.app.state.credits.charge(account["id"], op.credits, detail)
    if charge is None:
        raise HTTPException(status_code=402, detail="Not enough Argus credits for this lookup: your allowance renews "
                                                    "on the 1st, or buy more credits")  # fmt: skip
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as http:
            result = await call_source(http, provider, body.operation, body.params, key)
    except ConnectError as exc:
        await request.app.state.credits.refund(account["id"], charge, f"{detail} failed")
        raise HTTPException(status_code=exc.status, detail=exc.detail) from exc
    except (aiohttp.ClientError, TimeoutError, OSError) as exc:
        await request.app.state.credits.refund(account["id"], charge, f"{detail} failed")
        raise HTTPException(status_code=503, detail=f"{LABELS[provider]} could not be reached") from exc
    if result.get("not_found"):  # nothing found is still an answer, but costs nothing
        await request.app.state.credits.refund(account["id"], charge, f"{detail}: not found")
        charge = {**charge, "charged": 0, "available": charge["available"] + charge["charged"]}
    return {
        "result": result,
        "credits": {k: charge[k] for k in ("charged", "available", "allowance_remaining", "purchased")},
    }


@router.post("/connect/ai/{task}")
async def connect_ai(task: str, body: AnalystConnectRequest, request: Request):
    """Run an AI analyst task with the operator's Claude key, paid for in credits.

    The case material is passed straight to Anthropic and dropped when the answer comes back: it
    is never written to the database or the log. The ledger records only "ai/<task>".
    """
    account = await _customer(request, body.licence)
    if task not in TASKS:
        raise HTTPException(status_code=404, detail=f"Unknown analyst task {task!r}")
    settings = request.app.state.settings
    key = settings.anthropic_api_key.get_secret_value() if settings.anthropic_api_key else ""
    if not key:
        raise HTTPException(status_code=503, detail="The AI analyst is not available on this service")
    if not body.material.strip():
        raise HTTPException(status_code=422, detail="This case has nothing for the analyst to read yet")
    if len(body.material) > settings.analyst_max_chars + 10_000:
        raise HTTPException(status_code=413, detail="Too much case material for one request")
    detail = f"ai/{task}"
    charge = await request.app.state.credits.charge(account["id"], price(task, len(body.material)), detail)
    if charge is None:
        raise HTTPException(status_code=402, detail="Not enough Argus credits for the AI analyst: your allowance "
                                                    "renews on the 1st, or buy more credits")  # fmt: skip
    try:
        result = await run_task(task, body.material, key=key, settings=settings)
    except AnalystError as exc:
        await request.app.state.credits.refund(account["id"], charge, f"{detail} failed")
        raise HTTPException(status_code=exc.status, detail=exc.detail) from exc
    return {
        "result": result,
        "credits": {k: charge[k] for k in ("charged", "available", "allowance_remaining", "purchased")},
    }


@router.get("/accounts/{account_id}/credits")
async def account_credits(account_id: str, request: Request, _: Principal = Depends(require_platform_admin)):
    balance = await request.app.state.credits.balance(account_id)
    if balance is None:
        raise HTTPException(status_code=404, detail="Account not found")
    return {**balance, "ledger": await request.app.state.credits.ledger(account_id)}


@router.post("/accounts/{account_id}/credits")
async def add_credits(account_id: str, body: CreditsRequest, request: Request,
                      principal: Principal = Depends(require_platform_admin)):  # fmt: skip
    """Add purchased credits (what a payment provider's webhook calls) or correct a balance."""
    balance = await request.app.state.credits.add(account_id, body.amount, kind=body.kind,
                                                  detail=body.detail or body.kind)  # fmt: skip
    if balance is None:
        raise HTTPException(status_code=404, detail="Account not found")
    await audit(request, principal, "account.credits", account_id,
                details={"amount": body.amount, "kind": body.kind, "ip": client_ip(request)})  # fmt: skip
    return balance
