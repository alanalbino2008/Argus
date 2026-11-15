"""Ethereum-compatible wallets: balance, payments and token transfers, labels, and sanctions.

One ``0x`` address is the same account on Ethereum, Base, Polygon, Arbitrum and other EVM chains.
Argus reads each configured chain's public **Blockscout** explorer API (free, no key; set
``ARGUS_EVM_CHAINS`` to add chains or point at your own).

Blockscout also returns public **labels** ("Binance 14", "Uniswap V3: Router") and ENS names
("vitalik.eth"). Labels tell the investigator when money went to an exchange, which is often
where a trail can be followed up legally (exchanges hold identity records). Labelled services,
contracts and very busy wallets are flagged and not followed further, so strangers are not linked
through them.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, ClassVar

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, ScanConfig
from argus.core.settings import get_settings
from argus.intel import sanctions
from argus.intel.crypto import classify
from argus.modules.base import BaseModule
from argus.modules.crypto.common import SERVICE_TX_COUNT, Flows, counterparty_entities, iso, sanction_notes

NATIVE = {"ethereum": "ETH", "base": "ETH", "arbitrum": "ETH", "optimism": "ETH", "polygon": "POL", "gnosis": "xDAI"}


def _labels(party: dict[str, Any] | None) -> str:
    if not party:
        return ""
    tags = [t.get("display_name") or t.get("name") for t in party.get("public_tags") or []]
    tags += [t.get("name") for t in (party.get("metadata") or {}).get("tags") or []]
    names = [n for n in [party.get("name"), party.get("ens_domain_name"), *tags] if n]
    return str(names[0])[:80] if names else ""


def _amount(value: Any, decimals: Any = 18) -> float:
    try:
        return int(value) / 10 ** int(decimals or 0)
    except (TypeError, ValueError):
        return 0.0


def analyse(address: str, txs: list[dict[str, Any]], transfers: list[dict[str, Any]], native: str) -> dict[str, Flows]:
    """Flows per asset: the chain's own coin, then each token."""
    by_asset: dict[str, Flows] = {}
    rows = [(tx.get("from"), tx.get("to"), _amount(tx.get("value")), native, tx.get("timestamp"))
            for tx in txs if tx.get("status") in (None, "ok")]  # fmt: skip
    rows += [(t.get("from"), t.get("to"), _amount((t.get("total") or {}).get("value"), (t.get("total") or {}).get("decimals")),
              str((t.get("token") or {}).get("symbol") or "token")[:12], t.get("timestamp")) for t in transfers]  # fmt: skip
    for sender, receiver, amount, asset, when in rows:
        if not amount or not sender or not receiver:
            continue
        s, r = str(sender.get("hash", "")).lower(), str(receiver.get("hash", "")).lower()
        flows = by_asset.setdefault(asset, Flows())
        if s == address and r != address:
            flow, party = flows.by_counterparty[r], receiver
            flow.sent += amount
        elif r == address and s != address:
            flow, party = flows.by_counterparty[s], sender
            flow.received += amount
        else:
            continue
        flow.seen(iso(when))
        flow.label = flow.label or _labels(party)
        flow.service = flow.service or bool(party.get("is_contract")) or bool(flow.label)
    return by_asset


class EvmWalletModule(BaseModule):
    name = "evm_wallet"
    description = "Ethereum-style wallet balance, payments, token transfers, labels and sanctions (Blockscout, free)"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.CRYPTO_WALLET]
    third_party_safe = True
    attack_techniques = ("T1593",)  # public ledger and block explorers: open sources

    def can_handle(self, entity: Entity) -> bool:
        address = classify(entity.value)
        return entity.type == EntityType.CRYPTO_WALLET and address is not None and address.chain == "evm"

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        address = classify(entity.value)
        if address is None:
            return
        await sanctions.load(session)
        a = address.value
        md = entity.metadata
        md.update(chain="evm", checksum=address.checksum, checksummed=None)
        listed = sanction_notes(a)
        if listed:
            md["sanctions"] = listed
        chains: dict[str, Any] = {}
        limit = get_settings().crypto_counterparties
        for chain, base in get_settings().evm_chains.items():
            base = base.rstrip("/")
            explorer = f"{base}/address/{{}}"
            async with session.get(f"{base}/api/v2/addresses/{a}") as resp:
                if resp.status != 200:
                    continue
                info = await resp.json()
            async with session.get(f"{base}/api/v2/addresses/{a}/counters") as resp:
                counters = await resp.json() if resp.status == 200 else {}
            tx_count = int(counters.get("transactions_count") or 0)
            transfers_count = int(counters.get("token_transfers_count") or 0)
            balance = _amount(info.get("coin_balance"))
            if not tx_count and not transfers_count and not balance:
                continue  # never used on this chain
            native = NATIVE.get(chain, "ETH")
            label = _labels(info)
            chains[chain] = {"balance": round(balance, 8), "asset": native, "transactions": tx_count,
                             "token_transfers": transfers_count, "contract": bool(info.get("is_contract")),
                             "explorer_url": explorer.format(a)}  # fmt: skip
            if label:
                md["label"] = label
            if info.get("ens_domain_name"):
                md["ens"] = info["ens_domain_name"]
            service = bool(info.get("is_contract")) or tx_count >= SERVICE_TX_COUNT or bool(label and entity.depth > 0)
            if service:
                md["service"] = True
            if service or md.get("service"):
                continue  # contracts, exchanges and busy services mix many people's money
            txs: list[dict[str, Any]] = []
            transfers: list[dict[str, Any]] = []
            async with session.get(f"{base}/api/v2/addresses/{a}/transactions") as resp:
                if resp.status == 200:
                    txs = (await resp.json()).get("items") or []
            async with session.get(f"{base}/api/v2/addresses/{a}/token-transfers") as resp:
                if resp.status == 200:
                    transfers = (await resp.json()).get("items") or []
            times = sorted(t for t in (iso(x.get("timestamp")) for x in [*txs, *transfers]) if t)
            chains[chain].update(first_seen=times[0] if times else None, last_seen=times[-1] if times else None,
                                 transactions_examined=len(txs) + len(transfers))  # fmt: skip
            for asset, flows in analyse(a, txs, transfers, native).items():
                for item in counterparty_entities(entity, flows, chain=chain, asset=asset, limit=limit,
                                                  module=self.name, explorer=explorer):  # fmt: skip
                    yield item
        md["chains"] = chains
        md.pop("checksummed", None)
