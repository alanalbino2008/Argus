"""Bitcoin wallets: balance, activity, who sent and received money, and addresses with the same owner.

Data comes from a public Esplora API (mempool.space by default, or Blockstream, or your own node's
Esplora): free, no key. Bitcoin's ledger is public, so this is reading the blockchain, not anyone's
private records.

**Same owner (common-input heuristic).** To spend coins held at several addresses in one
payment, a wallet must sign for all of them, so addresses spent *together* as inputs of one
transaction almost always belong to the same owner. Chainalysis and every serious blockchain
analysis tool rely on this. It is deliberately not applied to **CoinJoin** transactions (many
people pooling coins into equal-sized outputs precisely to break this rule): those are detected
and skipped, and the wallet is flagged as having used one.

**Services are not followed.** A wallet with thousands of transactions is almost always an
exchange or payment service mixing many customers' money; following its counterparties would
link strangers. It is flagged, and the trail stops there.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import AsyncIterator
from typing import Any, ClassVar

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.core.settings import get_settings
from argus.intel import sanctions
from argus.intel.crypto import classify
from argus.modules.base import BaseModule
from argus.modules.crypto.common import SERVICE_TX_COUNT, Flows, counterparty_entities, iso, sanction_notes

SATS = 100_000_000
PAGES = 3  # up to 75 recent transactions per wallet
SAME_WALLET_LIMIT = 10


def is_coinjoin(tx: dict[str, Any]) -> bool:
    """Many inputs from different addresses and several equal-value outputs: a CoinJoin."""
    inputs = {(v.get("prevout") or {}).get("scriptpubkey_address") for v in tx.get("vin", [])} - {None}
    values = Counter(o.get("value") for o in tx.get("vout", []) if o.get("value"))
    return len(inputs) >= 3 and bool(values) and values.most_common(1)[0][1] >= 3


def analyse(address: str, txs: list[dict[str, Any]]) -> tuple[Flows, set[str], int]:
    """Counterparty flows, addresses spent together with ``address``, and how many CoinJoins it joined."""
    flows, together, coinjoins = Flows(), set(), 0
    for tx in txs:
        when = iso((tx.get("status") or {}).get("block_time"))
        ins = [((v.get("prevout") or {}).get("scriptpubkey_address"), (v.get("prevout") or {}).get("value", 0))
               for v in tx.get("vin", []) if not v.get("is_coinbase")]  # fmt: skip
        outs = [(o.get("scriptpubkey_address"), o.get("value", 0)) for o in tx.get("vout", [])]
        ours_in = sum(value for addr, value in ins if addr == address)
        ours_out = sum(value for addr, value in outs if addr == address)
        input_addrs = {addr for addr, _ in ins if addr}
        if is_coinjoin(tx):  # outputs belong to all participants: neither "same owner" nor a payment by this wallet
            coinjoins += 1
            continue
        if ours_in:  # the wallet paid: recipients are the outputs that aren't its own addresses
            together |= input_addrs - {address}
            for addr, value in outs:
                if addr and addr not in input_addrs and value:
                    flows.by_counterparty[addr].sent += value / SATS
                    flows.by_counterparty[addr].seen(when)
        elif ours_out:  # the wallet was paid: split the amount over the payers in proportion to their inputs
            total_in = sum(value for _, value in ins) or 1
            for addr, value in ins:
                if addr and addr != address:
                    flows.by_counterparty[addr].received += ours_out * (value / total_in) / SATS
                    flows.by_counterparty[addr].seen(when)
    return flows, together, coinjoins


class BitcoinWalletModule(BaseModule):
    name = "bitcoin_wallet"
    description = "Bitcoin wallet balance, payments, counterparties, same-owner addresses and sanctions (free API)"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.CRYPTO_WALLET]
    third_party_safe = True  # reads the public ledger; never contacts the wallet's owner
    attack_techniques = ("T1593",)  # public ledger and block explorers: open sources

    def can_handle(self, entity: Entity) -> bool:
        address = classify(entity.value)
        return entity.type == EntityType.CRYPTO_WALLET and address is not None and address.chain == "bitcoin"

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        base = get_settings().bitcoin_api_url.rstrip("/")
        address = classify(entity.value)
        if address is None or not base:
            return
        await sanctions.load(session)
        a = address.value
        explorer = "https://mempool.space/address/{}"
        async with session.get(f"{base}/address/{a}") as resp:
            if resp.status != 200:
                return
            info = await resp.json()
        stats = info.get("chain_stats") or {}
        funded, spent = stats.get("funded_txo_sum", 0), stats.get("spent_txo_sum", 0)
        tx_count = int(stats.get("tx_count", 0))
        md = entity.metadata
        md.update(chain="bitcoin", address_kind=address.kind, checksum=address.checksum, asset="BTC",
                  balance=round((funded - spent) / SATS, 8), total_received=round(funded / SATS, 8),
                  total_sent=round(spent / SATS, 8), transactions=tx_count, explorer_url=explorer.format(a))  # fmt: skip
        listed = sanction_notes(a)
        if listed:
            md["sanctions"] = listed
        if tx_count >= SERVICE_TX_COUNT:
            md["service"] = True
        if md.get("service") or not tx_count:
            return  # an exchange or service mixes many people's money: don't follow its counterparties

        txs: list[dict[str, Any]] = []
        url = f"{base}/address/{a}/txs"
        for _ in range(PAGES):
            async with session.get(url) as resp:
                if resp.status != 200:
                    break
                page = await resp.json()
            if not page:
                break
            txs += page
            if len(page) < 25:
                break
            url = f"{base}/address/{a}/txs/chain/{page[-1]['txid']}"
        times = sorted(t for t in (iso((tx.get("status") or {}).get("block_time")) for tx in txs) if t)
        md.update(transactions_examined=len(txs), first_seen=times[0] if times else None,
                  last_seen=times[-1] if times else None)  # fmt: skip
        flows, together, coinjoins = analyse(a, txs)
        if coinjoins:
            md["coinjoins"] = coinjoins
        for item in counterparty_entities(entity, flows, chain="bitcoin", asset="BTC",
                                          limit=get_settings().crypto_counterparties, module=self.name,
                                          explorer=explorer):  # fmt: skip
            yield item
        for other in sorted(together)[:SAME_WALLET_LIMIT]:
            if classify(other) is None:
                continue
            sibling = Entity.create(EntityType.CRYPTO_WALLET, other, label=f"{other[:10]}…",
                                    metadata={"chain": "bitcoin", "explorer_url": explorer.format(other),
                                              **({"sanctions": sanction_notes(other)} if sanction_notes(other) else {})},
                                    source_module=self.name, confidence=0.8, depth=entity.depth + 1)  # fmt: skip
            yield sibling
            yield Relation.create(entity.id, sibling.id, RelationType.SAME_WALLET,
                                  label="Spent together: most likely the same owner")  # fmt: skip
