"""What the wallet modules share: counterparty totals, wallet entities, sanctions and service flags."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from argus.core.models import Entity, EntityType, Relation, RelationType
from argus.intel import sanctions

SERVICE_TX_COUNT = 5000  # beyond this, a wallet is almost certainly an exchange or other service


@dataclass
class Flow:
    """Money between the investigated wallet and one counterparty (in the chain's own units)."""

    sent: float = 0.0  # from the investigated wallet to the counterparty
    received: float = 0.0  # from the counterparty to the investigated wallet
    transactions: int = 0
    first: str | None = None
    last: str | None = None
    label: str = ""
    service: bool = False

    def seen(self, when: str | None) -> None:
        self.transactions += 1
        if when:
            self.first = min(self.first or when, when)
            self.last = max(self.last or when, when)


@dataclass
class Flows:
    by_counterparty: dict[str, Flow] = field(default_factory=lambda: defaultdict(Flow))

    def top(self, limit: int) -> list[tuple[str, Flow]]:
        return sorted(self.by_counterparty.items(), key=lambda kv: -(kv[1].sent + kv[1].received))[:limit]


def iso(timestamp: Any) -> str | None:
    if timestamp in (None, ""):
        return None
    if isinstance(timestamp, (int, float)):
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
    try:
        return datetime.fromisoformat(str(timestamp).replace("Z", "+00:00")).isoformat()
    except ValueError:
        return None


def sanction_notes(address: str) -> list[dict[str, Any]]:
    return sanctions.check(address)


def counterparty_entities(origin: Entity, flows: Flows, *, chain: str, asset: str, limit: int, module: str,
                          explorer: str) -> list[Entity | Relation]:  # fmt: skip
    """Wallet entities for the largest counterparties, with directed SENT_FUNDS relations and amounts."""
    out: list[Entity | Relation] = []
    flagged = []
    for address, flow in flows.top(limit):
        listed = sanction_notes(address)
        metadata: dict[str, Any] = {"chain": chain, "explorer_url": explorer.format(address)}
        if flow.label:
            metadata["label"] = flow.label
        if flow.service:
            metadata["service"] = True
        if listed:
            metadata["sanctions"] = listed
            flagged.append({"address": address, "name": listed[0]["name"]})
        wallet = Entity.create(EntityType.CRYPTO_WALLET, address, label=flow.label or f"{address[:10]}…",
                               metadata=metadata, source_module=module, confidence=0.95,
                               depth=origin.depth + 1)  # fmt: skip
        out.append(wallet)
        for source, target, amount in ((origin, wallet, flow.sent), (wallet, origin, flow.received)):
            if amount > 0:
                out.append(Relation.create(source.id, target.id, RelationType.SENT_FUNDS,
                                           label=f"Sent {amount:.8g} {asset}",
                                           metadata={"amount": round(amount, 8), "asset": asset, "chain": chain,
                                                     "transactions": flow.transactions, "first": flow.first,
                                                     "last": flow.last}))  # fmt: skip
    if flagged:
        origin.metadata["sanctioned_counterparties"] = flagged
    return out
