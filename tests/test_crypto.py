"""Cryptocurrency investigation: address checksums, sanctions, Bitcoin and Ethereum-style wallet tracing."""

from __future__ import annotations

import hashlib

import pytest

from argus.core.models import Entity, EntityType, RelationType
from argus.core.settings import get_settings
from argus.intel import crypto, sanctions
from argus.modules.crypto.bitcoin import BitcoinWalletModule, analyse, is_coinjoin
from argus.modules.crypto.evm import EvmWalletModule
from tests.test_modules_offline import FakeResponse, FakeSession, collect

GENESIS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
VITALIK = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"


# ---------------------------------------------------------------------------- addresses
def test_keccak_matches_published_vectors_and_sha3():
    assert crypto.keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert crypto.keccak256(b"abc").hex() == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    for n in (0, 1, 134, 135, 136, 137, 271, 272, 500):  # every padding edge case
        assert crypto.keccak256(b"y" * n, domain=0x06) == hashlib.sha3_256(b"y" * n).digest(), n


@pytest.mark.parametrize("address", [
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
])  # fmt: skip
def test_eip55_checksums(address):  # the EIP-55 specification's own examples
    assert crypto.eip55(address.lower()) == address
    assert crypto.classify(address).checksum == "verified"
    broken = address[:-1] + (address[-1].swapcase() if address[-1].isalpha() else address[-1])
    if broken != address:
        assert crypto.classify(broken) is None


def test_bitcoin_addresses():
    cases = {
        GENESIS: ("bitcoin", "legacy"),
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy": ("bitcoin", "script"),
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq": ("bitcoin", "segwit"),
        "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4": ("bitcoin", "segwit"),  # BIP 173: upper case is valid
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr": ("bitcoin", "taproot"),  # BIP 86
    }
    for address, (chain, kind) in cases.items():
        found = crypto.classify(address)
        assert found and (found.chain, found.kind, found.traceable) == (chain, kind, True), address
    for bad in [
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb",  # one character changed
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",  # BIP 350: SegWit v0 with the Taproot checksum
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",  # BIP 350: Taproot with the old checksum
        "bc1QW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",  # mixed case
        "0x0000000000000000000000000000000000000000",  # the burn address is not someone's wallet
        "hello",
        "0x1234",
    ]:
        assert crypto.classify(bad) is None, bad


def test_addresses_are_found_in_text_without_false_alarms():
    page = (
        f"Donate! BTC {GENESIS} or ETH {VITALIK.lower()}. Tx 0x{'ab' * 32}. "
        f"Fake 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb, again {GENESIS}"
    )
    found = [a.value for a in crypto.find_addresses(page)]
    assert found == [GENESIS, VITALIK.lower()]  # the 64-digit hash and the corrupted copy are ignored


def test_scan_targets_recognise_wallets():
    from argus.cli.console import detect_target_type

    assert detect_target_type(GENESIS) == EntityType.CRYPTO_WALLET
    assert detect_target_type(VITALIK) == EntityType.CRYPTO_WALLET
    assert detect_target_type("jdoe") == EntityType.USERNAME


# ---------------------------------------------------------------------------- sanctions
SDN = (
    '36,"LAZARUS GROUP","-0- ","DPRK3] [CYBER2","-0- ","-0- ","-0- ","-0- ","-0- ","-0- ","-0- ",'
    '"a.k.a. APPLEWORM; Digital Currency Address - ETH 0x098B716B8Aaf21512996dC57EB0615e2383E2f96; alt. '
    'Digital Currency Address - XBT bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq; Secondary sanctions risk."\n'
    '99,"EXAMPLE PERSON","individual","SDGT","-0- ","-0- ","-0- ","-0- ","-0- ","-0- ","-0- ","DOB 01 Jan 1980."\n'
)
COMMENTS = '36,"Digital Currency Address - XBT 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy; alt. Digital Currency Address - USDT TXYZ"\n'


def test_the_ofac_list_is_read_with_names_and_programmes():
    listed = sanctions.parse(SDN, COMMENTS)
    eth = listed["0x098b716b8aaf21512996dc57eb0615e2383e2f96"][0]
    assert eth["name"] == "LAZARUS GROUP" and eth["programs"] == ["DPRK3", "CYBER2"] and eth["currency"] == "Ethereum"
    assert "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" in listed
    assert "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy" in listed  # continued in sdn_comments.csv
    assert len(listed) == 3  # "TXYZ" is too short to be an address; the person has no addresses


@pytest.fixture
def sanctions_file(tmp_path, monkeypatch):
    (tmp_path / "sdn.csv").write_text(SDN, encoding="latin-1")
    (tmp_path / "sdn_comments.csv").write_text(COMMENTS, encoding="latin-1")
    monkeypatch.setenv("ARGUS_SANCTIONS_FILE", str(tmp_path))
    get_settings.cache_clear()
    sanctions.reset()
    return tmp_path


async def test_sanctions_load_from_a_saved_copy(sanctions_file):
    await sanctions.load(FakeSession({}))
    assert sanctions.check("0x098B716B8AAF21512996DC57EB0615E2383E2F96")[0]["name"] == "LAZARUS GROUP"  # any case
    assert sanctions.check(GENESIS) == [] and sanctions.status()["listed_addresses"] == 3


async def test_a_missing_sanctions_list_never_stops_a_scan(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_SANCTIONS_FILE", str(tmp_path / "nowhere"))
    get_settings.cache_clear()
    sanctions.reset()
    await sanctions.load(FakeSession({}))
    assert sanctions.check(GENESIS) == [] and "FileNotFoundError" in sanctions.status()["error"]


# ---------------------------------------------------------------------------- Bitcoin
TARGET = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
SIBLING = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
SHOP = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
PAYER = "12c6DSiU4Rq3P4ZxziKxzrGuvbIRnpHhZf"  # not checked here: only appears as an input


def tx(txid, vin, vout, when=1_700_000_000):
    return {"txid": txid, "status": {"confirmed": True, "block_time": when},
            "vin": [{"prevout": {"scriptpubkey_address": a, "value": v}} for a, v in vin],
            "vout": [{"scriptpubkey_address": a, "value": v} for a, v in vout]}  # fmt: skip


HISTORY = [
    # paid the shop 0.5 BTC from two of its addresses: they share an owner
    tx("t1", [(TARGET, 40_000_000), (SIBLING, 20_000_000)], [(SHOP, 50_000_000), (TARGET, 9_990_000)], 1_700_000_000),
    # received 1 BTC from a payer
    tx("t2", [(PAYER, 150_000_000)], [(TARGET, 100_000_000), (PAYER, 49_990_000)], 1_690_000_000),
    # a CoinJoin: many strangers' inputs, equal outputs; must not make them "the same owner"
    tx("t3", [(TARGET, 10_000_000), ("1Stranger1aaaaaaaaaaaaaaaaaaaaaaa", 10_000_000), ("1Stranger2bbbbbbbbbbbbbbbbbbbbbbb", 10_000_000)],
       [("bc1qmix1", 9_000_000), ("bc1qmix2", 9_000_000), ("bc1qmix3", 9_000_000)], 1_710_000_000),
]  # fmt: skip


def test_bitcoin_flows_and_same_owner():
    flows, together, coinjoins = analyse(TARGET, HISTORY)
    assert together == {SIBLING} and coinjoins == 1  # strangers in the CoinJoin are not "the same owner"
    assert is_coinjoin(HISTORY[2]) and not is_coinjoin(HISTORY[0])
    assert not any(addr.startswith("bc1qmix") for addr in flows.by_counterparty)  # CoinJoin outputs aren't payments
    shop = flows.by_counterparty[SHOP]
    assert shop.sent == 0.5 and shop.transactions == 1
    assert flows.by_counterparty[PAYER].received == 1.0


async def test_tracing_a_bitcoin_wallet(sanctions_file, monkeypatch):
    sanctions.reset()
    session = FakeSession({
        rf"/address/{TARGET}$": FakeResponse(200, {"chain_stats": {"funded_txo_sum": 300_000_000,
                                                                   "spent_txo_sum": 150_000_000, "tx_count": 3}}),
        rf"/address/{TARGET}/txs$": FakeResponse(200, HISTORY),
    })  # fmt: skip
    seed = Entity.create(EntityType.CRYPTO_WALLET, TARGET)
    entities, relations = await collect(BitcoinWalletModule(), seed, session)
    md = seed.metadata
    assert (md["balance"], md["total_received"], md["transactions"]) == (1.5, 3.0, 3)
    assert md["sanctions"][0]["name"] == "LAZARUS GROUP" and md["coinjoins"] == 1
    assert md["explorer_url"].endswith(TARGET) and md["first_seen"].startswith("2023-07-22")
    wallets = {e.value: e for e in entities}
    assert wallets[SIBLING].metadata["sanctions"]  # the same-owner address is listed too
    paid = next(r for r in relations if r.type == RelationType.SENT_FUNDS and r.target_id == wallets[SHOP].id)
    assert paid.metadata["amount"] == 0.5 and paid.metadata["asset"] == "BTC" and paid.source_id == seed.id
    received = next(r for r in relations if r.type == RelationType.SENT_FUNDS and r.target_id == seed.id
                    and r.source_id == wallets[PAYER].id)  # fmt: skip
    assert received.metadata["amount"] == 1.0
    assert any(r.type == RelationType.SAME_WALLET and r.target_id == wallets[SIBLING].id for r in relations)


async def test_exchanges_and_services_are_not_followed():
    session = FakeSession({rf"/address/{GENESIS}$": FakeResponse(200, {"chain_stats": {"tx_count": 50_000}})})
    seed = Entity.create(EntityType.CRYPTO_WALLET, GENESIS)
    entities, _ = await collect(BitcoinWalletModule(), seed, session)
    assert seed.metadata["service"] is True and entities == []
    assert not any("/txs" in url for url in session.requested)  # its history was not even fetched


# ---------------------------------------------------------------------------- Ethereum-style chains
TOKEN_SENDER = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
EXCHANGE = "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359"


async def test_tracing_an_ethereum_wallet(sanctions_file):
    sanctions.reset()
    v = VITALIK.lower()
    party = lambda h, **kw: {"hash": h, "is_contract": False, **kw}  # noqa: E731
    session = FakeSession({
        rf"/addresses/{v}$": FakeResponse(200, {"coin_balance": str(25 * 10**17), "is_contract": False,
                                               "ens_domain_name": "vitalik.eth"}),
        rf"/addresses/{v}/counters$": FakeResponse(200, {"transactions_count": "3", "token_transfers_count": "1"}),
        rf"/addresses/{v}/transactions$": FakeResponse(200, {"items": [
            {"from": party(v), "to": party(EXCHANGE, name=None, public_tags=[{"display_name": "Binance 14"}]),
             "value": str(10**18), "timestamp": "2024-03-01T10:00:00Z", "status": "ok"},
            {"from": party("0x098b716b8aaf21512996dc57eb0615e2383e2f96"), "to": party(v), "value": str(2 * 10**18),
             "timestamp": "2024-02-01T10:00:00Z", "status": "ok"},
            {"from": party(v), "to": party(EXCHANGE), "value": "5", "timestamp": "2024-03-02T10:00:00Z", "status": "error"},
        ]}),
        rf"/addresses/{v}/token-transfers$": FakeResponse(200, {"items": [
            {"from": party(TOKEN_SENDER), "to": party(v), "total": {"value": "2500000", "decimals": "6"},
             "token": {"symbol": "USDC"}, "timestamp": "2024-01-15T10:00:00Z"}]}),
    })  # fmt: skip
    seed = Entity.create(EntityType.CRYPTO_WALLET, VITALIK)
    entities, relations = await collect(EvmWalletModule(), seed, session)
    md = seed.metadata
    eth = md["chains"]["ethereum"]
    assert (eth["balance"], eth["asset"], eth["transactions"], eth["token_transfers"]) == (2.5, "ETH", 3, 1)
    assert md["ens"] == "vitalik.eth" and eth["first_seen"].startswith("2024-01-15")
    wallets = {e.value: e for e in entities}
    assert wallets[EXCHANGE].metadata["label"] == "Binance 14" and wallets[EXCHANGE].metadata["service"] is True
    assert md["sanctioned_counterparties"][0]["name"] == "LAZARUS GROUP"
    amounts = {(r.metadata["asset"], r.metadata["amount"]) for r in relations if r.type == RelationType.SENT_FUNDS}
    assert amounts == {("ETH", 1.0), ("ETH", 2.0), ("USDC", 2.5)}  # the failed transaction is not money moved


async def test_a_contract_or_unused_chain_is_not_traced():
    session = FakeSession({
        r"/counters$": FakeResponse(200, {"transactions_count": "900000"}),
        r"/addresses/0x[0-9a-f]{40}$": FakeResponse(200, {"coin_balance": "0", "is_contract": True, "name": "Router"}),
    })  # fmt: skip
    seed = Entity.create(EntityType.CRYPTO_WALLET, VITALIK)
    entities, _ = await collect(EvmWalletModule(), seed, session)
    assert entities == [] and seed.metadata["service"] is True and seed.metadata["label"] == "Router"
    assert not any("/transactions" in url for url in session.requested)


# ---------------------------------------------------------------------------- websites and the API
async def test_wallets_published_on_a_website_are_found():
    from argus.modules.discovery.web_recon import WebReconModule

    session = FakeSession(
        {
            r"scam\.example/donate$": FakeResponse(
                200, f"<p>Send BTC to {GENESIS}</p><p>ETH: {VITALIK}</p><p>not a wallet: 0x{'cd' * 32}</p>"
            )
        }
    )
    seed = Entity.create(EntityType.DOMAIN, "scam.example")
    entities, _ = await collect(WebReconModule(), seed, session)
    wallets = {e.value: e.metadata for e in entities if e.type == EntityType.CRYPTO_WALLET}
    assert set(wallets) == {GENESIS, VITALIK.lower()}
    assert wallets[GENESIS] == {"origin": "published on website", "chain": "bitcoin", "traceable": True}


def test_a_mistyped_wallet_is_refused_before_scanning(client):
    bad = client.post("/api/scan", json={"target": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", "target_type": "crypto_wallet",
                                         "purpose": "Tracing a fraud payment", "authorized": True})  # fmt: skip
    assert bad.status_code == 422 and "checksum" in bad.json()["detail"]
    ok = client.post("/api/scan", json={"target": GENESIS, "purpose": "Tracing a fraud payment", "authorized": True,
                                        "max_depth": 0})  # fmt: skip
    assert ok.status_code == 200 and ok.json()["target_type"] == "crypto_wallet"
