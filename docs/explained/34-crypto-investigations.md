# 34 — Crypto Investigations (Plain-English Guide)

> Purpose: explain how Argus follows money through Bitcoin and Ethereum-style wallets, checks them
> against sanctions, and avoids the classic mistakes of blockchain analysis. Useful for questions
> like:
> * "how can you tell two Bitcoin addresses belong to the same person?"
> * "what is a CoinJoin and why does it matter?"
> * "how do you know an address isn't just a typo?"

## 1. Why this matters

Ransomware, scams, fake charities, extortion and sanctions evasion all end in a wallet address.
Unlike a bank account, a blockchain is **public**: anyone can read every payment ever made. The
skill is turning that raw ledger into an answer: where the money came from, where it went, who
might be behind it, and whether any of it touches a sanctioned group.

## 2. Is it even a real address?

Wallet addresses contain a built-in **checksum**, a few characters computed from the rest, so
that a typo is detected. Argus verifies it for every address it accepts or finds:

| Address | Example start | Checksum |
|---|---|---|
| Bitcoin legacy and script | `1…`, `3…` | Base58Check (double SHA-256) |
| Bitcoin SegWit and Taproot | `bc1q…`, `bc1p…` | Bech32 and Bech32m (BIP 173 and 350) |
| Ethereum-style | `0x…` | EIP-55 (capital letters encode a Keccak-256 hash) |

This matters twice:
* a mistyped address in a scan is refused with an explanation, instead of producing an empty or
  wrong investigation;
* when Argus scans a website, 64-character transaction hashes and random strings that only look
  like addresses are ignored, so a case isn't flooded with false wallets.

Keccak-256 (Ethereum's hash) is not the same as the SHA3-256 in Python's library: the two pad
data differently. So Argus implements Keccak itself, and the tests check it against published
values and against SHA3 at every tricky input length.

## 3. Following a Bitcoin wallet

Argus reads the wallet's history from a public Bitcoin API (mempool.space by default) and works
out:
* **balance, totals and active dates**;
* **who paid it, and whom it paid**, with amounts. When several people pay into one transaction,
  the amount received is shared between them in proportion to what each put in;
* **addresses with the same owner.** To spend coins held at several addresses in one payment, the
  owner has to sign for all of them, so addresses *spent together* almost always share an owner.
  This "common-input" rule is the foundation of professional blockchain analysis.

**CoinJoins.** Privacy-minded users break that rule on purpose. In a CoinJoin, many people put
coins into one transaction and get back equal-sized amounts, so nobody can tell who received
which. Treating a CoinJoin's inputs as one owner would link strangers. Argus recognises CoinJoins
(many inputs from different addresses, several identical outputs) and excludes them from both
"same owner" links and "payments", flagging only that the wallet used one. A test checks this.

## 4. Ethereum and compatible chains

One `0x…` address is the same account on Ethereum, Base, Polygon, Arbitrum and others. Argus
reads each configured chain's public **Blockscout** explorer. For each chain it gets:
* balance, transaction count and token transfers;
* payments in the chain's own coin and in tokens (USDC, USDT…). Failed transactions are ignored:
  no money moved;
* **labels**: Blockscout publishes names such as "Binance 14" or "Uniswap: Router", and ENS names
  such as "vitalik.eth".

Labels matter because exchanges keep identity records. "The money went to Binance" is often where
a journalist's or police investigation can continue through legal channels.

## 5. Exchanges and services are a dead end on purpose

An exchange's wallet holds thousands of customers' money. Following its counterparties would link
the subject to random strangers. So Argus flags these and **stops following the trail there**:
* labelled wallets (exchanges, services);
* smart contracts;
* wallets with thousands of transactions.

## 6. Sanctions

The US Treasury's Office of Foreign Assets Control (OFAC) lists the crypto addresses of
sanctioned groups: ransomware gangs, darknet markets, state hacking units, mixers. Argus reads
OFAC's own published files (free, public domain), caches them for a day, and checks **every**
wallet in the investigation: the target, every counterparty, and every same-owner address.

A match shows the designated party and the sanctions programmes. For example: *LAZARUS GROUP ·
DPRK3, CYBER2* (North Korea's state hackers). "Dealt with a sanctioned wallet" is shown
separately from "is a sanctioned wallet". A match is a fact about an address, not a verdict
about a person.

## 7. Where the data comes from, and what it costs

All of it is free public data with no API keys:
* Bitcoin from mempool.space (or Blockstream, or your own node);
* Ethereum-style chains from Blockscout;
* sanctions from OFAC.

Each source can be changed or self-hosted in the settings. Lookups go through the case's route
(Tor or VPN) like every other scan, so the explorer never learns the investigator's own address.

## 8. What a reviewer can check

* `argus/intel/crypto.py`: Keccak-256, the checksums, and finding addresses in text.
* `argus/intel/sanctions.py`: reading the OFAC files.
* `argus/modules/crypto/bitcoin.py`: flows, the common-input rule and CoinJoin detection.
* `argus/modules/crypto/evm.py`: chains, tokens, labels.
* `argus/modules/crypto/common.py`: counterparty wallets and the money relations.
* `tests/test_crypto.py`:
  * the published test vectors (EIP-55, BIP 173, 350 and 86);
  * corrupted addresses;
  * the OFAC file format;
  * Bitcoin flows, same owner and CoinJoin;
  * services not followed;
  * Ethereum tokens, labels and sanctioned counterparties;
  * wallets found on websites;
  * the scan refusing a mistyped address.
