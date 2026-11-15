"""Cryptocurrency addresses: recognising them, proving they are well-formed, and finding them in text.

Scams, extortion, sanctions evasion and fraud fundraising all end in a wallet address. Argus
recognises addresses for the chains it can trace, and **verifies each one's built-in checksum**:

* **Bitcoin**:
  * legacy and script addresses (``1...``, ``3...``): Base58Check, a double SHA-256 checksum;
  * SegWit and Taproot addresses (``bc1q...``, ``bc1p...``): Bech32 and Bech32m (BIP 173 and
    BIP 350), a BCH error-detecting code;
* **Ethereum and compatible chains** (``0x`` + 40 hex digits): an address in mixed case carries
  an EIP-55 checksum in its capitalisation, verified with Keccak-256.

A checksum turns a random string into evidence: text that merely looks like an address is
rejected, so a page full of hex does not flood a case with false wallets. Other chains (Litecoin,
Tron, Solana, Monero...) are recognised by format only, and labelled as not traced.

Keccak-256 is implemented here because Python's ``hashlib.sha3_256`` is the final SHA-3 standard,
which pads differently from the Keccak Ethereum uses. It is checked against published test
vectors.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------- Keccak-256
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
    0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]  # fmt: skip
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_MASK = (1 << 64) - 1


def _rol(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (64 - shift))) & _MASK if shift else value


def _keccak_f(state: list[list[int]]) -> None:
    for rc in _RC:
        c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(state[x][y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                state[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        state[0][0] ^= rc


def keccak256(data: bytes, *, domain: int = 0x01) -> bytes:
    """Keccak-256 as Ethereum uses it (original Keccak padding, not SHA3-256).

    ``domain=0x06`` gives standard SHA3-256 instead, which the tests compare with ``hashlib``.
    """
    rate = 136
    room = rate - len(data) % rate  # bytes of padding needed: 1..136
    padded = bytearray(data) + (bytes([domain | 0x80]) if room == 1 else
                                bytes([domain]) + b"\x00" * (room - 2) + b"\x80")  # fmt: skip
    state = [[0] * 5 for _ in range(5)]
    for start in range(0, len(padded), rate):
        block = padded[start : start + rate]
        for i in range(rate // 8):
            state[i % 5][i // 5] ^= int.from_bytes(block[i * 8 : i * 8 + 8], "little")
        _keccak_f(state)
    return b"".join(state[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


# ---------------------------------------------------------------------------- Bitcoin
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32M_CONST = 0x2BC830A3


def _b58decode(text: str) -> bytes | None:
    number = 0
    for char in text:
        index = _B58.find(char)
        if index < 0:
            return None
        number = number * 58 + index
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * (len(text) - len(text.lstrip("1"))) + body


def _base58check(text: str) -> bytes | None:
    raw = _b58decode(text)
    if raw is None or len(raw) < 5:
        return None
    payload, checksum = raw[:-4], raw[-4:]
    return payload if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum else None


def _polymod(values: list[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if (top >> i) & 1 else 0
    return chk


def _bech32_decode(text: str) -> tuple[str, list[int], str] | None:
    if text.lower() != text and text.upper() != text:
        return None  # mixed case is never valid Bech32
    text = text.lower()
    pos = text.rfind("1")
    if pos < 1 or pos + 7 > len(text) or len(text) > 90 or any(c not in _BECH32 for c in text[pos + 1 :]):
        return None
    hrp, data = text[:pos], [_BECH32.find(c) for c in text[pos + 1 :]]
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    check = _polymod(expanded + data)
    encoding = "bech32" if check == 1 else "bech32m" if check == _BECH32M_CONST else None
    return (hrp, data[:-6], encoding) if encoding else None


def _segwit_valid(text: str) -> str | None:
    """'segwit' or 'taproot' for a valid mainnet SegWit address, else None."""
    decoded = _bech32_decode(text)
    if decoded is None or decoded[0] != "bc" or not decoded[1]:
        return None
    _hrp, data, encoding = decoded
    version, program = data[0], data[1:]
    acc, bits, out = 0, 0, []
    for value in program:
        acc, bits = (acc << 5) | value, bits + 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if bits >= 5 or (bits and (acc << (8 - bits)) & 0xFF):  # leftover bits must be zero padding
        return None
    if not 2 <= len(out) <= 40 or version > 16:
        return None
    if version == 0:
        return "segwit" if encoding == "bech32" and len(out) in (20, 32) else None
    return (
        "taproot"
        if encoding == "bech32m" and version == 1 and len(out) == 32
        else "segwit"
        if encoding == "bech32m"
        else None
    )


# ---------------------------------------------------------------------------- Ethereum
def eip55(address: str) -> str:
    """The checksummed (mixed-case) form of an Ethereum address."""
    lower = address.lower().removeprefix("0x")
    digest = keccak256(lower.encode()).hex()
    return "0x" + "".join(c.upper() if c.isalpha() and int(digest[i], 16) >= 8 else c for i, c in enumerate(lower))


# ---------------------------------------------------------------------------- recognition
@dataclass(frozen=True)
class Address:
    value: str  # normalised (Bitcoin as written, Ethereum lower-case)
    chain: str  # "bitcoin" | "evm" | "litecoin" | "tron" | "monero" | "solana"
    kind: str  # e.g. "legacy", "script", "segwit", "taproot", "account"
    traceable: bool
    checksum: str  # "verified" | "not present" | "format only"

    @property
    def label(self) -> str:
        return {"bitcoin": "Bitcoin", "evm": "Ethereum-compatible", "litecoin": "Litecoin", "tron": "Tron",
                "monero": "Monero", "solana": "Solana"}.get(self.chain, self.chain)  # fmt: skip


_EVM = re.compile(r"^0x[0-9a-fA-F]{40}$")


def classify(text: str) -> Address | None:
    """What kind of cryptocurrency address ``text`` is, with its checksum verified; None if it is not one."""
    t = text.strip()
    if _EVM.match(t):
        body = t[2:]
        mixed = body != body.lower() and body != body.upper()
        if mixed and eip55(t) != t:
            return None  # a capitalisation that fails EIP-55: mistyped or invented
        if t.lower() == "0x" + "0" * 40:
            return None
        return Address(t.lower(), "evm", "account", True, "verified" if mixed else "not present")
    if t[:3].lower() == "bc1":
        kind = _segwit_valid(t)
        return Address(t.lower(), "bitcoin", kind, True, "verified") if kind else None
    if t[:1] in ("1", "3") and 25 <= len(t) <= 35:
        payload = _base58check(t)
        if payload is not None and len(payload) == 21 and payload[0] in (0x00, 0x05):
            return Address(t, "bitcoin", "legacy" if payload[0] == 0 else "script", True, "verified")
        return None
    if t[:4].lower() == "ltc1" and _bech32_decode(t):
        return Address(t.lower(), "litecoin", "segwit", False, "verified")
    if t[:1] in ("L", "M") and 26 <= len(t) <= 34:
        payload = _base58check(t)
        if payload is not None and len(payload) == 21 and payload[0] in (0x30, 0x32):
            return Address(t, "litecoin", "legacy", False, "verified")
    if t.startswith("T") and len(t) == 34:
        payload = _base58check(t)
        if payload is not None and len(payload) == 21 and payload[0] == 0x41:
            return Address(t, "tron", "account", False, "verified")
    if t[:1] in ("4", "8") and len(t) in (95, 106) and all(c in _B58 for c in t):
        return Address(t, "monero", "account", False, "format only")
    return None


_CANDIDATES = re.compile(
    r"\b(0x[0-9a-fA-F]{40}|bc1[02-9ac-hj-np-z]{11,71}|BC1[02-9AC-HJ-NP-Z]{11,71}|[13][1-9A-HJ-NP-Za-km-z]{25,34}"
    r"|ltc1[02-9ac-hj-np-z]{11,71}|[LM][1-9A-HJ-NP-Za-km-z]{25,33}|T[1-9A-HJ-NP-Za-km-z]{33}"
    r"|[48][1-9A-HJ-NP-Za-km-z]{94}(?:[1-9A-HJ-NP-Za-km-z]{11})?)\b"
)


def find_addresses(text: str, limit: int = 100) -> list[Address]:
    """Every valid address in ``text`` (checksums verified), in order of first appearance."""
    found: dict[str, Address] = {}
    for match in _CANDIDATES.finditer(text[:5_000_000]):
        address = classify(match.group(1))
        if address is not None and address.value not in found:
            found[address.value] = address
            if len(found) >= limit:
                break
    return list(found.values())
