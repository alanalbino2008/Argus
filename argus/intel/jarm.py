"""JARM: an active TLS server fingerprint (Salesforce, 2020).

Ten deliberately unusual TLS ClientHellos (different versions, cipher orders, extension orders,
ALPN lists and GREASE) are sent to a server. What it picks in reply (cipher, version, ALPN and
the order of its extensions) depends on its TLS library, version and configuration, so it is
hashed into a 62-character fingerprint:

* 30 characters: for each probe, the chosen cipher (2 hex digits: its position in a fixed list)
  and version (1 letter);
* 32 characters: the first half of the SHA-256 of every probe's ALPN and extension list.

Identical JARMs mean "configured the same way", which clusters a C2 framework's servers, a
phishing kit's hosting or an organisation's estate. Shodan (``ssl.jarm:``) and Censys
(``host.services.jarm.fingerprint``) index it. A hash of all zeros means no TLS answer at all.

This follows the original reference implementation byte for byte. The tests check it against an
independent implementation (pyjarm) on live local TLS servers in several configurations.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import random
from dataclasses import dataclass
from struct import pack

FAILED = "|||"
ZERO_JARM = "0" * 62
READ_BYTES = 1484  # what the reference reads from each server reply

# The cipher suites offered (reference order). NO1.3 drops the TLS 1.3 suites (0x13xx).
_ALL_CIPHERS = [bytes.fromhex(c) for c in ["0016", "0033", "0067", "c09e", "c0a2", "009e", "0039", "006b", "c09f", "c0a3", "009f", "0045", "00be", "0088", "00c4", "009a", "c008", "c009", "c023", "c0ac", "c0ae", "c02b", "c00a", "c024", "c0ad", "c0af", "c02c", "c072", "c073", "cca9", "1302", "1301", "cc14", "c007", "c012", "c013", "c027", "c02f", "c014", "c028", "c030", "c060", "c061", "c076", "c077", "cca8", "1305", "1304", "1303", "cc13", "c011", "000a", "002f", "003c", "c09c", "c0a0", "009c", "0035", "003d", "c09d", "c0a1", "009d", "0041", "00ba", "0084", "00c0", "0007", "0004", "0005"]]  # fmt: skip
_NO_13_CIPHERS = [c for c in _ALL_CIPHERS if not c.startswith(b"\x13")]

# Position of the selected cipher in this list (1-based, two hex digits) goes into the hash.
_HASH_CIPHERS = [
    "0004",
    "0005",
    "0007",
    "000a",
    "0016",
    "002f",
    "0033",
    "0035",
    "0039",
    "003c",
    "003d",
    "0041",
    "0045",
    "0067",
    "006b",
    "0084",
    "0088",
    "009a",
    "009c",
    "009d",
    "009e",
    "009f",
    "00ba",
    "00be",
    "00c0",
    "00c4",
    "c007",
    "c008",
    "c009",
    "c00a",
    "c011",
    "c012",
    "c013",
    "c014",
    "c023",
    "c024",
    "c027",
    "c028",
    "c02b",
    "c02c",
    "c02f",
    "c030",
    "c060",
    "c061",
    "c072",
    "c073",
    "c076",
    "c077",
    "c09c",
    "c09d",
    "c09e",
    "c09f",
    "c0a0",
    "c0a1",
    "c0a2",
    "c0a3",
    "c0ac",
    "c0ad",
    "c0ae",
    "c0af",
    "cc13",
    "cc14",
    "cca8",
    "cca9",
    "1301",
    "1302",
    "1303",
    "1304",
    "1305",
]

_ALPN = [b"\x08http/0.9", b"\x08http/1.0", b"\x08http/1.1", b"\x06spdy/1", b"\x06spdy/2", b"\x06spdy/3",
         b"\x02h2", b"\x03h2c", b"\x02hq"]  # fmt: skip
_RARE_ALPN = [b"\x08http/0.9", b"\x08http/1.0", b"\x06spdy/1", b"\x06spdy/2", b"\x06spdy/3", b"\x03h2c", b"\x02hq"]
_GREASE = [bytes([b, b]) for b in range(0x0A, 0x100, 0x10)]

# (record version, hello version)
_VERSIONS = {"TLS_1.1": (b"\x03\x02", b"\x03\x02"), "TLS_1.2": (b"\x03\x03", b"\x03\x03"),
             "TLS_1.3": (b"\x03\x01", b"\x03\x03")}  # fmt: skip


@dataclass(frozen=True)
class Probe:
    version: str
    ciphers: str  # "ALL" | "NO1.3"
    cipher_order: str  # FORWARD | REVERSE | TOP_HALF | BOTTOM_HALF | MIDDLE_OUT
    grease: bool
    rare_alpn: bool
    support: str  # "1.2_SUPPORT" | "1.3_SUPPORT" | "NO_SUPPORT"
    extension_order: str  # FORWARD | REVERSE


# The ten probes, in the order their answers are hashed.
PROBES = (
    Probe("TLS_1.2", "ALL", "FORWARD", False, False, "1.2_SUPPORT", "REVERSE"),
    Probe("TLS_1.2", "ALL", "REVERSE", False, False, "1.2_SUPPORT", "FORWARD"),
    Probe("TLS_1.2", "ALL", "TOP_HALF", False, False, "NO_SUPPORT", "FORWARD"),
    Probe("TLS_1.2", "ALL", "BOTTOM_HALF", False, True, "NO_SUPPORT", "FORWARD"),
    Probe("TLS_1.2", "ALL", "MIDDLE_OUT", True, True, "NO_SUPPORT", "REVERSE"),
    Probe("TLS_1.1", "ALL", "FORWARD", False, False, "NO_SUPPORT", "FORWARD"),
    Probe("TLS_1.3", "ALL", "FORWARD", False, False, "1.3_SUPPORT", "REVERSE"),
    Probe("TLS_1.3", "ALL", "REVERSE", False, False, "1.3_SUPPORT", "FORWARD"),
    Probe("TLS_1.3", "NO1.3", "FORWARD", False, False, "1.3_SUPPORT", "FORWARD"),
    Probe("TLS_1.3", "ALL", "MIDDLE_OUT", True, False, "1.3_SUPPORT", "REVERSE"),
)


def _mung(items: list[bytes], order: str) -> list[bytes]:
    n = len(items)
    if order == "FORWARD":
        return list(items)
    if order == "REVERSE":
        return items[::-1]
    if order == "BOTTOM_HALF":
        return items[n // 2 + 1 :] if n % 2 == 1 else items[n // 2 :]
    if order == "TOP_HALF":
        out = [items[n // 2]] if n % 2 == 1 else []
        return out + _mung(_mung(items, "REVERSE"), "BOTTOM_HALF")
    if order == "MIDDLE_OUT":
        middle = n // 2
        out = []
        if n % 2 == 1:
            out.append(items[middle])
            for i in range(1, middle + 1):
                out += [items[middle + i], items[middle - i]]
        else:
            for i in range(1, middle + 1):
                out += [items[middle - 1 + i], items[middle - i]]
        return out
    raise ValueError(order)


def _extensions(host: str, probe: Probe) -> bytes:
    ext = b""
    if probe.grease:
        ext += random.choice(_GREASE) + b"\x00\x00"
    name = host.encode()
    ext += b"\x00\x00" + pack(">H", len(name) + 5) + pack(">H", len(name) + 3) + b"\x00" + pack(">H", len(name)) + name
    ext += b"\x00\x17\x00\x00"  # extended master secret
    ext += b"\x00\x01\x00\x01\x01"  # max fragment length
    ext += b"\xff\x01\x00\x01\x00"  # renegotiation info
    ext += b"\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19"  # supported groups
    ext += b"\x00\x0b\x00\x02\x01\x00"  # EC point formats
    ext += b"\x00\x23\x00\x00"  # session ticket
    alpns = b"".join(_mung(_RARE_ALPN if probe.rare_alpn else _ALPN, probe.extension_order))
    ext += b"\x00\x10" + pack(">H", len(alpns) + 2) + pack(">H", len(alpns)) + alpns
    ext += b"\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01"
    share = (random.choice(_GREASE) + b"\x00\x01\x00" if probe.grease else b"") + b"\x00\x1d\x00\x20" + os.urandom(32)
    ext += b"\x00\x33" + pack(">H", len(share) + 2) + pack(">H", len(share)) + share
    ext += b"\x00\x2d\x00\x02\x01\x01"  # PSK key exchange modes
    if probe.version == "TLS_1.3" or probe.support == "1.2_SUPPORT":
        versions = [b"\x03\x01", b"\x03\x02", b"\x03\x03"]
        if probe.support != "1.2_SUPPORT":
            versions.append(b"\x03\x04")
        body = (random.choice(_GREASE) if probe.grease else b"") + b"".join(_mung(versions, probe.extension_order))
        ext += b"\x00\x2b" + pack(">H", len(body) + 1) + pack(">B", len(body)) + body
    return pack(">H", len(ext)) + ext


def client_hello(host: str, probe: Probe) -> bytes:
    """One JARM ClientHello record for ``host`` (used as the SNI)."""
    record_version, hello_version = _VERSIONS[probe.version]
    ciphers = _mung(_ALL_CIPHERS if probe.ciphers == "ALL" else _NO_13_CIPHERS, probe.cipher_order)
    if probe.grease:
        ciphers = [random.choice(_GREASE), *ciphers]
    suites = b"".join(ciphers)
    hello = hello_version + os.urandom(32) + b"\x20" + os.urandom(32)
    hello += pack(">H", len(suites)) + suites + b"\x01\x00" + _extensions(host, probe)
    handshake = b"\x01\x00" + pack(">H", len(hello)) + hello
    return b"\x16" + record_version + pack(">H", len(handshake)) + handshake


def parse_server_hello(data: bytes | None) -> str:
    """``cipher|version|alpn|extensions`` from a server's first reply, or ``|||``."""
    try:
        if not data or data[0] == 21:  # nothing, or a TLS alert
            return FAILED
        if not (data[0] == 22 and data[5] == 2):  # not a ServerHello
            return FAILED
        server_hello_length = int.from_bytes(data[3:5], "big")
        counter = data[43]  # session id length
        cipher = data[counter + 44 : counter + 46].hex()
        version = data[9:11].hex()
        return f"{cipher}|{version}|{_extension_info(data, counter, server_hello_length)}"
    except IndexError:
        return FAILED


def _extension_info(data: bytes, counter: int, server_hello_length: int) -> str:
    try:
        if (
            data[counter + 47] == 11
            or data[counter + 50 : counter + 53] == b"\x0e\xac\x0b"
            or data[82:85] == b"\x0f\xf0\x0b"
            or counter + 42 >= server_hello_length
        ):
            return "|"
        count = 49 + counter
        maximum = int.from_bytes(data[counter + 47 : counter + 49], "big") + (count - 1)
        types: list[bytes] = []
        alpn = ""
        while count < maximum:
            ext_type = data[count : count + 2]
            length = int.from_bytes(data[count + 2 : count + 4], "big")
            value = data[count + 4 : count + 4 + length]
            types.append(ext_type)
            if ext_type == b"\x00\x10" and not alpn and length:
                alpn = value[3:].decode("latin-1")
            count += length + 4
        return f"{alpn}|{'-'.join(t.hex() for t in types)}"
    except IndexError:
        return "|"


def jarm_hash(answers: list[str]) -> str:
    """The 62-character JARM from the ten parsed answers (all zeros when nothing answered)."""
    if all(a == FAILED for a in answers):
        return ZERO_JARM
    fuzzy = ""
    alpn_and_extensions = ""
    for answer in answers:
        cipher, version, alpn, extensions = ([*answer.split("|"), "", "", "", ""])[:4]
        fuzzy += _cipher_code(cipher) + _version_code(version)
        alpn_and_extensions += alpn + extensions
    return fuzzy + hashlib.sha256(alpn_and_extensions.encode()).hexdigest()[:32]


def _cipher_code(cipher: str) -> str:
    if not cipher:
        return "00"
    position = _HASH_CIPHERS.index(cipher) + 1 if cipher in _HASH_CIPHERS else len(_HASH_CIPHERS) + 1
    return f"{position:02x}"


def _version_code(version: str) -> str:
    return "abcdef"[int(version[3:4])] if version else "0"


async def _probe(connect_host: str, port: int, payload: bytes, timeout: float) -> bytes | None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(connect_host, port), timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    try:
        writer.write(payload)
        await asyncio.wait_for(writer.drain(), timeout)
        return await asyncio.wait_for(reader.read(READ_BYTES), timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    finally:
        writer.close()
        with contextlib.suppress(OSError, asyncio.TimeoutError):
            await asyncio.wait_for(writer.wait_closed(), 2)


async def fingerprint(connect_host: str, port: int, server_name: str, *, timeout: float = 8.0) -> dict[str, object]:
    """Run the ten probes against ``connect_host:port`` (``server_name`` as SNI); probes run one at a time.

    Returns ``{"jarm": hash, "answered": n}`` where ``answered`` counts probes that got a ServerHello.
    """
    answers = []
    for probe in PROBES:
        reply = await _probe(connect_host, port, client_hello(server_name, probe), timeout)
        answers.append(parse_server_hello(reply))
    return {"jarm": jarm_hash(answers), "answered": sum(a != FAILED for a in answers)}
