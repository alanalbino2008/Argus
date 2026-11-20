"""SSH server fingerprints: the banner and HASSH-server (Salesforce, 2018).

Before any encryption, an SSH server announces itself twice in clear text: its identification
banner (``SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6``) and its KEXINIT message, the algorithms it
supports, in order of preference. That list depends on the SSH software, its version and how it
was configured, so its hash identifies a server build across the internet:

    hasshServerAlgorithms = kex ; encryption(server→client) ; mac(server→client) ; compression(server→client)
    hasshServer           = md5(hasshServerAlgorithms)

Shodan indexes it as ``ssh.hassh``. Collecting it needs only the banner exchange and the
server's first packet: no key exchange, no login attempt, nothing a server logs as an auth event.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import struct
from typing import Any

CLIENT_BANNER = b"SSH-2.0-ArgusOSINT\r\n"
MAX_PREBANNER_LINES = 20  # RFC 4253 allows lines before the identification string
MAX_LINE = 255
MAX_PACKET = 35_000
MSG_KEXINIT = 20

KEXINIT_FIELDS = (
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_client_to_server",
    "encryption_server_to_client",
    "mac_client_to_server",
    "mac_server_to_client",
    "compression_client_to_server",
    "compression_server_to_client",
    "languages_client_to_server",
    "languages_server_to_client",
)


class SshProtocolError(ValueError):
    """The peer did not speak SSH-2 the way a server should."""


def parse_kexinit(payload: bytes) -> dict[str, list[str]]:
    """The name-lists of an SSH_MSG_KEXINIT payload (starting at the message number)."""
    if not payload or payload[0] != MSG_KEXINIT:
        raise SshProtocolError("first packet is not KEXINIT")
    offset = 1 + 16  # message number, cookie
    lists: dict[str, list[str]] = {}
    for name in KEXINIT_FIELDS:
        if offset + 4 > len(payload):
            raise SshProtocolError("truncated KEXINIT")
        (length,) = struct.unpack(">I", payload[offset : offset + 4])
        offset += 4
        if offset + length > len(payload):
            raise SshProtocolError("truncated name-list")
        raw = payload[offset : offset + length].decode("ascii", errors="replace")
        lists[name] = raw.split(",") if raw else []
        offset += length
    return lists


def hassh_server(lists: dict[str, list[str]]) -> tuple[str, str]:
    """(hasshServer, hasshServerAlgorithms) for a parsed KEXINIT."""
    algorithms = ";".join(
        ",".join(lists[key])
        for key in ("kex_algorithms", "encryption_server_to_client", "mac_server_to_client",
                    "compression_server_to_client")
    )  # fmt: skip
    return hashlib.md5(algorithms.encode(), usedforsecurity=False).hexdigest(), algorithms


def parse_banner(line: bytes) -> dict[str, str]:
    text = line.decode("utf-8", errors="replace").strip()
    parts = text.split(" ", 1)
    proto, _, software = parts[0].partition("-")[2].partition("-")
    return {"banner": text[:255], "protocol": proto, "software": software, "comments": parts[1] if len(parts) > 1 else ""}


async def _read_banner(reader: asyncio.StreamReader) -> bytes:
    for _ in range(MAX_PREBANNER_LINES):
        line = await reader.readline()
        if not line:
            raise SshProtocolError("connection closed before the SSH banner")
        if line.startswith(b"SSH-"):
            return line[:MAX_LINE]
    raise SshProtocolError("no SSH banner")


async def _read_packet(reader: asyncio.StreamReader) -> bytes:
    header = await reader.readexactly(5)
    length, padding = struct.unpack(">IB", header)
    if not 5 <= length <= MAX_PACKET or padding >= length:
        raise SshProtocolError("implausible packet length")
    body = await reader.readexactly(length - 1)
    return body[: length - 1 - padding]


async def fingerprint(connect_host: str, port: int, *, timeout: float = 8.0) -> dict[str, Any]:
    """Banner and HASSH-server of the SSH server at ``connect_host:port``.

    Raises ``OSError`` / ``asyncio.TimeoutError`` when unreachable and :class:`SshProtocolError`
    when what answers is not an SSH-2 server.
    """
    reader, writer = await asyncio.wait_for(asyncio.open_connection(connect_host, port), timeout)
    try:
        banner = await asyncio.wait_for(_read_banner(reader), timeout)
        info: dict[str, Any] = parse_banner(banner)
        if info["protocol"] not in ("2.0", "1.99"):
            raise SshProtocolError(f"SSH protocol {info['protocol']!r} is not SSH-2")
        writer.write(CLIENT_BANNER)
        await asyncio.wait_for(writer.drain(), timeout)
        try:
            payload = await asyncio.wait_for(_read_packet(reader), timeout)
        except asyncio.IncompleteReadError as exc:
            raise SshProtocolError("connection closed before KEXINIT") from exc
        lists = parse_kexinit(payload)
        digest, algorithms = hassh_server(lists)
        return {
            **info,
            "hassh_server": digest,
            "hassh_server_algorithms": algorithms,
            "host_key_algorithms": lists["server_host_key_algorithms"],
            "kex_algorithms": lists["kex_algorithms"],
        }
    finally:
        writer.close()
        with contextlib.suppress(OSError, asyncio.TimeoutError):
            await asyncio.wait_for(writer.wait_closed(), 2)
