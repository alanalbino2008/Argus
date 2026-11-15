"""A tiny forward proxy that only lets a capture browser reach the public internet.

When Argus captures a web page with a headless browser, the *page* decides what else the
browser loads: images, scripts, frames. A hostile page could ask for
``http://169.254.169.254/latest/meta-data/`` (a cloud metadata service) and the screenshot would
show the answer: server-side request forgery through a browser.

So the browser is started with this proxy as its only route out (``--proxy-server``, and
``--proxy-bypass-list=<-loopback>`` so even ``localhost`` goes through it). For every connection
the proxy:

1. resolves the host name **itself** and keeps only public addresses (``resolve_public``);
2. connects to the **checked address**, never re-resolving, so a DNS answer that changes between
   the check and the connection (DNS rebinding) cannot slip through;
3. refuses everything else with ``403``, and records what it refused.

It speaks the two forms browsers use: ``CONNECT host:443`` for HTTPS (the TLS stays end-to-end
between browser and site) and absolute-URI requests for plain HTTP.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from argus.security.network import BlockedDestinationError, resolve_public

logger = logging.getLogger("argus.evidence.proxy")
IDLE_TIMEOUT = 30.0
MAX_HEADER = 64 * 1024


@dataclass
class ProxyLog:
    allowed: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)


class GuardProxy:
    def __init__(self, *, allow_private: bool = False):
        self.allow_private = allow_private
        self.log = ProxyLog()
        self._server: asyncio.base_events.Server | None = None
        self.port = 0

    async def __aenter__(self) -> GuardProxy:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._server.wait_closed(), 2)

    async def _address(self, host: str, port: int) -> str | None:
        if self.allow_private:
            return host
        try:
            return (await resolve_public(host, port))[0]
        except (BlockedDestinationError, OSError):
            return None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), IDLE_TIMEOUT)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, ConnectionError):
            writer.close()
            return
        if len(head) > MAX_HEADER:
            writer.close()
            return
        request_line, _, rest = head.partition(b"\r\n")
        try:
            method, target, version = request_line.decode("latin-1").split(" ", 2)
        except ValueError:
            writer.close()
            return
        if method.upper() == "CONNECT":
            host, _, port_text = target.rpartition(":")
            host, port = host.strip("[]"), int(port_text or 443)
            preface = b""
        else:
            parts = urlsplit(target)
            if parts.scheme != "http" or not parts.hostname:
                await self._refuse(writer, target)
                return
            host, port = parts.hostname, parts.port or 80
            path = parts.path or "/"
            if parts.query:
                path += "?" + parts.query
            # Re-issue as an origin-form request; drop hop-by-hop proxy headers.
            headers = [h for h in rest.split(b"\r\n") if h and not h.lower().startswith((b"proxy-", b"connection:"))]
            preface = f"{method} {path} {version}\r\n".encode("latin-1") + b"\r\n".join(
                [*headers, b"Connection: close"]) + b"\r\n\r\n"  # fmt: skip
        address = await self._address(host, port)
        if address is None:
            self.log.blocked.append(f"{host}:{port}")
            await self._refuse(writer, f"{host}:{port}")
            return
        try:
            up_reader, up_writer = await asyncio.wait_for(asyncio.open_connection(address, port), IDLE_TIMEOUT)
        except (OSError, asyncio.TimeoutError):
            await self._reply(writer, b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return
        self.log.allowed.append(f"{host}:{port}")
        if method.upper() == "CONNECT":
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await writer.drain()
        else:
            up_writer.write(preface)
            await up_writer.drain()
        await asyncio.gather(self._pipe(reader, up_writer), self._pipe(up_reader, writer), return_exceptions=True)

    async def _pipe(self, src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        try:
            while True:
                chunk = await asyncio.wait_for(src.read(65536), IDLE_TIMEOUT)
                if not chunk:
                    break
                dst.write(chunk)
                await dst.drain()
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            with contextlib.suppress(Exception):
                dst.close()

    async def _refuse(self, writer: asyncio.StreamWriter, what: str) -> None:
        logger.info("Capture proxy refused %s", what)
        await self._reply(writer, b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")

    async def _reply(self, writer: asyncio.StreamWriter, data: bytes) -> None:
        with contextlib.suppress(Exception):
            writer.write(data)
            await writer.drain()
            writer.close()
