"""Preserve a web page as it was seen, with proof of what was captured and when.

A capture is a set of files plus a **manifest**:
* ``page.html``: the server's response, byte for byte;
* ``screenshot.png`` and ``rendered.html``: the page as a browser displayed it (needs a
  headless Chromium/Chrome);
* ``text.txt``: the visible text, for searching;
* ``headers.json``: the HTTP status, headers and redirect chain.

The manifest lists every file with its SHA-256, the URL, the final URL, the time, the tool and
what the browser was refused. The **capture digest** is the SHA-256 of the canonical manifest,
so changing any file, or any detail of the record, changes the digest.

Optionally the digest is sent to an **RFC 3161 timestamp authority**. Its signed reply is
independent proof that this exact evidence existed at that moment, verifiable later with
``openssl ts -verify`` without trusting Argus at all. Only the digest leaves Argus, never the
content.

Fetching follows the same SSRF rules as everything else in Argus: only public addresses, every
redirect re-checked, and the browser forced through :class:`GuardProxy`.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import glob
import hashlib
import html.parser
import json
import os
import secrets
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, ClassVar
from urllib.parse import urljoin, urlsplit

import aiohttp

from argus import __version__
from argus.core.settings import Settings
from argus.evidence.guard_proxy import GuardProxy
from argus.security.network import BlockedDestinationError, GuardedResolver, assert_public_host, configured_proxy_hosts

MAX_PAGE = 15 * 1024 * 1024
MAX_REDIRECTS = 5
BROWSER_TIMEOUT = 45.0
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 Argus-Capture"
)
# The headless shell first: it has no Google services, so it never "phones home" while you investigate.
BROWSER_CANDIDATES = ("chrome-headless-shell", "chromium-headless-shell", "chromium", "chromium-browser",
                      "google-chrome", "google-chrome-stable", "chrome")  # fmt: skip
SHELL_GLOB = "/opt/pw-browsers/chromium_headless_shell-*/*/chrome-headless-shell"
CHROMIUM_GLOB = "/opt/pw-browsers/chromium-*/chrome-linux*/chrome"
QUIET_FLAGS = (  # full Chrome/Chromium: switch off every background service that contacts Google
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-domain-reliability",
    "--disable-client-side-phishing-detection",
    "--disable-sync",
    "--disable-default-apps",
    "--no-pings",
    "--disable-breakpad",
    "--metrics-recording-only",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-features=Translate,MediaRouter,OptimizationHints,AutofillServerCommunication,SafeBrowsing",
)


class CaptureError(Exception):
    """The capture failed; the message is safe to show."""


@dataclass
class Capture:
    manifest: dict[str, Any]
    digest: str
    files: dict[str, tuple[str, bytes]]  # name -> (media type, content)
    timestamp_token: bytes | None = None
    warnings: list[str] = field(default_factory=list)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(manifest: dict[str, Any]) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def check_url(url: str, *, allow_private: bool) -> str:
    url = url.strip()
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise CaptureError("Enter a full web address starting with http:// or https://")
    if len(url) > 2048 or any(c in url for c in "\r\n\t "):
        raise CaptureError("That address is not valid")
    if parts.username or parts.password:
        raise CaptureError("Remove the user name and password from the address")
    if not allow_private:
        try:
            assert_public_host(parts.hostname)
        except BlockedDestinationError as exc:
            raise CaptureError("Only pages on the public internet can be captured") from exc
    return url


# ---------------------------------------------------------------------------- visible text
class _Text(html.parser.HTMLParser):
    SKIP: ClassVar[frozenset[str]] = frozenset({"script", "style", "noscript", "template", "svg"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.title = ""
        self._skip = 0
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        if tag in self.SKIP:
            self._skip += 1
        self._in_title = tag == "title"
        if tag in ("p", "div", "br", "li", "h1", "h2", "h3", "h4", "tr", "section", "article"):
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self.SKIP and self._skip:
            self._skip -= 1
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and not self.title:
            self.title = data.strip()[:300]
        if not self._skip and data.strip():
            self.parts.append(data.strip() + " ")


def visible_text(markup: str) -> tuple[str, str]:
    parser = _Text()
    with contextlib.suppress(Exception):
        parser.feed(markup)
    lines = [" ".join(line.split()) for line in "".join(parser.parts).splitlines()]
    return parser.title, "\n".join(line for line in lines if line)


# ---------------------------------------------------------------------------- fetching
async def fetch(url: str, settings: Settings) -> dict[str, Any]:
    """The server's response to ``url``, following (and re-checking) up to five redirects."""
    resolver = None if settings.allow_private_targets else GuardedResolver(trusted_hosts=configured_proxy_hosts())
    chain: list[dict[str, Any]] = []
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(resolver=resolver), timeout=aiohttp.ClientTimeout(total=30),
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}, trust_env=True,
    ) as http:  # fmt: skip
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            check_url(current, allow_private=settings.allow_private_targets)
            try:
                async with http.get(current, allow_redirects=False) as resp:
                    body = await resp.content.read(MAX_PAGE + 1)
                    entry = {"url": current, "status": resp.status, "headers": dict(resp.headers.items())}
                    chain.append(entry)
                    location = resp.headers.get("Location")
                    if 300 <= resp.status < 400 and location:
                        current = urljoin(current, location)
                        continue
                    if len(body) > MAX_PAGE:
                        raise CaptureError("The page is larger than 15 MB")
                    return {"final_url": current, "status": resp.status, "headers": entry["headers"],
                            "content_type": resp.headers.get("Content-Type", ""), "body": body, "chain": chain}  # fmt: skip
            except BlockedDestinationError as exc:
                raise CaptureError("The page redirected to an address that is not on the public internet") from exc
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                raise CaptureError(f"Could not load the page ({type(exc).__name__})") from exc
    raise CaptureError("Too many redirects")


# ---------------------------------------------------------------------------- the browser
def find_browser(settings: Settings) -> str | None:
    if settings.capture_browser == "off":
        return None
    if settings.capture_browser not in ("", "auto"):
        return settings.capture_browser if os.path.isfile(settings.capture_browser) else None
    shells = [shutil.which(n) for n in BROWSER_CANDIDATES[:2]] + sorted(glob.glob(SHELL_GLOB))[-1:]
    full = [shutil.which(n) for n in BROWSER_CANDIDATES[2:]] + sorted(glob.glob(CHROMIUM_GLOB))[-1:]
    return next((path for path in shells + full if path), None)


def is_headless_shell(browser: str) -> bool:
    return "headless-shell" in os.path.basename(browser) or "headless_shell" in browser


class _DevTools:
    """A minimal Chrome DevTools Protocol client over the browser's WebSocket (one page session)."""

    def __init__(self, ws: Any):
        self.ws = ws
        self._next = 0
        self._pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self.events: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.session: str | None = None
        self._reader = asyncio.create_task(self._read())

    async def _read(self) -> None:
        async for msg in self.ws:
            if msg.type != aiohttp.WSMsgType.TEXT:
                break
            data = json.loads(msg.data)
            if "id" in data and data["id"] in self._pending:
                self._pending.pop(data["id"]).set_result(data)
            elif "method" in data:
                await self.events.put(data)
        for future in self._pending.values():
            if not future.done():
                future.set_exception(CaptureError("The browser closed unexpectedly"))

    async def call(self, method: str, params: dict[str, Any] | None = None, *, page: bool = True,
                   timeout: float = 20.0) -> dict[str, Any]:  # fmt: skip
        self._next += 1
        message: dict[str, Any] = {"id": self._next, "method": method, "params": params or {}}
        if page and self.session:
            message["sessionId"] = self.session
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._pending[self._next] = future
        await self.ws.send_str(json.dumps(message))
        reply = await asyncio.wait_for(future, timeout)
        if "error" in reply:
            raise CaptureError(f"The browser refused {method}: {reply['error'].get('message', '')}"[:200])
        return dict(reply.get("result") or {})

    async def close(self) -> None:
        self._reader.cancel()
        with contextlib.suppress(Exception):
            await self.ws.close()


async def _devtools_url(proc: asyncio.subprocess.Process) -> str:
    if proc.stderr is None:
        raise CaptureError("The browser did not start")
    while True:
        line = await asyncio.wait_for(proc.stderr.readline(), 15)
        if not line:
            raise CaptureError("The browser did not start")
        text = line.decode(errors="replace")
        if "DevTools listening on " in text:
            return text.split("DevTools listening on ", 1)[1].strip()


async def _load(dt: _DevTools, url: str, notes: list[str]) -> None:
    """Navigate and wait for the load event, dismissing pop-up dialogs a page uses to stall capture."""
    await dt.call("Page.navigate", {"url": url})
    deadline = asyncio.get_running_loop().time() + 25
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            notes.append("The page had not finished loading after 25 seconds; captured as it was")
            return
        try:
            event = await asyncio.wait_for(dt.events.get(), remaining)
        except asyncio.TimeoutError:
            continue
        method = event.get("method")
        if method == "Page.javascriptDialogOpening":
            notes.append(f"Dismissed a pop-up ({event['params'].get('type', 'dialog')}) the page opened: "
                         f"{str(event['params'].get('message', ''))[:120]}")  # fmt: skip
            with contextlib.suppress(CaptureError, asyncio.TimeoutError):
                await dt.call("Page.handleJavaScriptDialog", {"accept": False}, timeout=5)
        elif method == "Page.loadEventFired":
            await asyncio.sleep(1.5)  # let late content settle
            return


async def render(url: str, browser: str, settings: Settings) -> dict[str, Any]:
    """Full-page screenshot and rendered DOM, with every request forced through the guard proxy."""
    notes: list[str] = []
    async with GuardProxy(allow_private=settings.allow_private_targets) as proxy:
        with tempfile.TemporaryDirectory(prefix="argus-capture-") as tmp:
            mode = [] if is_headless_shell(browser) else ["--headless=new", *QUIET_FLAGS]
            argv = [
                browser, *mode, "--disable-gpu", "--hide-scrollbars", "--mute-audio", "--disable-extensions",
                f"--user-agent={USER_AGENT}", f"--proxy-server=http://127.0.0.1:{proxy.port}",
                "--proxy-bypass-list=<-loopback>", f"--user-data-dir={tmp}/profile", "--remote-debugging-port=0",
                "--remote-allow-origins=*", "about:blank",
            ]  # fmt: skip
            if os.geteuid() == 0:  # Chrome refuses to run as root with its sandbox
                argv.insert(1, "--no-sandbox")
            proc = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.DEVNULL,
                                                        stderr=asyncio.subprocess.PIPE)  # fmt: skip
            screenshot = dom = None
            version = os.path.basename(browser)
            try:
                ws_url = await _devtools_url(proc)
                async with aiohttp.ClientSession() as local:  # loopback to our own browser only
                    ws = await local.ws_connect(ws_url, max_msg_size=64 * 1024 * 1024)
                    dt = _DevTools(ws)
                    try:
                        version = (await dt.call("Browser.getVersion", page=False)).get("product", version)
                        await dt.call("Browser.setDownloadBehavior", {"behavior": "deny"}, page=False)
                        target = await dt.call("Target.createTarget", {"url": "about:blank"}, page=False)
                        attached = await dt.call("Target.attachToTarget", {"targetId": target["targetId"],
                                                                           "flatten": True}, page=False)  # fmt: skip
                        dt.session = attached["sessionId"]
                        await dt.call("Page.enable")
                        await dt.call("Emulation.setDeviceMetricsOverride",
                                      {"width": 1366, "height": 900, "deviceScaleFactor": 1, "mobile": False})  # fmt: skip
                        await asyncio.wait_for(_load(dt, url, notes), BROWSER_TIMEOUT)
                        metrics = await dt.call("Page.getLayoutMetrics")
                        size = metrics.get("cssContentSize") or metrics.get("contentSize") or {}
                        height = int(min(max(size.get("height", 900), 900), 16000))
                        shot = await dt.call("Page.captureScreenshot", {
                            "format": "png", "captureBeyondViewport": True,
                            "clip": {"x": 0, "y": 0, "width": 1366, "height": height, "scale": 1}}, timeout=40)  # fmt: skip
                        screenshot = base64.b64decode(shot.get("data", ""))
                        if height == 16000:
                            notes.append("The page is very long; the screenshot shows the first 16,000 pixels")
                        result = await dt.call("Runtime.evaluate", {"expression": "document.documentElement.outerHTML",
                                                                    "returnByValue": True})  # fmt: skip
                        dom = str((result.get("result") or {}).get("value") or "").encode()
                        with contextlib.suppress(CaptureError, asyncio.TimeoutError):
                            await dt.call("Browser.close", page=False, timeout=5)
                    finally:
                        await dt.close()
            except (CaptureError, asyncio.TimeoutError, aiohttp.ClientError, OSError, KeyError) as exc:
                notes.append(f"The browser could not finish ({type(exc).__name__}: {str(exc)[:120]})")
            finally:
                if proc.returncode is None:
                    proc.kill()
                await proc.wait()
    return {
        "screenshot": screenshot or None,
        "dom": dom if dom and dom.strip() else None,
        "browser": version,
        "blocked": sorted(set(proxy.log.blocked)),
        "notes": notes,
    }


# ---------------------------------------------------------------------------- RFC 3161 timestamps
def _der(tag: int, body: bytes) -> bytes:
    n = len(body)
    length = (
        bytes([n])
        if n < 0x80
        else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    )
    return bytes([tag]) + length + body


def timestamp_request(digest_hex: str, nonce: int) -> bytes:
    """A DER TimeStampReq (RFC 3161) for a SHA-256 digest, asking for the TSA's certificate."""
    sha256_oid = bytes.fromhex("0609608648016503040201")
    algorithm = _der(0x30, sha256_oid + b"\x05\x00")
    imprint = _der(0x30, algorithm + _der(0x04, bytes.fromhex(digest_hex)))
    nonce_bytes = nonce.to_bytes((nonce.bit_length() + 8) // 8, "big")
    return _der(0x30, _der(0x02, b"\x01") + imprint + _der(0x02, nonce_bytes) + _der(0x01, b"\xff"))


def _read(data: bytes, offset: int) -> tuple[int, int, int]:
    """(tag, content start, content length) of the DER element at ``offset``."""
    tag, first = data[offset], data[offset + 1]
    if first < 0x80:
        return tag, offset + 2, first
    size = first & 0x7F
    return tag, offset + 2 + size, int.from_bytes(data[offset + 2 : offset + 2 + size], "big")


def timestamp_granted(reply: bytes) -> bool:
    """True if a TimeStampResp says granted (0) or granted with modifications (1)."""
    try:
        tag, start, _ = _read(reply, 0)
        tag2, start2, _ = _read(reply, start)  # PKIStatusInfo
        tag3, start3, length3 = _read(reply, start2)  # status INTEGER
        return (
            tag == tag2 == 0x30 and tag3 == 0x02 and int.from_bytes(reply[start3 : start3 + length3], "big") in (0, 1)
        )
    except IndexError:
        return False


async def trusted_timestamp(digest_hex: str, settings: Settings) -> bytes | None:
    url = settings.evidence_timestamp_url
    if not url:
        return None
    check_url(url, allow_private=settings.allow_private_targets)
    resolver = None if settings.allow_private_targets else GuardedResolver(trusted_hosts=configured_proxy_hosts())
    body = timestamp_request(digest_hex, secrets.randbits(63))
    session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(resolver=resolver),
                                    timeout=aiohttp.ClientTimeout(total=20), trust_env=True)  # fmt: skip
    async with session as http, http.post(url, data=body, headers={"Content-Type": "application/timestamp-query"},
                                          allow_redirects=False) as resp:  # fmt: skip
        reply = await resp.content.read(64 * 1024)
    return reply if resp.status == 200 and timestamp_granted(reply) else None


# ---------------------------------------------------------------------------- putting it together
def build(manifest_base: dict[str, Any], files: dict[str, tuple[str, bytes]]) -> tuple[dict[str, Any], str]:
    manifest = {
        **manifest_base,
        "files": [
            {"name": name, "media_type": media, "size": len(data), "sha256": sha256(data)}
            for name, (media, data) in sorted(files.items())
        ],
        "tool": f"Argus {__version__}",
    }
    return manifest, sha256(canonical(manifest))


async def capture_url(url: str, settings: Settings) -> Capture:
    url = check_url(url, allow_private=settings.allow_private_targets)
    captured_at = datetime.now(timezone.utc).isoformat()
    page = await fetch(url, settings)
    warnings: list[str] = []
    files: dict[str, tuple[str, bytes]] = {}
    media = (page["content_type"].split(";")[0].strip() or "application/octet-stream").lower()
    is_html = media in ("text/html", "application/xhtml+xml")
    files["page.html" if is_html else "response.bin"] = (media, page["body"])
    files["headers.json"] = ("application/json", json.dumps(
        {"status": page["status"], "headers": page["headers"], "redirects": [
            {"url": c["url"], "status": c["status"]} for c in page["chain"]]}, indent=2).encode())  # fmt: skip
    title, text = "", ""
    browser_info: dict[str, Any] = {}
    browser = find_browser(settings)
    if browser and is_html:
        rendered = await render(url, browser, settings)
        browser_info = {"browser": rendered["browser"], "blocked": rendered["blocked"]}
        warnings += rendered["notes"]
        if rendered["screenshot"]:
            files["screenshot.png"] = ("image/png", rendered["screenshot"])
        else:
            warnings.append("The browser could not take a screenshot")
        if rendered["dom"]:
            files["rendered.html"] = ("text/html", rendered["dom"])
        if rendered["blocked"]:
            warnings.append(f"Refused {len(rendered['blocked'])} non-public address(es) the page tried to load")
    elif is_html:
        warnings.append("No headless browser is installed, so there is no screenshot (install Chromium)")
    if is_html:
        markup = (files.get("rendered.html") or files["page.html"])[1].decode("utf-8", errors="replace")
        title, text = visible_text(markup)
        files["text.txt"] = ("text/plain", text.encode())
    manifest, digest = build({
        "kind": "web_capture", "url": url, "final_url": page["final_url"], "status": page["status"],
        "title": title, "captured_at": captured_at, "method": "server", **browser_info,
    }, files)  # fmt: skip
    token = None
    try:
        token = await trusted_timestamp(digest, settings)
    except (aiohttp.ClientError, asyncio.TimeoutError, CaptureError, OSError) as exc:  # a bonus, not required
        warnings.append(f"The timestamp authority did not answer ({type(exc).__name__})")
    if settings.evidence_timestamp_url and token is None and not any("timestamp" in w for w in warnings):
        warnings.append("The timestamp authority refused the request")
    return Capture(manifest, digest, files, token, warnings)


async def capture_upload(filename: str, media_type: str, data: bytes, settings: Settings, *, note: str = "") -> Capture:
    """Evidence the investigator already has (a screenshot of a private chat, a PDF, a photo)."""
    safe = os.path.basename(filename).replace("\x00", "")[:200] or "upload.bin"
    files = {safe: (media_type or "application/octet-stream", data)}
    manifest, digest = build({"kind": "upload", "original_filename": safe, "captured_at": datetime.now(timezone.utc).isoformat(),
                              "method": "upload", "note": note[:500]}, files)  # fmt: skip
    warnings: list[str] = []
    token = None
    try:
        token = await trusted_timestamp(digest, settings)
    except (aiohttp.ClientError, asyncio.TimeoutError, CaptureError, OSError) as exc:
        warnings.append(f"The timestamp authority did not answer ({type(exc).__name__})")
    return Capture(manifest, digest, files, token, warnings)
