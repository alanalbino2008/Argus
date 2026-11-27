"""Accessibility: every page passes axe-core's WCAG 2.1 A + AA checks, in light and dark, on a phone, and with
the command palette and the phone's "More" sheet open.

Boots a real Argus with demonstration data and runs tests/a11y/axe_audit.mjs (Playwright + axe-core). Skipped
where those are not installed; CI's "Accessibility" job installs them, so a regression — text that loses its
contrast, a control without a name, broken ARIA — fails the build instead of shipping."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "tests" / "a11y" / "axe_audit.mjs"
KEY = "argus_a11y-admin-key-0123456789abcdefghijklmnopqrstuv"
BOOT = "import uvicorn, sys; from argus.api import server; uvicorn.run(server.app, host='127.0.0.1', port=int(sys.argv[1]), log_level='warning')"


def _tooling_available() -> bool:
    node = shutil.which("node")
    if not node:
        return False
    probe = ("const r = require('node:module').createRequire(process.cwd() + '/'); r.resolve('playwright');"
             "if (!process.env.ARGUS_AXE_JS) r.resolve('axe-core/axe.min.js');")  # fmt: skip
    return subprocess.run([node, "-e", probe], cwd=ROOT, capture_output=True, check=False).returncode == 0  # noqa: S603


if os.environ.get("ARGUS_REQUIRE_A11Y") and not _tooling_available():
    # In CI's Accessibility job a missing tool must fail the build, not quietly skip the only test in it.
    raise RuntimeError("ARGUS_REQUIRE_A11Y is set but Playwright / axe-core cannot be found")
pytestmark = pytest.mark.skipif(not _tooling_available(), reason="Playwright and axe-core are not installed (npm)")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _request(url: str, method: str = "GET") -> int:
    req = urllib.request.Request(url, method=method, headers={"Authorization": f"Bearer {KEY}"})  # noqa: S310
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 - our own server on localhost
        return resp.status


@pytest.fixture
def argus_server(tmp_path):
    port = _free_port()
    env = {**os.environ, "ARGUS_DATABASE_URL": f"sqlite+aiosqlite:///{tmp_path / 'a11y.db'}",
           "ARGUS_BOOTSTRAP_ADMIN_KEY": KEY, "ARGUS_MONITORS_ENABLED": "false",
           "ARGUS_EXPOSURE_MONITORING_ENABLED": "false", "ARGUS_RANSOMWARE_FEED_URL": ""}  # fmt: skip
    proc = subprocess.Popen([sys.executable, "-c", BOOT, str(port)], cwd=ROOT, env=env,  # noqa: S603
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)  # fmt: skip
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 60
        while True:
            try:
                if _request(f"{base}/") == 200:
                    break
            except OSError:
                pass
            if time.monotonic() > deadline or proc.poll() is not None:
                raise RuntimeError("Argus did not start:\n" + (proc.stdout.read().decode() if proc.stdout else ""))
            time.sleep(0.3)
        assert _request(f"{base}/api/demo", "POST") in (200, 201)  # pages with real content, not just empty states
        yield base
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_every_page_meets_wcag_21_aa(argus_server):
    result = subprocess.run([shutil.which("node"), str(AUDIT), argus_server, KEY], cwd=ROOT,  # noqa: S603
                            capture_output=True, text=True, timeout=600, check=False)  # fmt: skip
    try:
        report = json.loads(result.stdout)
    except ValueError:
        pytest.fail(f"The audit did not run:\n{result.stdout[-3000:]}\n{result.stderr[-3000:]}")
    assert report["scanned"] >= 45, report["scanned"]  # every page, three ways, plus the palette and the sheet
    assert not report["errors"], report["errors"]
    assert report["failing"] == 0, json.dumps(report["violations"], indent=1)[:12000]
