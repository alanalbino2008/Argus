"""Check a freshly built Argus desktop app really works, before it is published.

    python packaging/desktop/smoke_test.py dist/Argus/Argus[.exe]

Starts the app with a throwaway data folder and checks that it answers on 127.0.0.1, serves the
web app, created its database, knows it is the desktop app, finds its screenshot browser, that a
second start just hands over to the running copy, and that Quit stops it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def get(url: str, data: bytes | None = None, origin: str = "") -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=data, method="POST" if data is not None else "GET")  # noqa: S310
    if origin:
        req.add_header("Origin", origin)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 - loopback only
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except OSError:  # not listening (yet)
        return 0, b""


def check(ok: bool, what: str) -> None:
    print(("PASS " if ok else "FAIL ") + what, flush=True)
    if not ok:
        raise SystemExit(1)


def main(app: str) -> None:
    home = Path(tempfile.mkdtemp(prefix="argus-smoke-"))
    env = {**os.environ, "ARGUS_HOME": str(home), "ARGUS_NO_BROWSER": "1", "BROWSER": "true"}
    proc = subprocess.Popen([app], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # noqa: S603
    state = home / "desktop.json"
    deadline = time.monotonic() + 120
    port = None
    while time.monotonic() < deadline and port is None:
        time.sleep(1)
        check(proc.poll() is None, "the app keeps running")
        if state.is_file():
            port = json.loads(state.read_text())["port"]
            while time.monotonic() < deadline and get(f"http://127.0.0.1:{port}/api/live")[0] != 200:
                time.sleep(1)
    check(port is not None, f"started and answered within 2 minutes (port {port})")
    base = f"http://127.0.0.1:{port}"
    status, page = get(base + "/")
    check(status == 200 and b"<html" in page.lower(), "serves the Argus web app")
    info = json.loads(get(base + "/api/personal/status")[1])
    check(info["edition"] == "personal" and info["desktop"] is True, "runs as Argus Personal, desktop app")
    check((home / "argus.db").is_file() and (home / "secret.key").is_file(), "created its database and key")
    check((home / "logs" / "argus.log").is_file(), "writes its log file")
    test = subprocess.run([app, "--self-test"], env=env, timeout=180, check=False)  # noqa: S603
    report = json.loads((home / "self-test.json").read_text())
    print(json.dumps(report, indent=2))
    check(test.returncode == 0 and report["screenshot"], "the bundled screenshot browser takes a screenshot")
    started = time.monotonic()
    second = subprocess.run([app], env=env, timeout=60, check=False)  # noqa: S603
    check(second.returncode == 0 and time.monotonic() - started < 30, "a second start hands over to the running copy")
    check(
        get(base + "/api/personal/quit", b"", origin="https://evil.example")[0] == 403, "other websites can't quit it"
    )
    check(get(base + "/api/personal/quit", b"", origin=base)[0] == 200, "Quit Argus answers")
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        check(False, "stops after Quit")
    check(not state.exists(), "stops after Quit and tidies up")
    print("All checks passed")


if __name__ == "__main__":
    main(sys.argv[1])
