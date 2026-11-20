"""Argus Personal as a desktop app: what runs when the investigator double-clicks the Argus icon.

* **One copy at a time.** If Argus is already running, the icon just opens it in the browser.
* **Only this computer.** Argus listens on 127.0.0.1, on the first free port from 8765.
* **Ready to use.** The installer carries the operator's account service address and licence key
  (``argus-desktop.json``), and a private screenshot browser for evidence captures, so there is
  nothing to configure.
* **Quiet.** No terminal window: messages go to a log file in Argus's data folder, which
  Settings can point the investigator to if support ever needs it.
* **Updates.** Once a day Argus asks the account service which version is current; a newer one
  is offered in Settings with a one-click download. Cases are kept across updates and uninstalls:
  they live in the data folder, not in the program's folder.
"""

from __future__ import annotations

import contextlib
import json
import logging
import logging.handlers
import os
import socket
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path
from typing import Any

FIRST_PORT, LAST_PORT = 8765, 8785
CONFIG_NAME = "argus-desktop.json"
STATE_NAME = "desktop.json"
STARTING_SECONDS = 20


def bundle_dir() -> Path:
    """Where the installer put Argus's own files (PyInstaller's folder when packaged)."""
    frozen = getattr(sys, "_MEIPASS", None)
    return Path(frozen) if frozen else Path(__file__).resolve().parent.parent


def bundled_config() -> dict[str, Any]:
    """The operator's settings built into this installer (account service address, licence key...)."""
    for folder in (bundle_dir(), Path(sys.executable).resolve().parent):
        path = folder / CONFIG_NAME
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return {}
            return data if isinstance(data, dict) else {}
    return {}


def bundled_browser() -> str | None:
    """The private screenshot browser shipped inside the app (Chrome's headless shell)."""
    name = "chrome-headless-shell.exe" if sys.platform == "win32" else "chrome-headless-shell"
    for folder in (bundle_dir() / "browser", Path(sys.executable).resolve().parent / "browser"):
        found = next((p for p in folder.rglob(name) if p.is_file()), None) if folder.is_dir() else None
        if found:
            return str(found)
    return None


def _answers(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/live", timeout=1.5) as resp:
            return resp.status == 200
    except OSError:
        return False


def _free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if os.name != "nt":  # as the server will: a port just released by a previous run is free
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def pick_port() -> int:
    for port in range(FIRST_PORT, LAST_PORT + 1):
        if _free(port):
            return port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:  # all taken: let the system choose
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def running_port(home: Path) -> int | None:
    """The port of an Argus already running for this user, if it still answers."""
    path = home / STATE_NAME
    try:
        port = int(json.loads(path.read_text(encoding="utf-8")).get("port"))
        starting = time.time() - path.stat().st_mtime < STARTING_SECONDS
    except (OSError, ValueError, TypeError):
        return None
    deadline = time.monotonic() + (STARTING_SECONDS if starting else 0)
    while True:  # a copy started moments ago may still be getting ready: give it a little time
        if _answers(port):
            return port
        if time.monotonic() >= deadline:
            return None
        time.sleep(1)


def _log_to_file(home: Path) -> None:
    folder = home / "logs"
    folder.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(folder / "argus.log", maxBytes=2_000_000, backupCount=3,
                                                   encoding="utf-8")  # fmt: skip
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    if sys.stdout is None or sys.stderr is None:  # a windowed app has no console: never write to one
        sys.stdout = sys.stderr = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115 - for the whole run


def prepare(home: Path) -> None:
    """Environment for the packaged app: the operator's settings and the bundled browser (never overriding the user's)."""
    for key, value in (bundled_config().get("env") or {}).items():
        if isinstance(key, str) and key.startswith("ARGUS_") and isinstance(value, str):
            os.environ.setdefault(key, value)
    browser = bundled_browser()
    if browser:
        os.environ.setdefault("ARGUS_CAPTURE_BROWSER", browser)
    os.environ.setdefault("ARGUS_HOME", str(home))
    os.environ.setdefault("ARGUS_DESKTOP", "1")


def self_test(home: Path) -> bool:
    """Check the bundled screenshot browser really runs here (used by the release build): result in self-test.json."""
    import subprocess
    import tempfile

    browser = bundled_browser()
    result: dict[str, Any] = {"browser": browser, "screenshot": False}
    if browser:
        with tempfile.TemporaryDirectory() as tmp:
            shot = Path(tmp) / "test.png"
            args = [browser, "--headless", "--disable-gpu", f"--screenshot={shot}", "--window-size=400,300",
                    f"--user-data-dir={Path(tmp) / 'profile'}", "data:text/html,<h1>Argus</h1>"]  # fmt: skip
            if sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0:
                args.insert(1, "--no-sandbox")  # Chrome refuses its sandbox as root (containers)
            try:
                run = subprocess.run(args, capture_output=True, timeout=90, check=False)  # noqa: S603 - our own browser
                result["screenshot"] = shot.is_file() and shot.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
                result["output"] = (run.stderr or b"")[-2000:].decode("utf-8", "replace")
            except (OSError, subprocess.TimeoutExpired) as exc:
                result["output"] = str(exc)
    (home / "self-test.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return bool(result["screenshot"])


def main() -> None:
    from argus.cli.console import personal_data_dir, run_personal

    home = personal_data_dir()
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    if "--self-test" in sys.argv[1:]:
        raise SystemExit(0 if self_test(home) else 1)
    already = running_port(home)
    if already:
        webbrowser.open(f"http://127.0.0.1:{already}")  # one copy at a time: just show it
        return
    _log_to_file(home)
    prepare(home)
    port = pick_port()
    (home / STATE_NAME).write_text(json.dumps({"port": port, "pid": os.getpid()}), encoding="utf-8")
    try:
        run_personal(port)
    finally:
        with contextlib.suppress(OSError):
            (home / STATE_NAME).unlink()


if __name__ == "__main__":
    main()
