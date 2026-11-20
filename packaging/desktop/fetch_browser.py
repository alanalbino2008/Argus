"""Download Chrome's headless shell (Chrome for Testing) into the app, for evidence screenshots.

The headless shell is a small Chrome without a window, made for automated page captures. Argus
uses it to save web pages as evidence; shipping it means investigators don't need Chrome
installed (Argus falls back to an installed Chrome or Edge if it is missing).

    python packaging/desktop/fetch_browser.py build/browser [win64|mac-arm64|mac-x64|linux64]
"""

from __future__ import annotations

import io
import json
import platform
import sys
import urllib.request
import zipfile
from pathlib import Path

INDEX = "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json"


def this_platform() -> str:
    machine = platform.machine().lower()
    if sys.platform == "win32":
        return "win64"
    if sys.platform == "darwin":
        return "mac-arm64" if machine in ("arm64", "aarch64") else "mac-x64"
    return "linux64"


def _get(url: str) -> bytes:
    if not url.startswith("https://"):
        raise SystemExit(f"Refusing a non-https download: {url}")
    with urllib.request.urlopen(url, timeout=300) as resp:  # noqa: S310 - https only, checked above
        return resp.read()


def main(out: str, target: str) -> None:
    stable = json.loads(_get(INDEX))["channels"]["Stable"]
    links = {d["platform"]: d["url"] for d in stable["downloads"]["chrome-headless-shell"]}
    if target not in links:
        raise SystemExit(f"No headless shell for {target}; available: {', '.join(links)}")
    folder = Path(out)
    folder.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(_get(links[target]))) as archive:
        for member in archive.infolist():
            path = (folder / member.filename).resolve()
            if not path.is_relative_to(folder.resolve()):
                raise SystemExit(f"Unsafe path in the download: {member.filename}")
            archive.extract(member, folder)
            mode = (member.external_attr >> 16) & 0o777
            if mode:
                path.chmod(mode)
    (folder / "VERSION").write_text(stable["version"], encoding="utf-8")
    print(f"Chrome headless shell {stable['version']} ({target}) in {folder}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "build/browser", sys.argv[2] if len(sys.argv) > 2 else this_platform())
