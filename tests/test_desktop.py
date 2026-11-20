"""The desktop app: one copy at a time, a free port, the operator's settings, Quit, updates, browsers."""

from __future__ import annotations

import asyncio
import json
import socket
import sys
from pathlib import Path

import pytest

from argus import __version__, desktop
from argus.accounts.personal import PersonalLicence, newer_version
from argus.cli import console
from argus.core import runtime_config
from argus.core.settings import Settings
from argus.evidence import capture
from tests import test_teams
from tests.test_plans import personal  # noqa: F401 - the Argus Personal fixture

fake_stripe, service = test_teams.fake_stripe, test_teams.service  # the account service fixtures
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "packaging" / "desktop"))
import write_config  # noqa: E402


# ---------------------------------------------------------------------------- starting
def test_a_free_port_on_this_computer_only():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen()
        assert desktop._free(taken.getsockname()[1]) is False
    port = desktop.pick_port()
    assert desktop._free(port)


def test_one_copy_at_a_time(tmp_path, monkeypatch):
    assert desktop.running_port(tmp_path) is None  # nothing running
    (tmp_path / desktop.STATE_NAME).write_text(json.dumps({"port": 9}), encoding="utf-8")
    monkeypatch.setattr(desktop, "STARTING_SECONDS", 0)
    assert desktop.running_port(tmp_path) is None  # left over after a crash: start afresh
    monkeypatch.setattr(desktop, "_answers", lambda port: port == 9)
    assert desktop.running_port(tmp_path) == 9  # running: the icon just opens it
    (tmp_path / desktop.STATE_NAME).write_text("not json", encoding="utf-8")
    assert desktop.running_port(tmp_path) is None


def test_the_operators_settings_and_the_bundled_browser(tmp_path, monkeypatch):
    shell = tmp_path / "browser" / "chrome-headless-shell-x" / (
        "chrome-headless-shell.exe" if sys.platform == "win32" else "chrome-headless-shell")  # fmt: skip
    shell.parent.mkdir(parents=True)
    shell.write_text("")
    (tmp_path / desktop.CONFIG_NAME).write_text(json.dumps({"env": {
        "ARGUS_ACCOUNT_SERVER_URL": "https://accounts.example.com", "PATH": "/evil", "ARGUS_X": 5}}))  # fmt: skip
    monkeypatch.setattr(desktop, "bundle_dir", lambda: tmp_path)
    for name in ("ARGUS_ACCOUNT_SERVER_URL", "ARGUS_CAPTURE_BROWSER", "ARGUS_HOME", "ARGUS_DESKTOP"):
        monkeypatch.setenv(name, "")  # remembered, so the test's own values are undone afterwards
        monkeypatch.delenv(name)
    monkeypatch.setenv("ARGUS_LICENCE_PUBLIC_KEY", "the users own")
    desktop.prepare(tmp_path / "home")
    import os

    assert os.environ["ARGUS_ACCOUNT_SERVER_URL"] == "https://accounts.example.com"
    assert os.environ["PATH"] != "/evil" and "ARGUS_X" not in os.environ  # only ARGUS_ text settings
    assert os.environ["ARGUS_CAPTURE_BROWSER"] == str(shell) and os.environ["ARGUS_DESKTOP"] == "1"
    assert os.environ["ARGUS_LICENCE_PUBLIC_KEY"] == "the users own"  # never overrides the user's own
    (tmp_path / desktop.CONFIG_NAME).write_text("[1, 2]")
    assert desktop.bundled_config() == {}


def test_the_installer_only_carries_public_settings(monkeypatch):
    monkeypatch.setenv("ARGUS_ACCOUNT_SERVER_URL", "https://accounts.example.com")
    monkeypatch.setenv("ARGUS_LICENCE_SIGNING_KEY", "very secret")
    config = write_config.build()
    assert config == {"env": {"ARGUS_ACCOUNT_SERVER_URL": "https://accounts.example.com"}}
    monkeypatch.setenv("ARGUS_ACCOUNT_SERVER_URL", "http://accounts.example.com")
    with pytest.raises(SystemExit):
        write_config.build()


def test_chrome_or_edge_already_installed(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    for var in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
        monkeypatch.setenv(var, str(tmp_path))
    found = capture._installed_browsers()
    assert any(p.endswith("chrome.exe") for p in found) and any(p.endswith("msedge.exe") for p in found)
    monkeypatch.setattr(sys, "platform", "darwin")
    assert "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" in capture._installed_browsers()
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(capture.shutil, "which", lambda name: None)
    monkeypatch.setattr(capture.glob, "glob", lambda pattern: [])
    edge = Path(next(p for p in found if p.endswith("msedge.exe")))  # (Windows paths: one name on this system)
    edge.parent.mkdir(parents=True, exist_ok=True)
    edge.write_text("")
    assert capture.find_browser(Settings(capture_browser="auto")) == str(edge)


# ---------------------------------------------------------------------------- quitting
def test_quit_argus(personal, monkeypatch):  # noqa: F811
    c, _accounts = personal
    assert c.post("/api/personal/quit").status_code == 409  # not started from the desktop app
    stopped = type("Server", (), {"should_exit": False})()
    monkeypatch.setattr(console, "SERVER", stopped)
    assert c.post("/api/personal/quit", headers={"Origin": "https://evil.test"}).status_code == 403
    assert stopped.should_exit is False
    r = c.post("/api/personal/quit")
    assert r.status_code == 200 and stopped.should_exit is True


# ---------------------------------------------------------------------------- updates
def test_comparing_versions():
    assert newer_version("1.55.0", "1.54.9") and newer_version("2.0.0", "1.99.99")
    assert not newer_version("1.54.0", "1.54.0") and not newer_version("1.9.0", "1.10.0")
    assert not newer_version("", "1.0.0") and not newer_version("1.55", "1.54.0") and not newer_version("x", "1.0.0")


class Answers:
    def __init__(self, reply):
        self.reply, self.calls = reply, []

    async def call(self, path, body):
        self.calls.append((path, body))
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


def test_offering_an_update(monkeypatch):
    from argus.accounts.personal import AccountServiceError

    monkeypatch.setenv("ARGUS_DESKTOP", "1")
    licence = PersonalLicence(Settings(), state=None, client=Answers({"version": "99.0.0",
                                                                      "download_url": "https://example.com/argus"}))  # fmt: skip
    assert asyncio.run(licence.check_update()) == {"version": "99.0.0", "download_url": "https://example.com/argus"}
    assert licence.client.calls == [("app-version", {"current": __version__})]  # nothing else is sent
    status = licence.status()
    assert status["update"]["version"] == "99.0.0" and status["desktop"] is True and status["version"] == __version__
    licence.client = Answers(AccountServiceError(0, "offline"))
    assert asyncio.run(licence.check_update())["version"] == "99.0.0"  # offline: keep what we knew
    for reply in ({"version": __version__, "download_url": "https://example.com"},
                  {"version": "99.0.0", "download_url": "javascript:alert(1)"}, {}):  # fmt: skip
        licence.client = Answers(reply)
        assert asyncio.run(licence.check_update()) is None


def test_the_owner_publishes_a_version(service):
    c = service
    assert c.post("/api/accounts/app-version").json() == {"version": None, "download_url": None}
    settings = c.app.state.settings
    runtime_config.apply(settings, {"values": {"desktop_latest_version": "1.60.0",
                                               "desktop_download_url": "https://example.com/download"}}, None)  # fmt: skip
    assert c.post("/api/accounts/app-version").json() == {
        "version": "1.60.0",
        "download_url": "https://example.com/download",
    }
    with pytest.raises(runtime_config.ConfigError):
        runtime_config.validate("desktop_latest_version", "1.60")
    with pytest.raises(runtime_config.ConfigError):
        runtime_config.validate("desktop_download_url", "http://example.com/download")
    assert runtime_config.validate("desktop_download_url", "") == ""
