"""Phase 72: signed case reports — checkable by anyone, without Argus."""

from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

from argus.cli.console import verify_report_cli
from argus.reports import signing
from tests.test_case_report import _build
from tests.test_cases import client, keys  # noqa: F401  (fixtures used by name)


def client_verify(report, trusted_key=None):
    """The Python client's offline verifier (the client lives in clients/python)."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "clients" / "python"))
    from argus_client import verify_report

    return verify_report(report, trusted_key)


def _report(c):
    case, _ = _build(c)
    r = c.get(f"/api/cases/{case['id']}/report.html")
    assert r.status_code == 200
    return r


def test_reports_are_signed_and_verify_everywhere(client, tmp_path, capsys):  # noqa: F811
    r = _report(client)
    key = client.get("/api/report-signing-key").json()
    assert (
        key["algorithm"] == "Ed25519"
        and key["source"] == "generated"
        and r.headers["x-argus-report-key"] == key["key_id"]
    )
    assert key["key_id"] in r.text and "argus-signature" in r.text

    # The server's own check, the library, the Python client and the command line agree.
    checked = client.post("/api/reports/verify", files={"file": ("report.html", r.content, "text/html")}).json()
    assert checked["valid"] and checked["trusted"] and checked["key_id"] == key["key_id"]
    assert checked["sha256"] == r.headers["x-argus-report-sha256"]
    assert signing.verify(r.content, key["public_key"])["trusted"] is True
    assert client_verify(r.content, key["key_id"])["trusted"] is True
    path = tmp_path / "report.html"
    path.write_bytes(r.content)
    assert verify_report_cli(str(path), key["key_id"]) == 0 and "Signed by the key you trust" in capsys.readouterr().out
    assert verify_report_cli(str(path), None) == 0

    # Any change breaks it: one character of a name.
    tampered = r.content.replace(b"Jane Roe", b"Jane Rae", 1)
    assert not client.post("/api/reports/verify", files={"file": ("r.html", tampered, "text/html")}).json()["valid"]
    assert not signing.verify(tampered)["valid"] and not client_verify(tampered)["valid"]
    path.write_bytes(tampered)
    assert verify_report_cli(str(path), None) == 1 and "NOT VALID" in capsys.readouterr().out

    # The key is stable: the next report is signed with the same one.
    assert _report(client).headers["x-argus-report-key"] == key["key_id"]
    actions = {e["action"] for e in client.get("/api/audit?limit=50").json()}
    assert "report.verify" in actions


def test_a_report_resigned_with_another_key_is_not_trusted(client):  # noqa: F811
    r = _report(client)
    other = signing.from_private(signing.new_private_key(), "settings")
    original = client.get("/api/report-signing-key").json()
    html = r.text
    sig = signing.SIGNATURE_RE.search(html).group(1)
    unsigned = html.replace(signing.SIGNATURE_TAG.format(sig), signing.SIGNATURE_TAG.format(""))
    unsigned = unsigned.replace(
        signing.KEY_TAG.format(original["public_key"]), signing.KEY_TAG.format(other.public_key)
    )
    forged = other.sign(unsigned).encode()
    result = client.post("/api/reports/verify", files={"file": ("r.html", forged, "text/html")}).json()
    assert result["valid"] and result["trusted"] is False  # intact, but not signed by this server
    assert client_verify(forged, original["key_id"])["trusted"] is False

    # A signature copied onto other content fails; swapped keys fail.
    swapped = r.text.replace(signing.KEY_TAG.format(original["public_key"]), signing.KEY_TAG.format(other.public_key))
    assert not signing.verify(swapped.encode())["valid"]


def test_unsigned_and_odd_files():
    assert signing.verify(b"<html>hello</html>")["problem"].startswith("Not a signed Argus report")
    assert signing.verify(b"\xff\xfe")["valid"] is False
    assert client_verify(b"<html></html>")["valid"] is False


def test_a_configured_key_is_used(make_client):
    private = signing.new_private_key()
    expected = signing.from_private(private, "settings").key_id
    c = make_client(report_signing_key=private, monitors_enabled="false")
    info = c.get("/api/report-signing-key").json()
    assert info["source"] == "settings" and info["key_id"] == expected
    with pytest.raises(signing.SigningError):
        signing.from_private(base64.b64encode(b"short").decode(), "settings")
