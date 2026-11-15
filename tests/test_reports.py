"""Client PDF reports: content decisions, injection safety, branding, registry and verification."""

from __future__ import annotations

import hashlib
import io
import re

import pytest
from PIL import Image
from pypdf import PdfReader

from argus.api import server
from argus.demo import DEMO_ID, build_demo
from argus.reports import pdf as pdf_module
from argus.reports.branding import BrandingError, check_accent, decode_data_url, sanitise_logo
from argus.reports.data import PERSONAL_TYPES, Branding, ReportOptions, build_report_data
from argus.reports.pdf import esc, render_pdf


@pytest.fixture(autouse=True)
def _fresh_limits():
    server._report_limiter._events.clear()


def _text(pdf: bytes) -> str:
    return "\n".join(page.extract_text() or "" for page in PdfReader(io.BytesIO(pdf)).pages)


def _data(**options):
    inv, graph = build_demo()
    return build_report_data(
        inv, graph, ReportOptions(**options), Branding(organisation="Northwind Security"),
        previous=build_demo(previous=True), generator="Argus test",
    )  # fmt: skip


def _png(size=(120, 40), colour=(79, 70, 229), fmt="PNG", **save) -> bytes:
    out = io.BytesIO()
    Image.new("RGB", size, colour).save(out, format=fmt, **save)
    return out.getvalue()


# ---------------------------------------------------------------------------- content
def test_report_content_is_prioritised_and_compared_with_the_last_scan():
    data = _data(prepared_for="Acme Corporation")
    assert data.rating == "critical" and data.severity_counts["critical"] == 5
    assert data.paths[0]["score"] == max(p["score"] for p in data.paths)
    actions = [r["action"] for r in data.recommendations]
    assert len(actions) == len(set(actions)) and data.recommendations[0]["severity"] == "critical"
    assert data.trend and data.trend["new_paths"] == 8 and data.trend["risk_delta"] > 0
    assert any("increased" in line for line in data.summary)


def test_personal_data_is_summarised_not_listed():
    data = _data()
    _, graph = build_demo()
    personal = {e.label for e in graph.get_all_entities() if e.type.value in PERSONAL_TYPES}
    listed = {row["value"] for row in data.inventory}
    assert personal and not (personal & listed)
    assert not {c["type"] for c in data.categories} & PERSONAL_TYPES
    assert data.people["people"] == 5 and data.people["email_format"] == "first.last@acme-corp.example"
    pdf_text = _text(render_pdf(data))
    for identifier in ("Dana Whitfield", "dana.whitfield@acme-corp.example", "dwhitfield-dev", "Aisha Patel"):
        assert identifier not in pdf_text, identifier
    assert "d•••@acme-corp.example" in pdf_text and "Person" in pdf_text  # pseudonyms keep paths readable
    full = _text(render_pdf(_data(include_personal_details=True)))
    assert "Dana Whitfield" in full and "dana.whitfield@acme-corp.example" in full


def test_inventory_can_be_left_out():
    data = _data(include_inventory=False)
    assert data.inventory == [] and data.categories  # counts stay, the list goes
    assert "detailed asset list was excluded" in _text(render_pdf(data))


# ---------------------------------------------------------------------------- the PDF
def test_pdf_has_the_expected_structure_and_metadata():
    data = _data(prepared_for="Acme Corporation", tlp="RED")
    pdf = render_pdf(data, verify_url="https://argus.example.com/api/reports/verify/<sha256>")
    reader = PdfReader(io.BytesIO(pdf))
    assert pdf.startswith(b"%PDF") and len(reader.pages) >= 8
    meta = reader.metadata
    assert meta.title == "Attack-surface assessment: acme-corp.example" and meta.author == "Northwind Security"
    assert data.report_id in meta.subject and "TLP:RED" in meta.subject
    outline = [item.title for item in reader.outline if not isinstance(item, list)]
    assert outline[:3] == ["1. Executive summary", "2. Priority recommendations", "3. Attack paths"]
    text = _text(pdf)
    for expected in ("Attack-Surface Assessment", "acme-corp.example", "Acme Corporation", "TLP:RED",
                     "Priority recommendations", "MITRE ATT&CK", data.report_id, "Page 2 of",
                     "https://argus.example.com/api/reports/verify/"):  # fmt: skip
        assert expected in text, expected


def test_scanned_text_cannot_inject_markup_into_the_pdf(tmp_path):
    """ReportLab markup can read local files (<img src>) and create links: scanned text must stay text."""
    secret = tmp_path / "secret.png"
    secret.write_bytes(_png())
    payloads = [
        f'<img src="{secret}" width="300" height="300"/>',
        '<a href="javascript:alert(1)">click</a>',
        '<font name="/etc/passwd">x</font><para>&nbsp;',
    ]
    data = _data()
    data.paths[0]["title"] = payloads[0]
    data.paths[0]["narrative"] = payloads[1]
    data.inventory[0]["value"] = payloads[2]
    data.flags = payloads
    data.target = payloads[0]
    pdf = render_pdf(data)
    reader = PdfReader(io.BytesIO(pdf))
    assert sum(len(page.images) for page in reader.pages) == 0  # the file was never read or embedded
    links = [a for page in reader.pages for a in (page.get("/Annots") or [])]
    assert not any("javascript" in str(link.get_object()).lower() for link in links)
    assert "<img src=" in _text(pdf) and "javascript:alert(1)" in _text(pdf)  # shown literally instead


def test_escaping_helper():
    assert esc('<b>&"x"</b>') == "&lt;b&gt;&amp;&quot;x&quot;&lt;/b&gt;"
    assert esc("a\x00b\x1bc") == "abc"  # control characters dropped


def test_non_latin_names_render_with_the_unicode_font():
    data = _data()
    data.target = "пример.рф"
    data.paths[0]["title"] = "Ελληνικά and Кириллица"
    text = _text(render_pdf(data))
    if pdf_module._Fonts.unicode:
        assert "Ελληνικά" in text and "пример.рф" in text
    else:  # no DejaVu on this machine: still renders, with replacement characters
        assert "?" in text


def test_reports_render_without_any_unicode_font(monkeypatch):
    monkeypatch.setattr(pdf_module, "FONT_DIRS", [])
    monkeypatch.setattr(pdf_module._Fonts, "unicode", False)
    monkeypatch.setattr(pdf_module._Fonts, "regular", "Helvetica")
    monkeypatch.setattr(pdf_module._Fonts, "bold", "Helvetica-Bold")
    data = _data()
    data.paths[0]["title"] = "Кириллица <x>"
    assert render_pdf(data).startswith(b"%PDF")


def test_branding_logo_and_colour_appear():
    data = _data()
    data.branding = Branding(organisation="Northwind Security", accent="#0f766e", logo_png=sanitise_logo(_png()))
    reader = PdfReader(io.BytesIO(render_pdf(data)))
    assert len(reader.pages[0].images) == 1  # the logo, on the cover
    cover = reader.pages[0].get_contents().get_data().decode("latin-1")
    assert ".058824 .462745 .431373 rg" in cover  # the accent colour (RGB 0-1) paints the cover band


# ---------------------------------------------------------------------------- logo safety
def test_logos_are_re_encoded_and_stripped():
    exif = Image.Exif()
    exif[0x8825] = {2: (51.0, 30.0, 0.0)}  # GPS latitude
    jpeg = _png(fmt="JPEG", exif=exif.tobytes())
    clean = sanitise_logo(jpeg)
    with Image.open(io.BytesIO(clean)) as im:
        assert im.format == "PNG" and not im.getexif()
    big = sanitise_logo(_png(size=(3000, 1000)))
    with Image.open(io.BytesIO(big)) as im:
        assert max(im.size) <= 800
    assert sanitise_logo(decode_data_url("data:image/png;base64," + __import__("base64").b64encode(_png()).decode()))


@pytest.mark.parametrize(
    "raw",
    [
        b"not an image",
        b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>",
        _png(fmt="GIF"),
        _png(size=(4100, 10)),  # too wide
        b"x" * 1_000_001,  # too big
    ],
)
def test_unsafe_logos_are_refused(raw):
    with pytest.raises(BrandingError):
        sanitise_logo(raw)


def test_decompression_bomb_is_refused_before_decoding():
    """A tiny PNG whose header claims 30000 x 30000 pixels."""
    import struct
    import zlib

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    ihdr = struct.pack(">IIBBBBB", 30000, 30000, 8, 2, 0, 0, 0)
    bomb = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(b"\0" * 64)) + chunk(b"IEND", b"")
    with pytest.raises(BrandingError):
        sanitise_logo(bomb)


def test_accent_colours_are_validated():
    assert check_accent("#ABCDEF") == "#abcdef"
    for bad in ("red", "#12345", "#1234567", "#12345g", "url(x)"):
        with pytest.raises(BrandingError):
            check_accent(bad)


# ---------------------------------------------------------------------------- the API
@pytest.fixture
def demo_client(make_client):
    client = make_client(monitors_enabled="false", notifications_enabled="false")
    client.post("/api/demo")
    return client


def test_generate_register_and_verify_a_report(demo_client):
    response = demo_client.post(f"/api/investigation/{DEMO_ID}/report", json={"prepared_for": "Acme", "tlp": "GREEN"})
    assert response.status_code == 200, response.text
    pdf = response.content
    digest = hashlib.sha256(pdf).hexdigest()
    assert response.headers["content-type"] == "application/pdf"
    assert response.headers["x-argus-report-sha256"] == digest
    assert re.match(r'attachment; filename="argus-report-acme-corp-example-\d{8}-ARG-[0-9A-F]{8}\.pdf"',
                    response.headers["content-disposition"])  # fmt: skip
    assert response.headers["cache-control"] == "no-store"
    report_id = response.headers["x-argus-report-id"]
    assert "TLP:GREEN" in _text(pdf) and "Acme" in _text(pdf)

    [listed] = demo_client.get("/api/reports").json()
    assert listed["id"] == report_id and listed["sha256"] == digest and listed["prepared_for"] == "Acme"

    # Anyone holding the file can verify it, without an account.
    anonymous = {"Authorization": ""}
    verified = demo_client.get(f"/api/reports/verify/{digest}", headers=anonymous)
    assert verified.status_code == 200 and verified.json()["report_id"] == report_id
    assert verified.json()["classification"] == "TLP:GREEN" and "created_by" not in verified.json()
    tampered = hashlib.sha256(pdf[:-10] + b"tampered!!").hexdigest()
    assert demo_client.get(f"/api/reports/verify/{tampered}", headers=anonymous).status_code == 404
    assert demo_client.get("/api/reports/verify/not-a-hash", headers=anonymous).status_code == 422

    event = next(e for e in demo_client.get("/api/audit?limit=20").json() if e["action"] == "report.generate")
    assert event["details"]["sha256"] == digest and event["details"]["report_id"] == report_id


def test_report_defaults_and_roles(demo_client):
    assert demo_client.post(f"/api/investigation/{DEMO_ID}/report").status_code == 200  # no body: defaults
    viewer = demo_client.post("/api/keys", json={"name": "v", "role": "viewer"}).json()["key"]
    headers = {"Authorization": f"Bearer {viewer}"}
    assert demo_client.post(f"/api/investigation/{DEMO_ID}/report", headers=headers).status_code == 403
    assert demo_client.get("/api/reports", headers=headers).status_code == 200
    bad = demo_client.post(f"/api/investigation/{DEMO_ID}/report", json={"tlp": "PURPLE"})
    assert bad.status_code == 422


def test_report_generation_is_rate_limited(demo_client):
    codes = [demo_client.post(f"/api/investigation/{DEMO_ID}/report").status_code for _ in range(11)]
    assert codes[:10] == [200] * 10 and codes[10] == 429


def test_reports_are_invisible_to_other_workspaces(demo_client):
    demo_client.post(f"/api/investigation/{DEMO_ID}/report")
    demo_client.post("/api/workspaces", json={"name": "Red Team"})
    red = {"X-Argus-Workspace": "red-team"}
    assert demo_client.post(f"/api/investigation/{DEMO_ID}/report", headers=red).status_code == 404
    assert demo_client.get("/api/reports", headers=red).json() == []


def test_branding_is_admin_only_validated_and_used(demo_client):
    import base64

    logo = "data:image/png;base64," + base64.b64encode(_png()).decode()
    saved = demo_client.put(
        "/api/reports/branding",
        json={"organisation": "Northwind Security", "accent": "#0F766E", "footer_note": "Confidential", "logo": logo},
    )
    assert saved.status_code == 200 and saved.json()["has_logo"] and saved.json()["accent"] == "#0f766e"
    assert demo_client.get("/api/reports/branding/logo").headers["content-type"] == "image/png"
    pdf = demo_client.post(f"/api/investigation/{DEMO_ID}/report").content
    assert len(PdfReader(io.BytesIO(pdf)).pages[0].images) == 1
    assert "Northwind Security" in _text(pdf) and "Confidential" in _text(pdf)
    assert demo_client.get("/api/reports").json()[0]["issued_by_org"] == "Northwind Security"

    keep = demo_client.put("/api/reports/branding", json={"organisation": "Northwind"})  # logo omitted: kept
    assert keep.json()["has_logo"]
    removed = demo_client.put("/api/reports/branding", json={"organisation": "Northwind", "logo": ""})
    assert not removed.json()["has_logo"]
    assert demo_client.put("/api/reports/branding", json={"organisation": "x", "accent": "red"}).status_code == 422
    gif = "data:image/gif;base64," + base64.b64encode(_png(fmt="GIF")).decode()
    assert demo_client.put("/api/reports/branding", json={"organisation": "x", "logo": gif}).status_code == 422
    analyst = demo_client.post("/api/keys", json={"name": "a", "role": "analyst"}).json()["key"]
    forbidden = demo_client.put(
        "/api/reports/branding", json={"organisation": "x"}, headers={"Authorization": f"Bearer {analyst}"}
    )
    assert forbidden.status_code == 403
    actions = [e["action"] for e in demo_client.get("/api/audit?limit=30").json()]
    assert actions.count("report.branding_update") == 3
