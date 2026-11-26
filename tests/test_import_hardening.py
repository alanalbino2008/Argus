"""Hardening of the untrusted-file readers: crafted spreadsheets, decompression bombs, long PDF lines,
and header injection into the WARC evidence format."""

from __future__ import annotations

import io
import time
import zipfile

import pytest

from argus.evidence.capture import _header_lines, build_warc
from argus.intel import imports as I


def _xlsx_raw(shared_xml: str, sheet_xml: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("xl/sharedStrings.xml", shared_xml)
        z.writestr("xl/worksheets/sheet1.xml", sheet_xml)
    return buf.getvalue()


def test_a_crafted_cell_reference_cannot_force_a_huge_row():
    # A cell addressed far out to the right (and a malformed many-letter reference) must not build a
    # multi-gigabyte row; only columns within the cap are kept.
    ns = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
    sheet = (
        f"<worksheet {ns}><sheetData>"
        '<row r="1"><c r="A1" t="inlineStr"><is><t>From</t></is></c><c r="B1" t="inlineStr"><is><t>To</t></is></c></row>'
        '<row r="2"><c r="XFD2" t="inlineStr"><is><t>far</t></is></c>'
        '<c r="AAAAAA2" t="inlineStr"><is><t>malformed</t></is></c>'
        '<c r="A2" t="inlineStr"><is><t>+447700900001</t></is></c>'
        '<c r="B2" t="inlineStr"><is><t>+447700900123</t></is></c></row>'
        "</sheetData></worksheet>"
    )
    rows = I.read_xlsx(_xlsx_raw(f"<sst {ns}></sst>", sheet))
    assert rows[0][:2] == ["From", "To"] and len(rows[1]) <= I.MAX_COLS
    kind, records = I.records_from_table(rows, "auto")
    assert kind == "cdr" and records[0]["from"] == "+447700900001"


def test_a_member_that_decompresses_past_the_limit_is_refused(monkeypatch):
    monkeypatch.setattr(I, "MAX_XML", 2000)  # a low cap so the test file stays small
    ns = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
    big = f"<sst {ns}>" + "<si><t>" + ("A" * 5000) + "</t></si></sst>"  # > the cap once decompressed
    with pytest.raises(I.ImportError_, match="too large to read safely"):
        I.read_xlsx(_xlsx_raw(big, f"<worksheet {ns}><sheetData></sheetData></worksheet>"))


def test_a_bad_shared_string_index_does_not_crash():
    ns = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
    sheet = f'<worksheet {ns}><sheetData><row r="1"><c r="A1" t="s"><v>notanumber</v></c></row></sheetData></worksheet>'
    assert I.read_xlsx(_xlsx_raw(f"<sst {ns}></sst>", sheet)) == []  # the non-numeric index becomes empty, no crash


def test_a_very_long_pdf_line_is_skipped_quickly():
    from argus.intel.imports import MAX_PDF_LINE, PDF_LINE

    line = "01/01/2026 " + ("1" * 50000) + " 1,000.00"
    start = time.monotonic()
    assert len(line) > MAX_PDF_LINE
    # The regex itself must not hang even if a long line reached it.
    PDF_LINE.match(line[:MAX_PDF_LINE])
    assert time.monotonic() - start < 2


def test_warc_headers_cannot_inject_lines():
    hostile = {"X-Thing": "ok\r\nWARC/1.1\r\nWARC-Type: fake", "Set-Cookie": "a=b\nInjected: 1"}
    lines = _header_lines(hostile)
    assert lines == ["X-Thing: ok WARC/1.1 WARC-Type: fake", "Set-Cookie: a=b Injected: 1"]
    assert not any("\r" in line or "\n" in line for line in lines)
    page = {"status": 200, "final_url": "https://x.test/", "headers": {"Evil": "v\r\nWARC-Type: resource"},
            "body": b"hi", "chain": [{"url": "https://x.test/", "status": 200, "headers": {}}]}  # fmt: skip
    warc = build_warc(page, "2026-01-01T00:00:00Z")
    # The hostile value survives only as inert text on one header line, never as a CRLF-framed record.
    assert b"\r\nWARC-Type: resource" not in warc and b"\r\nEvil: v WARC-Type: resource\r\n" in warc
    assert warc.count(b"WARC-Type: response") == 1
