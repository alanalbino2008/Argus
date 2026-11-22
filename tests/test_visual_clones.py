"""Phase 78: visual clone detection — a lookalike whose page looks like the brand's own."""

from __future__ import annotations

import io

from PIL import Image, ImageDraw

from argus.intel.lookalike_triage import WebProfile
from argus.intel.visual import MATCH, Fingerprint, best_match, fingerprint, similarity
from tests.test_brand_watch import _alerts, _cert, _due, _tick, bw  # noqa: F401  (fixture used by name)


def _page(header="#0b3d91", card=(60, 120, 420, 520), promo=True, text_shift=0) -> bytes:
    """A synthetic 'bank login page' screenshot."""
    image = Image.new("RGB", (1366, 1400), "#f4f6fa")
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, 1366, 80), fill=header)
    draw.rectangle(card, fill="white", outline="#cccccc")
    for i in range(3):
        y = card[1] + 80 + i * 70
        draw.rectangle((card[0] + 30 + text_shift, y, card[2] - 30, y + 40), outline="#ccccdd")
    if promo:
        draw.rectangle((480, 120, 1300, 520), fill="#dbe7ff")
    out = io.BytesIO()
    image.save(out, "PNG")
    return out.getvalue()


def _blank() -> bytes:
    out = io.BytesIO()
    Image.new("RGB", (1366, 900), "white").save(out, "PNG")
    return out.getvalue()


def _other() -> bytes:
    image = Image.new("RGB", (1366, 900), "white")
    draw = ImageDraw.Draw(image)
    for i in range(4):
        draw.rectangle((40 + i * 330, 400, 340 + i * 330, 640), fill="#e6e6e6")
    draw.rectangle((300, 120, 1066, 220), fill="#aa3333")
    out = io.BytesIO()
    image.save(out, "PNG")
    return out.getvalue()


def test_fingerprints():
    bank = fingerprint(_page())
    assert bank is not None and not bank.blank
    assert similarity(bank, fingerprint(_page(text_shift=6))) >= MATCH  # a kit's small changes
    assert similarity(bank, fingerprint(_other())) < MATCH
    assert similarity(bank, fingerprint(_blank())) == 0.0 and fingerprint(_blank()).blank
    assert fingerprint(b"not an image") is None
    again = Fingerprint.from_dict(bank.as_dict())
    assert (again.dhash, again.layout) == (bank.dhash, bank.layout) and round(again.contrast) == round(bank.contrast)
    refs = [{"url": "https://acmebank.com/", "fingerprint": bank.as_dict()}, {"url": "broken", "fingerprint": {}}]
    assert best_match(bank, refs) == {"url": "https://acmebank.com/", "similarity": 1.0}


def test_a_visual_copy_with_a_login_form_is_phishing(bw):  # noqa: F811
    c, state = bw
    state["keyword"] = [_cert("acmebank-verify.net", days_ago=1), _cert("acmebank-shoes.org", days_ago=1)]
    # The kit changes the title and favicon, so only the look gives it away.
    state["web"]["acmebank-verify.net"] = WebProfile(True, 200, "acmebank-verify.net", "Secure portal", True, "")
    state["web"]["acmebank-shoes.org"] = WebProfile(True, 200, "acmebank-shoes.org", "Cheap shoes", True, "")
    state["shots"] = {"https://acmebank.com/": _page(), "https://login.acmebank.com/": _page(promo=False),
                      "https://acmebank-verify.net/": _page(text_shift=6), "https://acmebank-shoes.org/": _other()}  # fmt: skip
    watch = c.post("/api/brand-watches", json={"domain": "acmebank.com", "web_check": "direct",
                                               "reference_urls": ["https://acmebank.com/", "https://login.acmebank.com/"]}).json()  # fmt: skip
    assert watch["reference_urls"] == ["https://acmebank.com/", "https://login.acmebank.com/"]
    _tick(c)
    listed = c.get("/api/brand-watches").json()[0]
    assert [r["url"] for r in listed["references"]] == ["https://acmebank.com/", "https://login.acmebank.com/"]
    recent = {f["name"]: f["triage"] for f in listed["recent"]}
    clone = recent["acmebank-verify.net"]
    assert clone["verdict"] == "phishing" and clone["visual"]["similarity"] >= MATCH
    assert any(r.startswith("Looks like your page https://acmebank.com/") for r in clone["reasons"])
    assert recent["acmebank-shoes.org"]["verdict"] == "live"  # a password field alone is not a copy
    (alert,) = _alerts(c)
    assert alert["severity"] == "critical"

    # References are rendered once a week, not on every run.
    calls = len([u for u, _ in state["shot_calls"] if "acmebank.com" in u])
    _due(c, watch["id"])
    _tick(c)
    assert len([u for u, _ in state["shot_calls"] if "acmebank.com" in u]) == calls


def test_no_visual_check_unless_websites_are_visited(bw):  # noqa: F811
    c, state = bw
    state["keyword"] = [_cert("acmebank-verify.net", days_ago=1)]
    c.post("/api/brand-watches", json={"domain": "acmebank.com"})
    _tick(c)
    assert state["shot_calls"] == []
    assert (
        c.post(
            "/api/brand-watches", json={"domain": "x-acme.com", "reference_urls": ["javascript:alert(1)"]}
        ).status_code
        == 422
    )
