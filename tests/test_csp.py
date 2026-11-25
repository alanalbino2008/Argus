"""Phase 99: Argus's pages load nothing from third parties, and CSP violations are reported."""

from __future__ import annotations

import re
from pathlib import Path

from argus.observability import metrics

WEB = Path(__file__).resolve().parents[1] / "argus" / "web"


def _count(directive):
    return metrics.REGISTRY.get_sample_value("argus_csp_violations_total", {"directive": directive}) or 0


def test_the_policy_allows_only_argus_itself(client):
    page = client.get("/")
    policy = page.headers["content-security-policy"]
    assert "https://" not in policy and "http://" not in policy  # no third party at all
    assert "font-src 'self'" in policy and "script-src 'self'" in policy and "report-uri /api/csp-report" in policy
    assert page.headers["reporting-endpoints"] == 'csp="/api/csp-report"'


def test_no_page_loads_anything_from_elsewhere():
    for html in WEB.glob("*.html"):
        text = html.read_text()
        # What the page *loads* (scripts, images, stylesheets, preloads), not ordinary links people click.
        external = re.findall(r'src="(https?://[^"]+)"', text) + re.findall(r'<link[^>]+href="(https?://[^"]+)"', text)
        assert external == [], f"{html.name} loads {external}"


def test_the_fonts_are_served_locally(client):
    css = client.get("/static/vendor/fonts/fonts.css")
    assert css.status_code == 200 and 'font-family: "Inter"' in css.text
    for name in re.findall(r'url\("([^"]+)"\)', css.text):
        font = client.get(f"/static/vendor/fonts/{name}")
        assert font.status_code == 200 and font.content[:4] == b"wOF2", name
    assert (WEB / "vendor" / "fonts" / "Inter-LICENSE.txt").read_text().startswith("Copyright")


def test_violation_reports_are_counted_in_both_formats(client):
    before = _count("script-src-elem")
    legacy = {"csp-report": {"document-uri": "https://argus.example/#/cases?secret=1",
                             "violated-directive": "script-src-elem", "blocked-uri": "https://evil.example/x.js"}}  # fmt: skip
    assert client.post("/api/csp-report", json=legacy, headers={"Authorization": ""}).status_code == 204
    modern = [{"type": "csp-violation", "body": {"effectiveDirective": "script-src-elem", "blockedURL": "inline",
                                                 "documentURL": "https://argus.example/"}}]  # fmt: skip
    assert client.post("/api/csp-report", json=modern).status_code == 204
    assert _count("script-src-elem") == before + 2


def test_odd_or_hostile_reports_are_ignored(client):
    before = _count("unknown")
    assert client.post("/api/csp-report", content=b"not json").status_code == 204
    assert client.post("/api/csp-report", content=b"x" * 20_000).status_code == 204  # too big: not read
    weird = {"csp-report": {"violated-directive": "<script>alert(1)</script>"}}
    assert client.post("/api/csp-report", json=weird).status_code == 204
    assert _count("unknown") == before + 1  # a made-up directive is not a new metric label
    total = sum(s.value for s in metrics.CSP_VIOLATIONS.collect()[0].samples if s.name.endswith("_total"))
    for _ in range(40):  # one address cannot flood the counter
        client.post("/api/csp-report", json={"csp-report": {"violated-directive": "img-src"}})
    after = sum(s.value for s in metrics.CSP_VIOLATIONS.collect()[0].samples if s.name.endswith("_total"))
    assert after - total <= 30
