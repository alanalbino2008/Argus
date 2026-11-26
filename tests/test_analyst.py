"""The AI analyst: case material, the Claude request, checking its answers, the API and Argus Connect.

Claude itself is replaced by a stand-in that records each request and answers as told.
"""

from __future__ import annotations

import io
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from typing import Any

import anthropic
import httpx2
import pytest

from argus.core.settings import get_settings
from argus.intel import analyst
from tests.test_cases import new_case
from tests.test_companies import broker  # noqa: F401 - the account service fixture

DOC = "Minutes. Jane Doe, treasurer of Hope Relief Ltd, met Tom Roe on 4 March 2024. Payment to wallet bc1qexample."


# ---------------------------------------------------------------------------- a stand-in for Claude
class FakeClaude:
    """Records requests; answers with ``reply(request) -> (stop_reason, text)``."""

    def __init__(self, reply, *, models=("claude-opus-test-2", "claude-sonnet-test", "claude-opus-test-1"),
                 fallback_error: bool = False):  # fmt: skip
        self.reply, self.requests, self.fallback_error = reply, [], fallback_error
        self.beta = SimpleNamespace(messages=SimpleNamespace(stream=lambda **kw: self._stream(kw, beta=True)))
        self.messages = SimpleNamespace(stream=lambda **kw: self._stream(kw, beta=False))

        async def listing(limit=20):
            return SimpleNamespace(data=[SimpleNamespace(id=m) for m in models])

        self.models = SimpleNamespace(list=listing)

    def _stream(self, request, *, beta):
        outer = self

        class Stream:
            async def __aenter__(self):
                if beta and outer.fallback_error:
                    response = httpx2.Response(400, request=httpx2.Request("POST", "https://api.anthropic.test"))
                    raise anthropic.BadRequestError("fallbacks: not supported for this model", response=response,
                                                    body=None)  # fmt: skip
                outer.requests.append({**request, "_beta": beta})
                return self

            async def __aexit__(self, *exc):
                return False

            async def get_final_message(self):
                stop, text = outer.reply(request)
                return SimpleNamespace(stop_reason=stop, model=request["model"],
                                       content=[SimpleNamespace(type="thinking", thinking=""),
                                                SimpleNamespace(type="text", text=text)])  # fmt: skip

        return Stream()


BRIEF = {
    "summary": "Jane Doe runs the charity's money [D1].",
    "key_findings": [{"finding": "Jane Doe is treasurer", "sources": ["D1"], "confidence": "likely"},
                     {"finding": "An invented claim", "sources": ["X9"], "confidence": "possible"}],
    "gaps": ["Who is Tom Roe?"], "next_steps": [{"action": "Check the charity register", "why": "To confirm the "
                                                 "trustees", "how": "Charity Commission search"}],
    "cautions": [],
}  # fmt: skip
EXTRACTION = {
    "entities": [
        {"type": "person", "value": "Jane Doe", "details": "treasurer", "source": "D1", "quote": "Jane Doe, treasurer of Hope Relief Ltd", "possible_minor": False},
        {"type": "person", "value": "Tom Roe", "details": "", "source": "D1", "quote": "met Tom Roe in Paris", "possible_minor": False},
        {"type": "person", "value": "Little Timmy", "details": "aged 9", "source": "D1", "quote": "Timmy", "possible_minor": True},
        {"type": "organisation", "value": "Hope Relief Ltd", "details": "", "source": "D1", "quote": "Hope Relief Ltd", "possible_minor": False},
        {"type": "wallet", "value": "bc1qexample", "details": "", "source": "D1", "quote": "wallet bc1qexample.", "possible_minor": False},
    ],
    "events": [
        {"title": "Jane Doe met Tom Roe", "date": "2024-03-04", "source": "D1", "quote": "met Tom Roe on 4 March 2024"},
        {"title": "Some time", "date": "the spring", "source": "D1", "quote": "x"},
    ],
}  # fmt: skip


def replies(request):
    task = next(t for t, p in analyst.TASK_PROMPTS.items() if p == request["messages"][0]["content"][1]["text"])
    if task == "brief":
        return "end_turn", json.dumps(BRIEF)
    if task == "extract":
        return "end_turn", json.dumps(EXTRACTION)
    return "end_turn", "# Report\n\nJane Doe is the treasurer [D1]. Also [Z3]."


@pytest.fixture
def claude(monkeypatch):
    fake = FakeClaude(replies)
    monkeypatch.setattr(analyst, "_client", lambda key: fake)
    analyst._newest.clear()
    return fake


# ---------------------------------------------------------------------------- material
def test_material_labels_every_source_and_says_what_was_left_out():
    case = {"title": "Fake charity", "purpose": "Investigating a fake charity", "summary": "Started from a tip."}
    items = [
        {"id": "i1", "kind": "entity", "title": "Jane Doe", "body": "", "data": {"type": "person", "value": "Jane Doe", "attributes": {"role": "treasurer"}}},
        {"id": "i2", "kind": "entity", "title": "Hope Relief", "body": "", "data": {"type": "organisation", "value": "Hope Relief"}},
        {"id": "i3", "kind": "link", "title": "", "body": "", "data": {"from": "i1", "to": "i2", "label": "treasurer of", "confidence": "confirmed"}},
        {"id": "i4", "kind": "note", "title": "Tip", "body": "A donor says the charity is fake.", "data": {}},
        {"id": "i5", "kind": "event", "title": "Appeal launched", "body": "", "data": {}, "occurred_at": "2024-01-02T10:00:00+00:00"},
    ]  # fmt: skip
    docs = [
        {"id": "ev1", "title": "Minutes", "url": None, "captured_at": "2024-05-01T00:00:00+00:00", "text": DOC},
        {"id": "ev2", "title": "Huge page", "url": "https://example.org/x", "captured_at": "", "text": "word " * 30000},
        {"id": "ev3", "title": "Another huge page", "url": "https://example.org/y", "captured_at": "", "text": "word " * 30000},
        {"id": "ev4", "title": "photo.jpg", "url": None, "captured_at": "", "text": None},
    ]  # fmt: skip
    m = analyst.build_material(case, items, docs, max_chars=200_000)
    assert "[P1] person: Jane Doe (role: treasurer)" in m.text
    assert "[L1] Jane Doe -> Hope Relief: treasurer of (confirmed)" in m.text
    assert "[N1] Tip: A donor says" in m.text and "[T1] 2024-01-02T10:00: Appeal launched" in m.text
    assert "[D1] --- document: Minutes" in m.text and DOC in m.text
    assert m.sources["D1"]["id"] == "ev1" and m.sources["D2"]["kind"] == "document"
    assert m.shortened == ["Huge page", "Another huge page"]  # each document is capped
    assert m.unreadable == ["photo.jpg"] and "2 document(s) were shortened" in m.text
    small = analyst.build_material(case, items, docs, max_chars=61_000)
    assert small.left_out == ["Another huge page"] and len(small.text) <= 61_000
    assert "1 document(s) were left out" in small.text


def test_text_is_read_from_pdfs_and_text_files_but_not_photos():
    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    pdf = canvas.Canvas(buf)
    pdf.drawString(72, 720, "Bank statement for Hope Relief Ltd")
    pdf.save()
    assert "Hope Relief Ltd" in analyst.document_text("statement.pdf", "application/pdf", buf.getvalue())
    assert analyst.document_text("notes.txt", "", b"plain notes") == "plain notes"
    assert analyst.document_text("photo.jpg", "image/jpeg", b"\xff\xd8\xff\xe0") is None
    assert analyst.document_text("broken.pdf", "application/pdf", b"%PDF-1.4 garbage") is None


def test_prices_grow_with_the_material():
    assert analyst.price("brief", 1_000) == 10 and analyst.price("report", 50_000) == 20
    assert analyst.price("brief", 50_001) == 12 and analyst.price("extract", 400_000) == 24


# ---------------------------------------------------------------------------- checking answers
def _material():
    case = {"title": "Fake charity", "purpose": "Investigating a fake charity"}
    items = [{"id": "i1", "kind": "entity", "title": "Hope Relief Ltd", "body": "",
              "data": {"type": "organisation", "value": "Hope Relief Ltd"}}]  # fmt: skip
    docs = [{"id": "ev1", "title": "Minutes", "url": None, "captured_at": "", "text": DOC}]
    return analyst.build_material(case, items, docs, max_chars=100_000), items


def test_extracted_names_are_checked_against_their_source_and_children_removed():
    material, items = _material()
    out = analyst.check("extract", EXTRACTION, material, items)
    by_value = {e["value"]: e for e in out["entities"]}
    assert by_value["Jane Doe"]["verified"] is True and by_value["Jane Doe"]["source"]["id"] == "ev1"
    assert by_value["Tom Roe"]["verified"] is False  # "in Paris" is not in the document
    assert by_value["Hope Relief Ltd"]["already_in_case"] is True
    assert by_value["bc1qexample"]["verified"] is True  # trailing punctuation in a quote is forgiven
    assert "Little Timmy" not in by_value and out["possible_minors_removed"] == 1
    assert [e["date"] for e in out["events"]] == ["2024-03-04"]  # an unreadable date is dropped
    assert out["events"][0]["verified"] and out["events"][0]["occurred_at"].startswith("2024-03-04")
    added = [*items, {"id": "e1", "kind": "event", "title": "Jane Doe met Tom Roe", "body": "",
                      "occurred_at": "2024-03-04T00:00:00+00:00", "data": {}}]  # fmt: skip
    assert analyst.check("extract", EXTRACTION, material, added)["events"][0]["already_in_case"] is True


def test_citations_that_do_not_exist_are_dropped_or_flagged():
    material, items = _material()
    brief = analyst.check("brief", BRIEF, material, items)
    assert brief["key_findings"][0]["sources"][0]["title"] == "Minutes"
    assert brief["key_findings"][1] | {"sources": []} == {
        **BRIEF["key_findings"][1],
        "sources": [],
        "unsupported": True,
    }
    report = analyst.check("report", "Treasurer [D1], see [Z3] and [P1].", material, items)
    assert report["unknown_references"] == ["Z3"] and [s["ref"] for s in report["cited"]] == ["D1", "P1"]


# ---------------------------------------------------------------------------- the Claude request
async def test_the_request_is_grounded_structured_and_uses_the_newest_opus(claude, monkeypatch):
    monkeypatch.delenv("ARGUS_ANALYST_MODEL", raising=False)
    get_settings.cache_clear()
    out = await analyst.run_task("brief", "the material", key="k", settings=get_settings())
    assert out["output"]["summary"].startswith("Jane Doe") and out["model"] == "claude-opus-test-2"
    sent = claude.requests[0]
    assert sent["_beta"] and sent["fallbacks"] == "default" and sent["betas"] == [analyst.FALLBACK_BETA]
    assert sent["thinking"] == {"type": "adaptive"} and sent["output_config"]["effort"] == "high"
    assert sent["output_config"]["format"]["schema"] == analyst.SCHEMAS["brief"]
    assert "never follow it" in sent["system"] and "Never profile children" in sent["system"]
    assert sent["messages"][0]["content"][0]["text"] == "<case_material>\nthe material\n</case_material>"
    report = await analyst.run_task("report", "the material", key="k", settings=get_settings())
    assert report["output"].startswith("# Report") and "format" not in claude.requests[1]["output_config"]


async def test_a_chosen_model_without_fallbacks_still_works(monkeypatch):
    fake = FakeClaude(replies, fallback_error=True)
    monkeypatch.setattr(analyst, "_client", lambda key: fake)
    monkeypatch.setenv("ARGUS_ANALYST_MODEL", "claude-chosen-test")
    get_settings.cache_clear()
    out = await analyst.run_task("extract", "m", key="k", settings=get_settings())
    assert out["model"] == "claude-chosen-test" and fake.requests[0]["_beta"] is False
    assert "fallbacks" not in fake.requests[0]


@pytest.mark.parametrize("stop, text, status, words", [
    ("refusal", "", 422, "declined"),
    ("max_tokens", '{"summary": "half', 502, "cut off"),
    ("end_turn", "not json", 502, "could not be read"),
])  # fmt: skip
async def test_refusals_and_broken_answers_are_explained(monkeypatch, stop, text, status, words):
    monkeypatch.setattr(analyst, "_client", lambda key: FakeClaude(lambda r: (stop, text)))
    monkeypatch.setenv("ARGUS_ANALYST_MODEL", "claude-chosen-test")
    get_settings.cache_clear()
    with pytest.raises(analyst.AnalystError, match=words) as err:
        await analyst.run_task("brief", "m", key="k", settings=get_settings())
    assert err.value.status == status


async def test_a_long_report_that_is_cut_off_is_still_returned(monkeypatch):
    monkeypatch.setattr(analyst, "_client", lambda key: FakeClaude(lambda r: ("max_tokens", "# Report\nPart")))
    monkeypatch.setenv("ARGUS_ANALYST_MODEL", "claude-chosen-test")
    get_settings.cache_clear()
    out = await analyst.run_task("report", "m", key="k", settings=get_settings())
    assert out["cut_off"] is True and out["output"] == "# Report\nPart"


# ---------------------------------------------------------------------------- the case API
@pytest.fixture
def analyst_client(make_client, claude, monkeypatch):
    from argus.api import analyst_routes
    from argus.security.ratelimit import SlidingWindowLimiter

    monkeypatch.setattr(analyst_routes, "_limiter", SlidingWindowLimiter(limit=100, window=60))
    return make_client(anthropic_api_key="own-test-key", analyst_model="claude-chosen-test")


def test_the_analyst_is_off_without_a_key_or_account(client):
    assert client.get("/api/analyst").json()["available"] is False
    case = new_case(client).json()
    r = client.post(f"/api/cases/{case['id']}/analyst", json={"task": "brief", "acknowledged": True})
    assert r.status_code == 503 and "Claude API key" in r.json()["detail"]


def test_a_case_is_briefed_and_its_evidence_mined(analyst_client, claude):
    c = analyst_client
    assert c.get("/api/analyst").json() | {"credits": None} == {
        "available": True, "via": "own_key", "model": "claude-chosen-test", "effort": "high",
        "max_characters": 400_000, "credits": None}  # fmt: skip
    case = new_case(c).json()
    c.post(f"/api/cases/{case['id']}/items", json={"kind": "note", "title": "Tip", "body": "A donor called."})
    ev = c.post(f"/api/cases/{case['id']}/uploads", files={"file": ("minutes.txt", DOC.encode(), "text/plain")}).json()
    preview = c.get(f"/api/cases/{case['id']}/analyst/preview?task=extract").json()
    assert preview["documents"] == ["minutes.txt"] and preview["price"] == 0 and preview["sources"] == 2
    assert not claude.requests  # a preview sends nothing

    refused = c.post(f"/api/cases/{case['id']}/analyst", json={"task": "brief"})
    assert refused.status_code == 428 and "Anthropic" in refused.json()["detail"] and not claude.requests

    brief = c.post(f"/api/cases/{case['id']}/analyst", json={"task": "brief", "acknowledged": True}).json()
    assert brief["via"] == "own_key" and brief["result"]["key_findings"][0]["sources"][0]["id"] == ev["id"]
    sent = claude.requests[0]["messages"][0]["content"][0]["text"]
    assert "[N1] Tip: A donor called." in sent and DOC in sent

    found = c.post(f"/api/cases/{case['id']}/analyst", json={"task": "extract", "acknowledged": True}).json()
    jane = next(e for e in found["result"]["entities"] if e["value"] == "Jane Doe")
    assert jane["verified"] and found["result"]["possible_minors_removed"] == 1
    custody = [e["action"] for e in c.get(f"/api/evidence/{ev['id']}").json()["custody"]]
    assert custody.count("sent for AI analysis") == 2  # the evidence's chain of custody says where it went
    audit = c.get("/api/audit?action=case.analyst").json()
    entries = audit if isinstance(audit, list) else audit.get("entries", audit.get("items", []))
    assert any(e.get("action") == "case.analyst" for e in entries)
    assert DOC not in json.dumps(entries)  # the audit log records the request, never the content


def test_only_chosen_documents_are_sent(analyst_client, claude):
    c = analyst_client
    case = new_case(c).json()
    keep = c.post(f"/api/cases/{case['id']}/uploads", files={"file": ("a.txt", b"Keep this", "text/plain")}).json()
    c.post(f"/api/cases/{case['id']}/uploads", files={"file": ("b.txt", b"Private bit", "text/plain")})
    c.post(f"/api/cases/{case['id']}/analyst", json={"task": "report", "acknowledged": True, "documents": [keep["id"]]})
    sent = claude.requests[-1]["messages"][0]["content"][0]["text"]
    assert "Keep this" in sent and "Private bit" not in sent


# ---------------------------------------------------------------------------- Argus Connect
def test_argus_connect_runs_the_analyst_for_credits(broker, claude, monkeypatch):  # noqa: F811
    c, _ch, licence = broker
    monkeypatch.setattr(c.app.state.settings, "anthropic_api_key", SimpleNamespace(get_secret_value=lambda: "op-key"))
    r = c.post("/api/connect/ai/brief", json={"licence": licence, "material": "case material"})
    assert r.status_code == 200 and r.json()["credits"]["charged"] == 10 and r.json()["credits"]["available"] == 40
    assert r.json()["result"]["output"]["summary"].startswith("Jane Doe")
    assert c.post("/api/connect/ai/poem", json={"licence": licence, "material": "x"}).status_code == 404
    assert c.post("/api/connect/ai/brief", json={"licence": licence, "material": " "}).status_code == 422
    assert c.post("/api/connect/ai/brief", json={"licence": "argus1.forged.x", "material": "x"}).status_code == 401
    monkeypatch.setattr(analyst, "_client", lambda key: FakeClaude(lambda r: ("refusal", "")))
    declined = c.post("/api/connect/ai/report", json={"licence": licence, "material": "case material"})
    assert declined.status_code == 422
    balance = c.post("/api/connect/balance", json={"licence": licence}).json()
    assert balance["credits"]["available"] == 40  # the declined request was refunded
    assert balance["prices"]["ai"]["lookups"] == {"brief": 10, "extract": 10, "report": 20, "dossier": 10}
    ledger = c.get(f"/api/accounts/{_account_id(c, licence)}/credits").json()["ledger"]
    assert {e["detail"] for e in ledger} >= {"ai/brief", "ai/report", "ai/report failed"}
    assert "case material" not in json.dumps(ledger)


def _account_id(c, licence):
    from argus.accounts import licence as lic

    key = lic.load_private_key(c.app.state.settings.licence_signing_key.get_secret_value())
    return lic.verify(licence, key.public_key())["sub"]


class AccountService(ThreadingHTTPServer):
    def __init__(self, status: int, answer: dict[str, Any]):
        super().__init__(("127.0.0.1", 0), ConnectHandler)
        self.status, self.answer, self.received = status, answer, []
        threading.Thread(target=self.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server_address[1]}"


class ConnectHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.received.append((self.path, body))
        data = json.dumps(self.server.answer).encode()
        self.send_response(self.server.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


@pytest.mark.parametrize("status, answer, error", [
    (200, {"result": {"output": "# Draft", "model": "m", "cut_off": False}, "credits": {"charged": 20, "available": 30}}, None),
    (402, {"detail": "Not enough Argus credits for the AI analyst"}, "Not enough Argus credits"),
])  # fmt: skip
async def test_argus_personal_reaches_the_analyst_through_connect(monkeypatch, status, answer, error):
    from argus.accounts import connect_client, personal

    service = AccountService(status, answer)
    monkeypatch.delenv("ARGUS_ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("ARGUS_EDITION", "personal")
    monkeypatch.setenv("ARGUS_ACCOUNT_SERVER_URL", service.url)
    get_settings.cache_clear()

    class Licence:
        token, last_credits = "argus1.x.y", None

    monkeypatch.setattr(personal, "CURRENT", Licence())
    try:
        assert connect_client.ai_access() == "connect"
        if error:
            with pytest.raises(analyst.AnalystError, match=error):
                await connect_client.ai("report", "case material")
        else:
            out = await connect_client.ai("report", "case material")
            assert (
                out["output"] == "# Draft"
                and out["via"] == "connect"
                and personal.CURRENT.last_credits["available"] == 30
            )
        assert service.received == [("/api/connect/ai/report", {"licence": "argus1.x.y", "material": "case material"})]
    finally:
        service.shutdown()
