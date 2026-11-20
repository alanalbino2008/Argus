"""The legal documents customers see: filled in with the owner's details, served as web pages.

The documents are templates (``argus/data/legal/*.md``) written for Argus as it actually works:
cases stay on the investigator's computer; the account service holds only account, device,
payment and credit records; lookups and AI requests pass through without being kept. The owner
fills in their business details in the owner console (Legal), and **publishes** a version (a
date): from then on, new accounts must accept it, and existing customers are asked to accept
again whenever a newer version is published.

They're a starting point, not legal advice: the console says so until the owner confirms a
lawyer has reviewed them.
"""

from __future__ import annotations

import html
import re
from functools import cache
from pathlib import Path
from typing import Any

DOCS = {
    "terms": "Terms of Service",
    "privacy": "Privacy Policy",
    "acceptable-use": "Acceptable Use Policy",
    "refunds": "Refunds and Cancellation",
    "dpa": "Data Processing Agreement",
    "subprocessors": "Subprocessors",
}
ACCEPTED_WITH_TERMS = ("terms", "acceptable-use", "privacy")  # what "I agree" covers
FOLDER = Path(__file__).resolve().parent.parent / "data" / "legal"
_PLACEHOLDER = re.compile(r"\{\{([a-z_]+)\}\}")


def published(settings: Any) -> str:
    """The published version (a date), or "" while the owner hasn't published the documents."""
    return str(settings.legal_terms_version or "")


def needs_acceptance(settings: Any, account: dict[str, Any] | None) -> bool:
    version = published(settings)
    return bool(version and account and account.get("terms_version") != version)


def values(settings: Any) -> dict[str, str]:
    """What fills the templates: the owner's details, or a visible gap where one is missing."""

    def get(name: str, missing: str) -> str:
        return str(getattr(settings, name, "") or "").strip() or missing

    company = get("legal_company_name", "[your business's legal name]")
    number = str(settings.legal_company_number or "").strip()
    address = str(settings.legal_company_address or "").strip()
    contact = get("legal_contact_email", "") or str(settings.support_email or "") or "[contact email]"
    hosting = get("legal_hosting_provider", "[hosting provider]")
    email = (
        get("legal_email_provider", "") or (str(settings.smtp_host or "") and "[email provider]") or "[email provider]"
    )
    return {
        "company": company,
        "company_number_text": f" (company number {number})" if number else "",
        "address_text": f"of {address}" if address else "[registered address]",
        "contact": contact,
        "privacy_contact": get("legal_privacy_email", "") or contact,
        "governing_law": get("legal_governing_law", "England and Wales"),
        "authority": get("legal_supervisory_authority", "the Information Commissioner's Office (ico.org.uk)"),
        "hosting_provider": hosting.split("|")[0].strip(),
        "hosting_location": (hosting.split("|")[1].strip() if "|" in hosting else "[location]"),
        "email_provider": email.split("|")[0].strip(),
        "email_location": (email.split("|")[1].strip() if "|" in email else "[location]"),
        "version": published(settings) or "draft",
        "trial_days": str(settings.trial_days),
    }


@cache
def _template(doc: str) -> str:
    return (FOLDER / f"{doc}.md").read_text(encoding="utf-8")


def text(doc: str, settings: Any) -> str:
    """A document with the owner's details filled in (Markdown)."""
    if doc not in DOCS:
        raise KeyError(doc)
    filled = values(settings)
    return _PLACEHOLDER.sub(lambda m: filled.get(m.group(1), m.group(0)), _template(doc))


# ---------------------------------------------------------------------------- Markdown to HTML
_LINK = re.compile(r"\[([^\]]+)\]\((/legal/[a-z-]+|https://[^)\s]+)\)")
_BOLD = re.compile(r"\*\*(.+?)\*\*")


def _inline(raw: str) -> str:
    out = html.escape(raw, quote=True)  # everything escaped first: the owner's details are text
    out = _BOLD.sub(r"<strong>\1</strong>", out)
    return _LINK.sub(lambda m: f'<a href="{m.group(2)}">{m.group(1)}</a>', out)


def to_html(markdown: str) -> str:
    """The small Markdown the documents use: headings, paragraphs, lists, tables, bold, links."""
    blocks: list[str] = []
    para: list[str] = []
    items: list[str] = []
    table: list[str] = []
    numbered = False

    def flush() -> None:
        nonlocal para, items, table
        if para:
            blocks.append(f"<p>{_inline(' '.join(para))}</p>")
            para = []
        if items:
            tag = "ol" if numbered else "ul"
            blocks.append(f"<{tag}>" + "".join(f"<li>{_inline(i)}</li>" for i in items) + f"</{tag}>")
            items = []
        if table:
            rows = [
                [c.strip() for c in r.strip().strip("|").split("|")] for r in table if not re.match(r"^\|[-| ]+\|$", r)
            ]
            head = "".join(f"<th>{_inline(c)}</th>" for c in rows[0])
            body = "".join("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in r) + "</tr>" for r in rows[1:])
            blocks.append(
                f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'
            )
            table = []

    for line in markdown.splitlines():
        stripped = line.strip()
        heading = re.match(r"^(#{1,3}) (.+)$", stripped)
        bullet = re.match(r"^- (.+)$", stripped)
        number = re.match(r"^\d+\. (.+)$", stripped)
        if heading:
            flush()
            level = len(heading.group(1))
            blocks.append(f"<h{level}>{_inline(heading.group(2))}</h{level}>")
        elif stripped.startswith("|"):
            if para or items:
                flush()
            table.append(stripped)
        elif bullet or number:
            if para or table:
                flush()
            numbered = bool(number)
            items.append((bullet or number).group(1))  # type: ignore[union-attr]
        elif not stripped:
            flush()
        else:
            if items or table:
                flush()
            para.append(stripped)
    flush()
    return "\n".join(blocks)


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{title} · {company}</title>
<style>
:root{{--bg:#fff;--text:#111827;--muted:#4b5563;--line:#e5e7eb;--accent:#0369a1;--note:#fef3c7}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0b1220;--text:#e5e7eb;--muted:#9ca3af;--line:#1f2937;--accent:#38bdf8;--note:#3b2f0b}}}}
body{{margin:0;background:var(--bg);color:var(--text);font:16px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
main{{max-width:760px;margin:0 auto;padding:32px 16px 64px}} a{{color:var(--accent)}}
nav{{display:flex;gap:12px;flex-wrap:wrap;font-size:14px;border-bottom:1px solid var(--line);padding-bottom:12px;margin-bottom:8px}}
nav a[aria-current]{{font-weight:600;text-decoration:none;color:var(--text)}}
h1{{font-size:28px;margin:24px 0 8px}} h2{{font-size:20px;margin:28px 0 8px}}
.scroll{{overflow-x:auto}} table{{border-collapse:collapse;width:100%;font-size:14px}}
th,td{{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}}
.draft{{background:var(--note);padding:10px 12px;border-radius:8px;font-size:14px}}
footer{{color:var(--muted);font-size:13px;margin-top:40px}}
</style></head><body><main>
<nav aria-label="Legal documents">{nav}</nav>
{draft}
{body}
<footer>{company} · Questions: {contact}</footer>
</main></body></html>"""


def page(doc: str, settings: Any) -> str:
    filled = values(settings)
    current = ' aria-current="page"'
    nav = " ".join(f'<a href="/legal/{d}"{current if d == doc else ""}>{html.escape(t)}</a>' for d, t in DOCS.items())
    draft = "" if published(settings) else '<p class="draft">Draft: these documents have not been published yet.</p>'
    return PAGE.format(title=html.escape(DOCS[doc]), company=html.escape(filled["company"]), nav=nav, draft=draft,
                       body=to_html(text(doc, settings)), contact=html.escape(filled["contact"]))  # fmt: skip


def links(base: str) -> dict[str, str]:
    base = base.rstrip("/")
    return {doc: f"{base}/legal/{doc}" for doc in DOCS}


def health(settings: Any) -> tuple[str, str, str]:
    """(status, detail, what to do) for the owner console."""
    missing = [label for name, label in (("legal_company_name", "business name"), ("legal_company_address", "address"),
                                         ("legal_contact_email", "contact email"))
               if not getattr(settings, name, "")]  # fmt: skip
    if missing:
        return "warn", f"Missing: {', '.join(missing)}", "Fill in your business details under Legal"
    if not published(settings):
        return "warn", "Not published yet: new customers aren't asked to accept them", "Publish them under Legal"
    if not settings.legal_reviewed:
        return (
            "warn",
            f"Version {published(settings)} published; not yet reviewed by a lawyer",
            ("Have a lawyer review them, then tick 'A lawyer has reviewed these' under Legal"),
        )
    return "ok", f"Version {published(settings)} published and reviewed", ""
