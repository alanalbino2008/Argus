# ruff: noqa: PERF401  (record by record is clearer than comprehensions here)
"""Lawfully obtained data, imported into a case: call records, bank and payment statements, contact lists,
and phone extraction reports. Each is read into simple records and cross-referenced with the case.

Formats:

* **Call detail records** (CSV or XLSX): one row per call or message, with the caller, the called number,
  the time, and often the duration, type and cell. Column names vary by operator; common ones are
  recognised (``A Party``, ``Calling Number``, ``From``, ``Start Time``, ``Duration``, ``Cell ID``...).
* **Transactions** (CSV, XLSX, or a PDF statement with text): bank or payment statements: date, amount (or paid in / paid out),
  counterparty or description, account and reference.
* **Contact lists** (CSV or XLSX): names with phone numbers or email addresses, such as an address-book
  export from a phone or an XRY contacts export.
* **Cellebrite UFDR** (the ``.ufdr`` file, a ZIP with ``report.xml``): contacts, calls, chats and messages,
  and user accounts. XRY exports are read through their CSV or XLSX exports of contacts and calls.

Nothing is sent anywhere: the file is read on the Argus server, kept as case evidence (fingerprinted,
with its chain of custody), and its records are kept beside it.
"""

from __future__ import annotations

import csv
import io
import re
import zipfile
from datetime import datetime, timezone
from typing import Any

from defusedxml import ElementTree as SafeET

from argus.intel.names import similarity

MAX_RECORDS = 200_000
MAX_XML = 200 * 1024 * 1024
KINDS = ("auto", "cdr", "transactions", "contacts", "ufdr")


class ImportError_(ValueError):
    pass


def _key(header: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(header or "").strip().lower()).strip("_")


ALIASES = {
    "from": ("a_party", "a_number", "anumber", "calling", "calling_number", "caller", "from", "from_number", "msisdn",
             "originating", "originating_number", "source", "source_number", "a_msisdn"),
    "to": ("b_party", "b_number", "bnumber", "called", "called_number", "callee", "to", "to_number", "destination",
           "destination_number", "dialled", "dialed", "dialled_number", "terminating", "b_msisdn", "other_party"),
    "when": ("start", "start_time", "start_date_time", "datetime", "date_time", "timestamp", "time_stamp", "call_date",
             "event_time", "date_and_time", "transaction_date", "date"),
    "time": ("time", "start_time_only", "call_time"),
    "duration": ("duration", "duration_seconds", "seconds", "call_duration", "dur", "duration_s"),
    "type": ("type", "call_type", "event", "event_type", "service", "record_type", "direction"),
    "cell": ("cell", "cell_id", "cellid", "cgi", "site", "site_id", "tower", "lac_ci", "first_cell", "location"),
    "amount": ("amount", "value", "transaction_amount", "amount_gbp", "amount_eur", "amount_usd"),
    "paid_in": ("paid_in", "credit", "money_in", "credit_amount", "in"),
    "paid_out": ("paid_out", "debit", "money_out", "debit_amount", "out"),
    "counterparty": ("counterparty", "payee", "payer", "beneficiary", "merchant", "name", "counterparty_name",
                     "description", "narrative", "details", "transaction_description", "memo"),
    "account": ("account", "account_number", "counterparty_account", "iban", "sort_code", "beneficiary_account",
                "payee_account"),
    "reference": ("reference", "ref", "payment_reference"),
    "phone": ("phone", "phone_number", "mobile", "mobile_phone", "telephone", "number", "tel", "cell_phone", "home_phone",
              "work_phone", "phone_1", "phone_2"),
    "email": ("email", "e_mail", "email_address", "mail"),
    "contact_name": ("name", "full_name", "display_name", "contact", "contact_name", "first_name"),
    "last_name": ("last_name", "surname", "family_name"),
}  # fmt: skip


def _columns(headers: list[str]) -> dict[str, list[int]]:
    keys = [_key(h) for h in headers]
    found: dict[str, list[int]] = {}
    for field, names in ALIASES.items():
        for i, k in enumerate(keys):
            if k in names:
                found.setdefault(field, []).append(i)
    return found


def norm_phone(value: str) -> str:
    raw = str(value or "").strip()
    digits = re.sub(r"\D", "", raw)
    if len(digits) < 5:
        return ""
    return ("+" if raw.startswith("+") or raw.startswith("00") else "") + digits.removeprefix("00")


def _identifier(value: Any) -> str:
    text = str(value or "").strip()
    if "@" in text and "." in text.split("@")[-1]:
        return text.lower()
    phone = norm_phone(text)
    return phone or text[:120]


DATE_FORMATS = ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M",
                "%d/%m/%Y", "%Y-%m-%d", "%d-%m-%Y %H:%M:%S", "%d-%m-%Y", "%d.%m.%Y %H:%M:%S", "%d.%m.%Y", "%m/%d/%Y %H:%M:%S",
                "%d %b %Y", "%d %b %Y %H:%M:%S", "%Y%m%d%H%M%S")  # fmt: skip


def parse_when(value: Any, time_value: Any = None) -> str | None:
    """An ISO date-time from the many ways records write them (day-first where ambiguous, as in UK and EU records)."""
    moment: datetime | None
    if isinstance(value, datetime):
        moment = value
    else:
        text = str(value or "").strip()
        if time_value and str(time_value).strip() and ":" not in text:
            text = f"{text} {str(time_value).strip()}"
        if not text:
            return None
        text = re.sub(r"(\.\d+)?(Z|[+-]\d\d:?\d\d)?$", "", text.replace("T", " ", 1)).strip()
        moment = None
        for fmt in DATE_FORMATS:
            try:
                moment = datetime.strptime(text, fmt.replace("T", " "))
                break
            except ValueError:
                continue
        if moment is None:
            return None
    return (moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)).isoformat()


def _money(value: Any) -> float | None:
    text = re.sub(r"[^\d,.\-()]", "", str(value or "").strip())
    if not text:
        return None
    negative = (text.startswith("(") and text.endswith(")")) or text.startswith("-")
    text = text.strip("()-")
    if "," in text and "." in text:
        text = text.replace(",", "") if text.rfind(".") > text.rfind(",") else text.replace(".", "").replace(",", ".")
    elif "," in text and len(text.split(",")[-1]) == 2:
        text = text.replace(",", ".")
    else:
        text = text.replace(",", "")
    try:
        amount = float(text)
    except ValueError:
        return None
    return -amount if negative else amount


# ---------------------------------------------------------------------------- tables (CSV and XLSX)
def read_csv(data: bytes) -> list[list[str]]:
    text = data.decode("utf-8-sig", errors="replace")
    try:
        dialect = csv.Sniffer().sniff(text[:20000], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    return [row for row in csv.reader(io.StringIO(text), dialect) if any(cell.strip() for cell in row)][
        : MAX_RECORDS + 1
    ]


def read_xlsx(data: bytes) -> list[list[str]]:
    """The first worksheet of an Excel file, read safely (no macros, no external references)."""
    ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ImportError_("This is not an Excel (.xlsx) file") from exc
    with z:
        names = z.namelist()
        shared: list[str] = []
        if "xl/sharedStrings.xml" in names:
            if z.getinfo("xl/sharedStrings.xml").file_size > MAX_XML:
                raise ImportError_("The spreadsheet is too large")
            root = SafeET.fromstring(z.read("xl/sharedStrings.xml"))
            shared = ["".join(t.text or "" for t in si.iter(f"{{{ns['m']}}}t")) for si in root.findall("m:si", ns)]
        sheets = sorted(n for n in names if re.fullmatch(r"xl/worksheets/sheet\d+\.xml", n))
        if not sheets:
            raise ImportError_("The spreadsheet has no worksheet")
        if z.getinfo(sheets[0]).file_size > MAX_XML:
            raise ImportError_("The spreadsheet is too large")
        root = SafeET.fromstring(z.read(sheets[0]))
    rows: list[list[str]] = []
    for row in root.iter(f"{{{ns['m']}}}row"):
        cells: dict[int, str] = {}
        for c in row.findall("m:c", ns):
            ref = c.get("r") or ""
            letters = re.match(r"[A-Z]+", ref)
            col = 0
            for ch in letters.group(0) if letters else "":
                col = col * 26 + ord(ch) - 64
            v = c.find("m:v", ns)
            inline = c.find("m:is", ns)
            if c.get("t") == "s" and v is not None and v.text is not None:
                value = shared[int(v.text)] if int(v.text) < len(shared) else ""
            elif inline is not None:
                value = "".join(t.text or "" for t in inline.iter(f"{{{ns['m']}}}t"))
            else:
                value = v.text if v is not None and v.text is not None else ""
            cells[max(col - 1, len(cells)) if not letters else col - 1] = value
        if cells:
            rows.append([cells.get(i, "") for i in range(max(cells) + 1)])
        if len(rows) > MAX_RECORDS:
            break
    return [r for r in rows if any(str(x).strip() for x in r)]


def _excel_date(value: str) -> str | None:
    """Excel stores dates as days since 1899-12-30."""
    try:
        serial = float(value)
    except ValueError:
        return None
    if not 20000 < serial < 80000:
        return None
    from datetime import timedelta

    return (datetime(1899, 12, 30, tzinfo=timezone.utc) + timedelta(days=serial)).isoformat()


def table(data: bytes, filename: str) -> list[list[str]]:
    return read_xlsx(data) if filename.lower().endswith((".xlsx", ".xlsm")) or data[:2] == b"PK" else read_csv(data)


def _get(row: list[str], cols: dict[str, list[int]], field: str) -> str:
    for i in cols.get(field, []):
        if i < len(row) and str(row[i]).strip():
            return str(row[i]).strip()
    return ""


def _when_of(row: list[str], cols: dict[str, list[int]]) -> str | None:
    raw = _get(row, cols, "when")
    return parse_when(raw, _get(row, cols, "time") if cols.get("time") != cols.get("when") else None) or _excel_date(
        raw
    )


def records_from_table(rows: list[list[str]], kind: str) -> tuple[str, list[dict[str, Any]]]:
    """(the kind recognised, the records) from a table with a header row."""
    if len(rows) < 2:
        raise ImportError_("The file has no rows after its header")
    cols = _columns(rows[0])
    if kind == "auto":
        if cols.get("from") and cols.get("to"):
            kind = "cdr"
        elif cols.get("amount") or cols.get("paid_in") or cols.get("paid_out"):
            kind = "transactions"
        elif cols.get("phone") or cols.get("email"):
            kind = "contacts"
        else:
            raise ImportError_("The columns were not recognised: name them like a call record (From, To, Start Time), "
                               "a statement (Date, Amount, Description) or a contact list (Name, Phone)")  # fmt: skip
    out: list[dict[str, Any]] = []
    for row in rows[1 : MAX_RECORDS + 1]:
        if kind == "cdr":
            a, b = _identifier(_get(row, cols, "from")), _identifier(_get(row, cols, "to"))
            if not a and not b:
                continue
            kind_text = _get(row, cols, "type").lower()
            rtype = "sms" if any(w in kind_text for w in ("sms", "text", "mms", "message")) else "call"
            duration = re.sub(r"[^\d]", "", _get(row, cols, "duration"))
            out.append({"type": rtype, "when": _when_of(row, cols), "from": a, "to": b,
                        "duration": int(duration) if duration else None, "cell": _get(row, cols, "cell") or None,
                        "detail": kind_text or None})  # fmt: skip
        elif kind == "transactions":
            amount = _money(_get(row, cols, "amount"))
            if amount is None:
                paid_in, paid_out = _money(_get(row, cols, "paid_in")), _money(_get(row, cols, "paid_out"))
                amount = (paid_in or 0) - abs(paid_out or 0) if (paid_in or paid_out) else None
            if amount is None:
                continue
            out.append({"type": "transaction", "when": _when_of(row, cols), "amount": round(amount, 2),
                        "counterparty": _get(row, cols, "counterparty")[:200] or None,
                        "account": _get(row, cols, "account")[:60] or None,
                        "reference": _get(row, cols, "reference")[:120] or None})  # fmt: skip
        else:
            name = " ".join(x for x in (_get(row, cols, "contact_name"), _get(row, cols, "last_name")) if x)[:200]
            ids = [
                _identifier(row[i])
                for f in ("phone", "email")
                for i in cols.get(f, [])
                if i < len(row) and row[i].strip()
            ]
            for ident in dict.fromkeys(i for i in ids if i):
                out.append({"type": "contact", "name": name or None, "from": ident})
    return kind, out


# ---------------------------------------------------------------------------- Cellebrite UFDR
def _fields(model: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    for f in model.findall("{*}field"):
        value = f.find("{*}value")
        if f.get("name") and value is not None and value.text:
            out[f.get("name")] = value.text.strip()
    return out


def _parties(model: Any) -> list[dict[str, str]]:
    found = []
    for mm in model.findall("{*}multiModelField"):
        for party in mm.findall("{*}model"):
            if party.get("type") in ("Party", "Contact", "PhoneNumber", "EmailAddress", "UserID"):
                fields = _fields(party)
                found.append({"role": fields.get("Role") or mm.get("name") or "", "id": fields.get("Identifier") or
                              fields.get("Value") or "", "name": fields.get("Name") or ""})  # fmt: skip
    for mf in model.findall("{*}modelField"):
        for party in mf.findall("{*}model"):
            fields = _fields(party)
            if fields.get("Identifier") or fields.get("Value"):
                found.append({"role": mf.get("name") or "", "id": fields.get("Identifier") or fields.get("Value") or "",
                              "name": fields.get("Name") or ""})  # fmt: skip
    return found


def records_from_ufdr(data: bytes) -> list[dict[str, Any]]:
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ImportError_("This is not a UFDR file (a ZIP archive with report.xml)") from exc
    with z:
        reports = [n for n in z.namelist() if n.lower().endswith("report.xml")] or [
            n for n in z.namelist() if n.lower().endswith(".xml")]  # fmt: skip
        if not reports:
            raise ImportError_("The UFDR file has no report.xml")
        info = z.getinfo(reports[0])
        if info.file_size > MAX_XML:
            raise ImportError_("The report is larger than 200 MB; export a smaller extraction")
        root = SafeET.fromstring(z.read(info))
    out: list[dict[str, Any]] = []
    for model in (el for el in root.iter() if isinstance(el.tag, str) and el.tag.rsplit("}", 1)[-1] == "model"):
        mtype = model.get("type")
        if mtype not in ("Contact", "Call", "InstantMessage", "SMS", "Email", "UserAccount"):
            continue
        fields = _fields(model)
        parties = _parties(model)
        when = parse_when(fields.get("TimeStamp") or fields.get("DateTime") or fields.get("Date"))
        if mtype == "Contact":
            for p in parties or [{"id": fields.get("Value") or "", "name": ""}]:
                if p["id"]:
                    out.append(
                        {
                            "type": "contact",
                            "name": fields.get("Name") or p["name"] or None,
                            "from": _identifier(p["id"]),
                        }
                    )
        elif mtype == "UserAccount":
            out.append({"type": "account", "name": fields.get("Name") or None, "from": _identifier(fields.get("Username") or
                        fields.get("Name") or ""), "detail": fields.get("ServiceType") or fields.get("Source") or None})  # fmt: skip
        else:
            sender = next((p for p in parties if p["role"].lower() in ("from", "sender")), None)
            receivers = [p for p in parties if p["role"].lower() in ("to", "receiver", "recipient", "participants")]
            if mtype == "Call" and not sender and parties:
                direction = fields.get("Direction", "").lower()
                other = parties[0]
                sender = {"id": "(this phone)", "name": ""} if direction.startswith("out") else other
                receivers = [other] if direction.startswith("out") else [{"id": "(this phone)", "name": ""}]
            for r in receivers or [{"id": "", "name": ""}]:
                out.append({"type": {"Call": "call", "SMS": "sms", "Email": "email"}.get(mtype, "message"), "when": when,
                            "from": _identifier((sender or {}).get("id")), "to": _identifier(r.get("id")),
                            "name": (sender or {}).get("name") or r.get("name") or None,
                            "duration": int(fields["Duration"].split(".")[0].replace(":", "") or 0)
                            if fields.get("Duration", "").replace(":", "").split(".")[0].isdigit() else None,
                            "detail": fields.get("Source") or None})  # fmt: skip
        if len(out) >= MAX_RECORDS:
            break
    return out


# ---------------------------------------------------------------------------- PDF bank statements
PDF_LINE = re.compile(
    r"^\s*(?P<date>\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}|\d{4}-\d{2}-\d{2}|\d{1,2}\s+[A-Za-z]{3}\s*(?:\d{2,4})?)\s+"
    r"(?P<text>.*?)\s+(?P<amounts>(?:\(?-?[£$€]?\d{1,3}(?:[,.]\d{3})*[.,]\d{2}\)?(?:\s*(?:CR|DR))?\s*){1,3})$"
)
AMOUNT = re.compile(r"\(?-?[£$€]?\d{1,3}(?:[,.]\d{3})*[.,]\d{2}\)?(?:\s*(?:CR|DR))?")
CREDIT_WORDS = (
    "credit",
    "received",
    "salary",
    "wages",
    "refund",
    "interest paid",
    "transfer from",
    "deposit",
    "paid in",
)


def records_from_pdf_statement(data: bytes) -> list[dict[str, Any]]:
    """Transactions read from the text of a PDF statement: a line starting with a date and ending in an amount
    (and usually the balance). With a balance, the sign comes from how it moved; otherwise from the wording.
    Scanned (image-only) statements have no text to read."""
    from pypdf import PdfReader

    try:
        reader = PdfReader(io.BytesIO(data))
        text = "\n".join((page.extract_text() or "") for page in reader.pages[:200])
    except Exception as exc:
        raise ImportError_(f"The PDF could not be read ({type(exc).__name__}); is it password-protected?") from exc
    if not text.strip():
        raise ImportError_("The PDF has no text (a scanned statement): export it as CSV from the bank instead")
    out: list[dict[str, Any]] = []
    balance: float | None = None
    year = None
    for line in text.splitlines():
        match = PDF_LINE.match(line)
        if not match:
            continue
        amounts = AMOUNT.findall(match.group("amounts"))
        values = [_money(a.replace("CR", "").replace("DR", "")) for a in amounts]
        if not values or values[0] is None:
            continue
        date = match.group("date").strip()
        if re.fullmatch(r"\d{1,2}\s+[A-Za-z]{3}", date) and year:
            date = f"{date} {year}"
        when = parse_when(date)
        if when:
            year = when[:4]
        amount = abs(values[0])
        if len(values) >= 2 and values[-1] is not None:
            new_balance = values[-1]
            sign = 1 if balance is not None and new_balance > balance else -1 if balance is not None else None
            balance = new_balance
        else:
            sign = None
        words = (match.group("text") + " " + match.group("amounts")).lower()
        if sign is None:
            sign = 1 if "cr" in match.group("amounts").lower() or any(w in words for w in CREDIT_WORDS) else -1
        out.append({"type": "transaction", "when": when, "amount": round(sign * amount, 2),
                    "counterparty": match.group("text").strip()[:200] or None, "account": None, "reference": None,
                    "detail": "read from a PDF: check against the original"})  # fmt: skip
    if not out:
        raise ImportError_(
            "No transactions were recognised in the PDF (lines starting with a date and ending in an amount)"
        )
    return out


def parse(data: bytes, filename: str, kind: str = "auto") -> tuple[str, list[dict[str, Any]]]:
    """(the kind read, its records). Raises :class:`ImportError_` with a readable reason."""
    if kind not in KINDS:
        raise ImportError_(f"Unknown kind {kind!r}")
    lower = filename.lower()
    if data.startswith(b"%PDF") or lower.endswith(".pdf"):
        if kind not in ("auto", "transactions"):
            raise ImportError_("Only bank or payment statements are read from PDFs")
        return "transactions", records_from_pdf_statement(data)
    if kind == "ufdr" or (kind == "auto" and lower.endswith(".ufdr")):
        return "ufdr", records_from_ufdr(data)
    return records_from_table(table(data, filename), kind)


# ---------------------------------------------------------------------------- what the records say
def phone_key(value: str) -> str:
    digits = re.sub(r"\D", "", value or "")
    return digits[-9:] if len(digits) >= 7 else ""


def case_identifiers(items: list[dict[str, Any]], people: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every phone number, email address, username and name already in the case, with where it is."""
    out: list[dict[str, Any]] = []
    for item in items:
        data = item.get("data") or {}
        if item.get("kind") != "entity":
            continue
        value = str(data.get("value") or item.get("title") or "")
        out.append({"kind": data.get("type") or "other", "value": value, "where": f"case entity: {item.get('title')}"})
    for person in people:
        known = person.get("known") or {}
        for field, kind in (("phones", "phone"), ("emails", "email"), ("usernames", "username"), ("names", "person")):
            for value in known.get(field) or []:
                out.append({"kind": kind, "value": str(value), "where": f"known about {person['name']}"})
        for cand in person.get("candidates") or []:
            if cand.get("status") == "confirmed" and cand.get("kind") in ("phone", "email", "username"):
                out.append({"kind": cand["kind"], "value": cand["value"], "where": f"confirmed for {person['name']}"})
    return out


def analyse(records: list[dict[str, Any]], known: list[dict[str, Any]]) -> dict[str, Any]:
    """Who appears most, when, and which of them are already in the case."""
    phones: dict[str, list[dict[str, Any]]] = {}
    others: dict[str, list[dict[str, Any]]] = {}
    names = []
    for k in known:
        if k["kind"] == "phone" and phone_key(k["value"]):
            phones.setdefault(phone_key(k["value"]), []).append(k)
        elif k["kind"] in ("person", "organisation"):
            names.append(k)
        else:
            others.setdefault(k["value"].strip().lower().lstrip("@"), []).append(k)

    def matches_of(ident: str, name: str | None) -> list[dict[str, Any]]:
        found = list(phones.get(phone_key(ident), [])) if phone_key(ident) else []
        found += others.get(ident.lower().lstrip("@"), [])
        if name:
            found += [k for k in names if similarity(name, k["value"], kind="person") >= 0.9]
        return [{"value": k["value"], "where": k["where"]} for k in found][:5]

    stats: dict[str, dict[str, Any]] = {}
    hours: dict[int, int] = {}
    types: dict[str, int] = {}
    dates: list[str] = []
    for r in records:
        types[r["type"]] = types.get(r["type"], 0) + 1
        when = r.get("when")
        if when:
            dates.append(when)
            if len(when) >= 13 and when[11:13].isdigit():
                hours[int(when[11:13])] = hours.get(int(when[11:13]), 0) + 1
        touched: list[dict[str, Any]] = []
        if r["type"] == "transaction":
            party = (r.get("counterparty") or r.get("account") or "(unnamed)").strip()
            entry = stats.setdefault(f"tx:{party.lower()}", {"identifier": party, "names": [], "count": 0, "paid_in": 0.0,
                                                              "paid_out": 0.0, "first": None, "last": None})  # fmt: skip
            entry["paid_in" if r["amount"] > 0 else "paid_out"] += abs(r["amount"])
            touched.append(entry)
        else:
            for ident in {str(r.get("from") or ""), str(r.get("to") or "")} - {"", "(this phone)"}:
                entry = stats.setdefault(
                    ident, {"identifier": ident, "names": [], "count": 0, "first": None, "last": None}
                )
                if r.get("name") and r["name"] not in entry["names"] and len(entry["names"]) < 3:
                    entry["names"].append(r["name"])
                touched.append(entry)
        for entry in touched:
            entry["count"] += 1
            if when:
                entry["first"] = min(entry["first"] or when, when)
                entry["last"] = max(entry["last"] or when, when)

    def name_of(entry: dict[str, Any]) -> str | None:
        # a transaction's counterparty is a name; a contact's names were collected
        return (entry["names"] or [None])[0] or (entry["identifier"] if " " in entry["identifier"] else None)

    ranked = sorted(stats.values(), key=lambda e: -e["count"])
    for entry in ranked:
        entry["in_case"] = matches_of(entry["identifier"], name_of(entry))
        for money in ("paid_in", "paid_out"):
            if money in entry:
                entry[money] = round(entry[money], 2)
    top = ranked[:50]
    in_case = [e for e in ranked if e["in_case"]]
    dates.sort()
    return {"records": len(records), "types": types, "from": dates[0] if dates else None, "to": dates[-1] if dates else None,
            "hours_utc": {str(h): hours[h] for h in sorted(hours)}, "top": top, "in_case": in_case[:100]}  # fmt: skip
