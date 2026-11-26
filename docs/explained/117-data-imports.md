# 117. Importing call records, statements, contact lists and phone extractions

The case's **Data** tab imports data obtained lawfully for the case, and compares it with what the case
already holds.

| Kind | Files | What is read |
| --- | --- | --- |
| Call detail records | CSV, XLSX | caller, called number, time, duration, call or text, cell |
| Bank or payment statements | CSV, XLSX | date, amount (or paid in / paid out), counterparty or description, account, reference |
| Contact lists | CSV, XLSX (also XRY contact exports) | names with phone numbers and email addresses |
| Cellebrite UFDR | `.ufdr` | contacts, calls, chats and messages (with the app), user accounts |

Column names vary between operators, banks and tools; the usual ones are recognised (for example
`A Party`, `Calling Number`, `From`, `Start Time`, `Duration`, `Cell ID`, `Paid in`, `Paid out`,
`Description`). *Recognise it* picks the kind from the columns. Dates are read day-first where
ambiguous (as UK and EU records write them). Times without a time zone are treated as UTC. XRY data
is read through its CSV or XLSX exports.

## Kept as evidence

The imported file is case evidence like any upload: fingerprinted, timestamped if a timestamp authority
is set, with a chain of custody. The records read from it are kept beside it (`records.json`), covered
by the same digest.

## What it shows

* how many records, of which kinds, and over what period;
* the hours of the day they fall in;
* **Already in the case**: every number, address, account or name in the records that the case already
  holds (in its entities, or known or confirmed about a person on the People tab), with how often it
  appears and when first and last. Phone numbers are matched on their last nine digits, addresses and
  usernames exactly, and names closely;
* **Most frequent**: the numbers, addresses or counterparties that appear most, with totals paid in and
  out for statements.

## Safeguards

These files hold other people's communications and money.

* A case must record its legal authorisation (warrant, court order or ticket; see 114) before anything
  can be imported. The Data tab lets you record it.
* Every import (`case.import`) and every reading of one (`case.import_view`) is audited, with the
  authorisation.
* Files are read on the Argus server and never sent anywhere.

API: `POST /api/cases/{case}/imports` (multipart `file`, optional `kind` and `note`);
`GET /api/cases/{case}/imports`; `GET /api/cases/{case}/imports/{evidence id}`.
