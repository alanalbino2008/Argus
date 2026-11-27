# Correctness review: a whole-repository bug sweep

A sweep of the whole codebase for bugs and logic errors, after the run of dark/deep-web features. It
combined automated analysis with a manual read of the riskiest logic.

## How it was done

- **Static analysis** with bug-focused rule sets (flake8-bugbear, pylint errors/warnings, async misuse,
  swallowed exceptions) over all 331 modules. After discarding idioms (FastAPI's `Depends` defaults,
  deliberate module globals), nothing real remained — the codebase is disciplined at the pattern level.
- **Pattern greps** for classic defects: naive datetimes, SQL built from f-strings, `except: pass`,
  `== None`. None found (the one f-string SQL uses fixed table names).
- **Frontend XSS audit**: every HTML interpolation goes through the escaping `html` template; the
  `trusted()` bypass is used only for icons and server-generated QR codes. No external data reaches it.
- **Manual review** of recent code and the security core (two-person approval, password reveal, rate
  limiting), plus a Python 3.10 portability check (3.10 is supported and tested).

## What was fixed

| Area | Problem | Fix |
|---|---|---|
| Exposure alerts | A watched-term alert was labelled as a **supplier** ("…for supplier Project Falcon") | Selector watches get their own wording: "watched term “…”" |
| Exposure alerts (privacy) | For an **email** selector, the address appeared in clear in the alert's headline, target and subjects — and alerts leave Argus (Slack, Teams, email, SIEM), breaking the rule that alerts never carry addresses | Email addresses are masked everywhere in an alert |
| Dark-web findings | A finding's identity included the index's *last-crawled* date, so every re-crawl re-announced the **same listing as new** (alert spam) | Identity is the onion / paste link; title + date only when there is no link |
| Exports (security) | Six CSV exports wrote raw text — including attacker-controlled scan results, leak-site victims and dark-web titles — so a value like `=HYPERLINK(…)` would run as a **formula** in Excel (CSV injection). Three other exports already guarded against this | One shared spreadsheet-safe writer (`argus/core/csvsafe.py`) now used by every export |
| Exposure export | Dark-web and paste findings exported **without their link** — the columns were designed for breaches | A Reference column carries the onion / paste / leak link |
| One-box investigate | If the search could not start (scan rate limit, a private-network site, an anonymous case's route), the request failed **after** creating the case: an orphaned case, and a retry made a duplicate | The case is always returned; the response says the search did not start and why |
| Ransomware hub | New-group detection flagged **every** group on the first view, and a genuinely new group was shown only to whoever loaded the page first | Per-group first-seen dates: the first run is a silent baseline; a group stays "new" for a week, for every viewer |
| Breach look-ups | A network error or an unexpected reply from Have I Been Pwned failed the person's whole breach run (HTTP 500) | Provider failures yield nothing for that identifier, like the other providers |
| Rate limiting | The in-memory limiter kept an entry for **every address it had ever seen** — unbounded memory growth on public endpoints | Stale keys are swept once the table grows |
| Selector watches | "Acme Corp" and "acme corp" were two watches, so every alert arrived **twice** | Terms are unique regardless of case and spacing |
| Software EOL | A malformed or timestamp-style end-of-life date from the external feed crashed the module (and a trailing `Z` fails on Python 3.10) | Parsed tolerantly; junk is "unknown", not a crash |
| Type checking | Three long-standing mypy errors | Annotated — mypy now reports no issues |

Every fix has a regression test.
