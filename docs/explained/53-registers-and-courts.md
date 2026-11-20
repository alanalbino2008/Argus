# 53 — More Company Registers, Insolvency Notices and Court Records (Plain-English Guide)

> Purpose: explain the company registers, insolvency notices and court records Argus now
> checks. Useful for questions like:
> * "who runs this French or Norwegian company?"
> * "has this company been wound up?"
> * "has this person or company been in a US court?"

## 1. The sources

| Source | Covers | Cost | What it adds |
|---|---|---|---|
| France (SIRENE / national register) | Every French company | Free | Details, status, address; directors and partners with roles; a person's French directorships |
| Norway (Brønnøysund) | Every Norwegian organisation | Free | Details, **bankruptcy and winding-up flags**; managing director, chair, board, auditor |
| Finland (PRH) | Every Finnish company | Free | Details, former names, line of business; bankruptcy or liquidation. No directors in Finland's open data |
| OpenCorporates | ~140 countries and US states | Own key, or credits | The company in whichever register it's in, with current officers; a person's companies |
| The Gazette (UK) | UK insolvency notices | Free | Winding-up orders, administrations, receiverships, bankruptcies, newest first |
| CourtListener (US) | US federal court dockets | Own key (free account), or credits | Cases where the company or person is a party: court, date, docket number, link |

These join the UK register (Companies House), worldwide ownership (GLEIF), US-listed
companies (SEC), the Offshore Leaks and sanctions lists that Argus already checks.

## 2. Getting it right

* **Companies** are only taken as the target when the registered name matches closely. If the
  same name is registered in several countries, Argus says so, so the investigator can pick
  the right one.
* **People found by name alone are possible matches.** Names repeat. Argus says how each was
  matched ("same name and month of birth", or "same name only: check it's the same person"),
  shows them at lower confidence, and the profile PDF repeats the warning.
* **Insolvency notices about people** come from a name search: check the notice's address and
  date of birth. A company's notices never include its directors' personal bankruptcies.
* **Costs stay predictable.** OpenCorporates and CourtListener lookups cost credits, unless
  the investigator uses their own key. So they run only on the scan's own target, never on
  every company it finds.

## 3. Privacy

* Registers publish directors' dates of birth. Argus keeps **month and year only**, as the UK
  register does.
* People a register marks as **deceased** are left out, and deceased estates notices are
  never searched.
* As always, searches run within a case with its recorded purpose, and protected people
  (children) are never profiled.

## 4. For the operator

The free sources work straight away. For OpenCorporates and CourtListener, add their keys in
the owner console (Data sources) so customers can use them with credits. Investigators can
also add their own keys in Argus Personal (Settings → Your own API keys), which makes lookups
direct and free of credits.

## 5. What a reviewer can check

* `argus/modules/corporate/europe.py`: France, Norway, Finland.
* `argus/modules/corporate/opencorporates.py`; `argus/modules/legal/gazette.py`;
  `argus/modules/legal/courts.py`.
* `argus/accounts/connectors.py`: the fixed, validated lookups for OpenCorporates and
  CourtListener, and how each key is sent.
* `tests/test_europe_registers.py`: against each register's real answers, with people's names
  and birth dates replaced by invented ones.
* `tests/test_legal_sources.py`: OpenCorporates, the Gazette (its real answer) and CourtListener.
