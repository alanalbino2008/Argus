# 35 — Companies, Sanctions & Leaks, and Argus Credits (Plain-English Guide)

> Purpose: explain how Argus investigates companies and the people behind them, checks them
> against sanctions lists and leaked offshore records, and how premium data sources are paid for
> with Argus credits. Useful for questions like:
> * "who really owns this company?"
> * "how do you avoid accusing the wrong John Smith?"
> * "how can a product resell access to a paid data source safely?"

## 1. Why this matters

Money laundering, sanctions evasion, fraud and corruption hide behind companies: shells,
nominee directors, chains of owners across countries. Following a company to its directors, its
owners and their *other* companies is how journalists and investigators uncover these networks.
Checking each name against sanctions lists and leaked offshore records shows where to look hardest.

## 2. The sources

| Source | What it gives | Cost |
|---|---|---|
| **UK Companies House** | directors with roles and dates; **people with significant control** (who owns or controls the company, and how); each director's other companies | credits, or your own free key |
| **GLEIF** (global LEI register) | legal name, addresses, jurisdiction, **direct and ultimate parent companies** | free |
| **SEC EDGAR** | US-listed companies: filing ID, ticker, incorporation, industry, former names, recent filings | free |
| **Sanctions lists** | the US (OFAC SDN), UK and UN lists, with aliases, dates of birth, nationalities | free |
| **ICIJ Offshore Leaks** | people and companies named in the Panama, Paradise and Pandora Papers and other leaks | free (credited under the Open Database Licence) |

Each source is read from its official public service, and each can be switched off or pointed
at a saved copy.

## 3. Matching names without accusing the wrong person

Names are messy:
* "SMITH, John Paul", "John P. Smith" and "Jóhn Smith" are probably the same name;
* "Acme Holdings Limited" and "ACME HOLDINGS LTD." are the same company.

Argus:
* removes accents and punctuation, puts "Surname, Given" back in reading order, and for companies
  ignores legal forms (Ltd, LLC, PJSC, GmbH…);
* compares **word by word, in any order**, allowing small spelling differences in each word;
* for people, insists that **every word** of the shorter name matches: "John Smith" is never
  "Johnson Smithers", and a single word ("Smith") never identifies anyone;
* shows a **score** with every match.

Most importantly, **a similar name is not the same person.** When Argus knows more about someone,
it compares those details with the listing. The register gives a director's birth month and year
and their nationality. If they contradict the listing, Argus says so plainly: *"Probably a
different person: born 1980, but the listed person was born 1975."* A test checks exactly this.

When the register has no exact match for a company, Argus doesn't guess: it lists the closest
names, with their scores, for the investigator to choose from.

## 4. Following the network

Starting from a company, Argus finds its directors and owners. For each current director (up to a
set number), it lists every other company they've been appointed to. Nominee directors show up as
one person on dozens of boards, and dissolved companies show how a network changed over time.
GLEIF adds the corporate chain upwards: the parent, and the ultimate parent.

Starting from a person's name, Argus searches the register of directors. Several people can
share a name, so their companies are linked as *possible* matches, labelled with the birth month
that tells them apart.

## 5. Argus credits: premium sources without keys

Some sources need an account and a key. Asking every customer to sign up with each provider is a
poor experience, and it earns the product nothing. So Argus has **Argus Connect**:

* the **Argus account service** (run by the company selling Argus) holds the provider keys;
* the customer's Argus asks the account service for a lookup, and pays in **Argus credits**;
* each plan includes a **monthly allowance** (free trial 50, Personal 500, Professional 2,000)
  that renews on the 1st; customers can **buy more**, and bought credits never expire.

Done safely:

* **A fixed menu, never a proxy.** The account service runs only named lookups, such as
  "company", "officers", "persons with significant control" and "appointments". Each detail is
  checked against a strict pattern and placed into a fixed address on the provider's own site.
  Nobody can use it to call anywhere else with the operator's keys; the tests try path tricks such
  as `../../admin`.
* **Atomic charging.** Credits are taken in a single locked step, so two lookups at the same
  moment can't overspend.
* **Fair charging.** Invalid requests are refused before any credit is taken. Failures and "not
  found" answers are refunded.
* **A ledger.** Every change is recorded (allowance, use, refund, purchase), naming the provider
  and lookup but never the search itself.
* **Only for current subscribers.** The licence must be genuine, the computer still signed in,
  and the subscription current.

**Privacy.** A brokered lookup tells the account service what was looked up. Investigators who
can't reveal even that set their own key for the source; their lookups then go directly, through
their own route, and cost no credits. The subscription card in Settings says this plainly.

**Payments later.** When a payment provider is added, buying credits is one call, the same one
an administrator uses today.

## 6. What a reviewer can check

* `argus/intel/names.py`: name normalisation and matching.
* `argus/intel/watchlists.py`: the US, UK and UN list readers and screening.
* `argus/modules/corporate/companies_house.py`: companies, officers, owners, appointments.
* `argus/modules/corporate/registers.py`: GLEIF, SEC, Offshore Leaks, sanctions screening, and
  the "probably a different person" check.
* `argus/accounts/connectors.py`: the fixed menu and parameter validation.
* `argus/storage/subscriber_repo.py` (`CreditRepository`): allowance, purchases, atomic charges,
  refunds and the ledger.
* `argus/api/connect_routes.py` and `argus/accounts/connect_client.py`: Argus Connect.
* `tests/test_companies.py`:
  * name-matching cases;
  * all three sanctions list formats (including the older UK layout);
  * one broken list not stopping the others;
  * Companies House end to end;
  * GLEIF, SEC and Offshore Leaks;
  * the proxy refusals;
  * credits: charging, refunds, running out, buying more, the new month and the ledger;
  * only current subscribers spending.
