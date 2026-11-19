# 47 — The Business Dashboard (Plain-English Guide)

> Purpose: explain the **Business** page that the operator of the Argus account service uses to
> run the business. Useful for questions like:
> * "how many paying customers do we have, and what do they bring in each month?"
> * "who needs help, or a nudge?"
> * "which paid sources do people actually use?"

## 1. Who sees it

Only platform admins, and only on the account service (the central server that holds customer
accounts). Investigators using Argus Personal never see it. It shows accounts and credits only:
the account service never has customers' cases.

## 2. What it shows

| Section | What it tells you |
|---|---|
| **Paying customers** | How many pay, on which plan. A customer whose renewal is being retried still counts |
| **Monthly recurring revenue** | Paying subscriptions × their plan's price in Stripe. A yearly price counts as a twelfth a month |
| **On free trial** | Trials running now, and what share of finished trials became paying |
| **Payment due** | Customers whose card Stripe is retrying |
| **New accounts per week** | The last twelve weeks; hover a bar for how many of those people now pay. Also as a table |
| **Needs attention** | Payments failing; trials ending in the next three days; trials that ended without paying (worth a friendly email); accounts locked after wrong passwords; paying customers with no credits left |
| **Credits used** | By source (Companies House, web search, the AI analyst) over 30 days, 90 days or 12 months, and who uses the most. Lookups that failed or found nothing were refunded, so they don't count |
| **Credit packs sold** | How many of each pack, and roughly what they took at today's prices |

Stripe's own dashboard remains the record of money actually paid, refunded and paid out. This
page is for steering the business.

## 3. Looking after an account

The **Accounts** list can be searched (email, name, account id or Stripe customer id), filtered
by status and plan, and downloaded as a spreadsheet (CSV). Click an account to:

* see its plan, status, paid-until date, Stripe customer, credits and credit history;
* **change the plan, status or paid-until date** (to correct something, or give a free
  extension). Payments normally keep these up to date on their own;
* **add or remove credits**, with a reason that is kept in the credit history;
* **sign a computer out** to free a place on the account. The person keeps their cases.

Every change is recorded in the audit log, and so is every spreadsheet download.

## 4. Safeguards

* Platform admins only; other users and keys are refused.
* The spreadsheet is personal data (customers' emails): its download is audited, and any cell
  that a spreadsheet program could run as a formula is neutralised.
* Password hashes never leave the server.

## 5. What a reviewer can check

* `argus/accounts/business.py`: how every figure is worked out.
* `argus/api/business_routes.py`: the summary, account list and CSV endpoints.
* `argus/web/js/views/business.js`: the page.
* `tests/test_business.py`:
  * every figure on sample accounts, including yearly prices, refunds netted off, the period,
    pack takings and each kind of "needs attention";
  * the endpoints, search and filters, the CSV and formula neutralising;
  * access for platform admins only, and only on an account service.
