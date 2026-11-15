# 33 — Argus Accounts & Argus Personal (Plain-English Guide)

> Purpose: explain how Argus runs on one investigator's own computer while still being unlocked
> by an account (so it can be sold as a subscription), and how that is done without ever seeing
> the investigator's cases. Useful for questions like:
> * "how do desktop apps check a subscription?"
> * "why can't someone just edit the licence file?"
> * "what happens when a subscription ends, or the laptop is offline?"

## 1. Why this matters

Journalists and independent investigators often can't, or shouldn't, put their cases on someone
else's server. Their sources, notes and evidence belong on their own computer. A business still
needs to know who is a paying customer. Argus does both:

* **Argus Personal** runs on the investigator's laptop and keeps the cases there;
* it is **unlocked by an Argus account**, checked by an account service the company runs.

## 2. The two parts

| | Argus Personal (the laptop) | The account service (central) |
|---|---|---|
| Holds | cases, evidence, scans | accounts, plans, which computers are signed in |
| Started with | `argus --personal` | `ARGUS_ACCOUNT_SERVICE_ENABLED=true` |
| Reachable from | only the laptop itself (127.0.0.1) | the internet |

**What the account service learns:**
* the email and password at sign-in;
* a random id and a name for each computer;
* when each computer renews.

**What it never learns:** anything about cases, evidence or searches. That separation is what
lets a journalist trust a subscription product.

## 3. Licences: a signed permission slip

When someone signs in, the account service gives that computer a **licence**: a small piece of
text saying who it is for, the plan, the subscription's status and the dates below. The service
**signs** it with a private key (Ed25519, a modern digital-signature scheme). Argus Personal has
only the matching *public* key, which can check signatures but cannot make them.

So:

* **It can't be forged or edited.** Changing anything (a later expiry date, a bigger plan) breaks
  the signature. A test changes the date to 2099 and checks it is refused.
* **It can't be copied.** Each licence names the computer it was issued to, and the service that
  issued it. A licence copied from another computer is refused.
* **It works offline.** Checking a signature needs no internet, so the app doesn't phone home on
  every click.

The dates:

| Date | Meaning |
|---|---|
| Paid until | the end of the paid period or free trial |
| Renew after | the app quietly asks for a fresh licence (daily); this picks up renewals, upgrades and cancellations |
| Works offline until | how long the app keeps working without reaching the service (14 days by default), for travel and poor connections |

## 4. Never held hostage

Some subscription software locks people out of their own work when a payment fails. For an
investigator that could mean losing access to evidence before a deadline, or before a court date.

When a subscription isn't current, Argus Personal becomes **read-only**:

* everything can still be **opened, searched, verified and exported** (including the evidence
  bundle);
* only **new work** (scans, captures, uploads, watching accounts) waits, with a plain message
  saying why and how to fix it.

This applies when the trial ended, the subscription was cancelled, the laptop was offline too
long, or the laptop was signed out from elsewhere. A banner shows it, with **Check again** for
after renewing. A "payment due" status (a card being retried) keeps full access meanwhile.

The rule applies to every way into the app, API keys included, so it can't be worked around.

## 5. Accounts done properly

* **Passwords** are stored with **scrypt**, a deliberately slow, memory-hungry hash, each with its
  own random salt. A stolen database doesn't reveal them.
* **Guessing is stopped**: five wrong passwords lock the account for 15 minutes, and requests are
  rate-limited per address.
* **No account fishing**: a wrong password and an unknown email get the same answer, taking the
  same time, so nobody can test which emails have accounts.
* **Weak passwords are refused**: too short, the email address itself, or a well-known password.
* **Computers per plan**: a trial covers one computer, Personal two, Professional three. Signing
  out on one frees its place.
* **Sign-in is protected against other websites**: another site can't sign the browser in or out
  (the request must come from Argus's own page).

## 6. Ready for payments

Each account has a **plan**, a **status** (trialing, active, past_due, cancelled, suspended) and
a **paid-until** date. When payments are added (Stripe, Paddle…), the payment provider tells
Argus about each payment or cancellation through a webhook, and the handler makes one call to
update those three fields. The laptops pick the change up at their next renewal, within a day. No
other part of Argus needs to change.

## 7. What a reviewer can check

* `argus/accounts/licence.py`: signing, verification and what a licence allows.
* `argus/accounts/passwords.py`: scrypt and password rules.
* `argus/api/account_routes.py`: the account service.
* `argus/storage/subscriber_repo.py`: accounts, lock-out and per-plan computer limits.
* `argus/accounts/personal.py` and `argus/api/personal_routes.py`: Argus Personal's sign-in,
  renewal and the read-only gate.
* `tests/test_accounts.py`: covers forgery, editing, copying, every access state, the service end
  to end, lock-out, administration rights, and Argus Personal against a stand-in account service
  (sign-in, read-only and back, offline, signed out elsewhere, untrusted keys, expiry,
  sign-out). It also checks that no case data ever reaches the account service.
