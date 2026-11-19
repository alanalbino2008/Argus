# 49 — Refunds and Disputes (Plain-English Guide)

> Purpose: explain what Argus does when you refund a customer, or when a customer's bank
> disputes a payment (a *chargeback*). Useful for questions like:
> * "if I refund a credit pack, do they keep the credits?"
> * "what happens to someone who disputes a payment?"
> * "what if they'd already used the credits?"

## 1. Refunds

You refund in Stripe's dashboard as usual. Stripe tells Argus, and:

| Refunded payment | What Argus does |
|---|---|
| **Credit pack** | Takes back the credits it bought. Refund half the price and half the credits go |
| **Subscription** | Records it and emails the customer. Their access doesn't change: to end it, cancel the subscription in Stripe as well |

Credits already used can't be taken back, so the balance never goes below zero. How many
couldn't be taken back is recorded, so you can see it. The customer gets a short email saying
how much was refunded and how many credits were removed.

## 2. Disputes (chargebacks)

When a customer's bank disputes a payment, Stripe takes the money back while the dispute is
looked at. Argus then:

1. **puts the account on hold**. Argus becomes read-only on their computer: their cases stay
   there, readable and exportable, but new work waits, and signing in says to contact support;
2. **holds back the credits** that payment bought;
3. **emails the customer kindly**, since many disputes are mistakes ("I didn't recognise the
   charge"), inviting them to get in touch;
4. **flags it** on the Business page under "Needs attention".

You answer the dispute in Stripe's dashboard (Payments → Disputes) with your evidence. Then:

* **you win** (or the customer withdraws it): the hold is lifted automatically, the account goes
  back to how it was, the credits come back, and the customer is told;
* **you lose**: the hold stays, and the Business page asks you to decide. Lift it (set the
  status back on the account) if you're happy to carry on with that customer.

While the hold is on, routine subscription updates from Stripe don't accidentally lift it.

## 3. What a reviewer can check

* `argus/api/billing_routes.py`: `_refunded`, `_dispute_opened`, `_dispute_closed`, and the
  hold kept during subscription updates.
* `argus/storage/subscriber_repo.py`: payments (`record_payment`) and taking credits back
  (`take_back`).
* `argus/accounts/emails.py`: the three new emails.
* `argus/web/js/views/business.js`: disputes in "Needs attention", refunds and disputes for the
  period, and each account's payments.
* `tests/test_refunds_disputes.py`:
  * partial and full refunds of credit packs, the same refund reported twice, credits already
    spent;
  * a subscription refund;
  * a dispute won: hold, credits held, hold kept through subscription updates, everything
    restored;
  * a dispute lost: the hold stays until the operator lifts it;
  * a dispute about a payment Argus never saw.
