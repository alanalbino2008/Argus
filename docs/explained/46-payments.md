# 46 — Payments (Plain-English Guide)

> Purpose: explain how customers pay for Argus, what happens when a payment succeeds, fails or is
> cancelled, and what protects the money and the customers. Useful for questions like:
> * "how does someone subscribe or buy credits?"
> * "what happens if a card is declined?"
> * "does Argus ever see card numbers?"

## 1. How a customer pays

In Argus Personal, **Settings → Your Argus subscription** shows:

* **Subscribe** buttons for each plan, with the price as set in Stripe;
* **Buy credits** buttons for each credit pack;
* **Manage billing**, once something has been bought.

Clicking a button opens **Stripe's own payment page**. When the customer has paid, Stripe sends
them back to Argus, which checks the subscription straight away and unlocks it. Nobody types card
details into Argus, and Argus never receives them.

**Manage billing** opens Stripe's customer page, where the customer can update their card,
download invoices, change plan or cancel.

## 2. What each event does

Stripe tells the account service about every payment event (a *webhook*):

| What happened | What changes |
|---|---|
| A subscription is paid | The plan is switched on, status *active*, paid until the end of the period |
| It renews each month | The paid-until date moves on |
| A renewal payment fails | Status *payment due*. **Argus keeps working** for at least 7 days while Stripe retries, and Settings asks the customer to update their card |
| The customer cancels | Argus keeps working **until the end of the period already paid for**, then turns read-only (cases stay readable and exportable) |
| A credit pack is paid | The credits are added; purchased credits never expire |
| A plan is upgraded mid-month | The bigger monthly credit allowance is available straight away |

Argus Personal picks the change up within seconds after a payment (it checks straight away), and
otherwise at its daily renewal.

## 3. Safeguards

* **Card details never touch Argus.** Payment happens on Stripe's pages.
* **Every notification from Stripe is checked.** It must carry a signature made with a secret
  only Stripe and the account service know, over the exact message. Anything unsigned, altered,
  or more than five minutes old is refused, so nobody can fake a payment.
* **Each event counts once.** Stripe sometimes sends the same event twice; credits are never
  added twice, and if applying an event fails it is retried by Stripe and applied then.
* **Out-of-order events can't undo a payment.** For subscription changes, Argus asks Stripe for
  the subscription as it is now rather than trusting an older message.
* **An old subscription ending doesn't cancel a new one.**
* **A test-mode service refuses live events**, so trials can't touch real money.
* **The return address is restricted** to the customer's own computer (or the operator's page),
  so a payment link can't be used to send someone to another site.
* **Everything is in the audit log:** checkouts, subscription changes and credit purchases.
* **Suspended accounts can't buy.** Lapsed accounts can, so they can renew.

## 4. For the operator

Prices are set in Stripe; Argus only needs the price ids. Setup steps are in
`docs/DEPLOYMENT.md` ("Payments with Stripe"). Try it first with Stripe's test keys and test cards.

## 5. What a reviewer can check

* `argus/accounts/stripe_billing.py`: talking to Stripe, checking webhook signatures, reading
  subscriptions, and how Stripe's statuses map to Argus's.
* `argus/api/billing_routes.py`: catalogue, checkout, billing page, the webhook and what each
  event changes.
* `argus/storage/subscriber_repo.py`: applying each event once (`claim_event`), and the
  allowance on upgrade.
* `argus/api/personal_routes.py` and `argus/web/js/views/settings.js`: the buttons in Argus
  Personal; `argus/web/js/main.js`: coming back from Stripe.
* `tests/test_billing.py`:
  * signatures (wrong secret, altered, too old, rotated secrets);
  * subscribing, renewing, upgrading, a failed payment, cancelling, subscribing again;
  * an old subscription ending while a new one is active;
  * buying credits, a payment still pending, the same event twice;
  * payments not configured; paying from Argus Personal, including when lapsed.
