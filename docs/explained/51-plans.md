# 51 — The Four Plans (Plain-English Guide)

> Purpose: explain what each Argus plan includes, how that is enforced, and how "bring your own
> keys" works. Useful for questions like:
> * "which plan should I choose?"
> * "why can't I start a watch on my plan?"
> * "how do I use my own Companies House or Claude key?"

## 1. The plans

| | Bring your own keys | Personal | Professional | Business |
|---|---|---|---|---|
| Investigations, cases, evidence, link chart, exports | yes | yes | yes | yes |
| Monthly credits (premium sources, AI analyst) | none: use your own keys, or buy packs | 500 | 2,000 | 1,000 per seat, shared |
| Computers | 1 | 2 | 3 | 2 per person |
| Monitoring and watches | | | yes | yes |
| Branded reports (your logo) | | | yes | yes |
| Playbooks | | | yes | yes |
| Team tools: add people, create their accounts, shared credits | | | | yes |
| Price | lowest | | | per seat, plus an optional one-off set-up fee |

The free trial includes everything in Professional, so people can see what it offers.

## 2. How the plan is enforced

The plan's features are written into the **signed licence** that unlocks Argus Personal. Argus
checks them on the computer itself, so it works offline and can't be edited.

* Trying something your plan doesn't include (starting a watch, a playbook, adding a logo) shows
  a clear message saying which plans include it.
* Anything that already exists stays readable: nothing is hidden or deleted.
* Scheduled scans and watches pause until the plan includes them again.

## 3. Bring your own keys

Settings → **Your own API keys** takes keys for UK Companies House, web search (Brave) and
Claude (the AI analyst):

* with a key, lookups go **straight from your computer** to the source and use no Argus credits;
* keys are **encrypted on your computer**, with a key only that computer has, and are never sent
  to the Argus account service;
* only the last four characters are ever shown back, to tell keys apart.

The Bring-your-own-keys plan is priced for this, but any plan can add its own keys.

## 4. Business

* **Seats and set-up.** The owner chooses the number of seats when subscribing. An optional
  one-off set-up fee is added to the first payment only. Seats can be changed under Manage
  billing.
* **Adding people.** The owner types a name and email:
  * if the person is new to Argus, an account is created for them and they're emailed a link to
    **choose their own password** (it works once, for a week). The owner never knows their
    password;
  * if they already have an Argus account, they get an **invitation** instead, so nobody's
    existing account can be taken over.
* **Lost laptop?** The owner can sign a member out of every computer; they sign in again with
  their password.
* The owner sees members, last sign-in and credits used, never anyone's cases (see guide 50).

## 5. What a reviewer can check

* `argus/accounts/licence.py` (`PLANS`): each plan's credits, computers and features.
* `argus/accounts/features.py`: which actions need which feature, and the messages.
* `argus/api/personal_routes.py` (`licence_gate`): enforcement on the computer.
* `argus/accounts/own_keys.py`: your own keys, encrypted; `argus/accounts/connect_client.py`:
  own keys first, then credits.
* `argus/api/team_routes.py` (`team_add`, `team_sign_out_member`): Business accounts.
* `tests/test_plans.py`:
  * what each plan includes;
  * Personal refused the Professional features, while what exists stays readable and
    background runs pause;
  * Professional allowed;
  * own keys saved encrypted, never sent or shown, reloaded at start;
  * the Business set-up fee;
  * owner-created accounts, existing accounts invited instead, and signing a member out.
