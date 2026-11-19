# 50 — Team Plans (Plain-English Guide)

> Purpose: explain how a newsroom, agency or firm buys Argus for several investigators. Useful
> for questions like:
> * "who pays, and how do people join?"
> * "can the team owner see what members are investigating?" (No.)
> * "what happens when someone leaves, or the team stops paying?"

## 1. How it works

* **One person pays.** The *owner* subscribes to the Team plan in Argus Personal (Settings →
  Your Argus subscription), choosing how many **seats**: one for themselves and one per
  colleague. Seats can be added or removed later under Manage billing.
* **Colleagues are invited by email.** Each gets a link that works once, for a week. They join
  with their existing Argus account or create one, and sign in to Argus Personal on their own
  computers (two each).
* **Credits are shared.** Each seat adds 1,000 credits a month to one shared pool, and credit
  packs the owner buys go into it too.

## 2. What the owner sees, and doesn't

| The owner sees | The owner never sees |
|---|---|
| Who is on the team, open invitations | Anyone's cases, notes, evidence or searches |
| When each person last signed in | What anyone looked up |
| How many credits each person used this month | |

Cases never leave each person's own computer. The account service never has them, so nobody
there can show them to anyone.

## 3. Members follow the team

* While someone is on a team, Argus uses the **team's** subscription: its plan, its paid-until
  date and its credits.
* If the team's payment fails, everyone keeps working while Stripe retries. If the team's
  subscription ends or is put on hold, every member's Argus becomes read-only: their cases stay
  readable and exportable, and new work waits.
* **Leaving or being removed**: the person goes back to their own account as it was, and needs
  their own plan to start new work. Their cases stay on their computer.

## 4. Sensible limits

* Invitations can't exceed the free seats, and nobody can join a full team.
* Someone who already pays for their own plan is asked to cancel it first, so they don't pay
  twice.
* Someone can only be on one team at a time.
* Members don't buy plans or credits: the owner looks after those.
* Members don't get "your trial is ending" emails.

## 5. For the operator

Create a recurring **per-seat** price for the Team plan in Stripe, set it as
`ARGUS_STRIPE_PRICE_TEAM`, and allow quantity changes in Stripe's customer portal. See
`docs/DEPLOYMENT.md`. Teams show on the Business page with their seats; revenue counts every
seat.

## 6. What a reviewer can check

* `argus/accounts/teams.py`: how a member takes on the team's plan, and whose credits they spend.
* `argus/api/team_routes.py`: status, invitations, joining, removing and leaving.
* `argus/storage/subscriber_repo.py` (`TeamRepository`): seats, invitations stored only as hashes.
* `argus/api/connect_routes.py`: lookups charged to the team's pool, recording who used them.
* `argus/web/join.html`, `argus/web/js/join.js`: the join page; `argus/web/js/views/settings.js`:
  the team section.
* `tests/test_teams.py`:
  * seats and invitations;
  * a new member joining and running a paid lookup from the shared pool;
  * the owner seeing usage per member;
  * members unable to manage the team or buy plans;
  * the team ending, with everyone going read-only;
  * existing accounts joining, refused when they already pay;
  * removing and leaving;
  * more seats mid-month;
  * the team buttons in Argus Personal.
