# 52 — The Owner Console (Plain-English Guide)

> Purpose: explain the owner console, the server owner's own control panel at `/admin`, and
> what keeps everyone else out. Useful for questions like:
> * "how do I change my Stripe keys or email server without the terminal?"
> * "could someone else get into it?"
> * "what happens if I lose my phone?"

## 1. Getting in

**Once, to set it up:**

1. Whoever deploys Argus sets your email as the owner (`ARGUS_OWNER_EMAIL`). Only that address
   can ever be the owner.
2. Open `/admin`, enter that email and the server's administrator key. The key proves you
   control the server.
3. Scan the QR code with an authenticator app on your phone, choose a password, and save the
   ten recovery codes somewhere safe, such as a password manager.

Set-up then closes for good: nobody can set up a second owner.

**Every time after that:** your email and password, then the 6-digit code from your phone.

## 2. Why nobody else can get in

* **Two things are needed:** your password **and** your phone. A stolen password alone opens
  nothing.
* **Guessing is stopped.** Five wrong attempts lock the console for 15 minutes and email you.
  Codes change every 30 seconds and work only once.
* **You're told.** Every sign-in, lock-out, password change and authenticator change is
  emailed to you, with where it came from.
* **Sessions are short.** At most 8 hours, and 30 minutes without use. Each one is listed under
  Security, where you can sign it out.
* **Changing anything asks again.** Saving a setting needs a code from the last 10 minutes.
* **Nothing else opens it.** API keys, other users and single sign-on can't reach the console.
  Once you exist, the server never creates a new administrator key by itself. The "owner only"
  switch (Security) can also stop keys and other admins from administering the server at all.
* **Stored safely.** Your password and recovery codes are stored only as one-way hashes.
  Sessions are stored only as fingerprints. The authenticator secret and every API key you enter
  are encrypted, never shown back and never written to the log.

**Lost your phone?** Sign in with a recovery code instead of the 6-digit code, then go to
Security → Move to a new phone.

## 3. What you can do there

| Section | What it does |
|---|---|
| Overview | Health checks with how to fix anything wrong; your business at a glance; recent activity |
| Payments | Stripe keys, plan prices and credit packs; Test connection; the webhook address to give Stripe |
| Email | Mail server, sender, support address; Send test email |
| Accounts & plans | Open sign-ups, trial length, offline days; each plan's monthly credits and computers |
| Data sources | Your Companies House, Brave Search and Claude keys, which pay for customers' lookups |
| Security | You, your sessions, password, recovery codes, a new phone; who can administer; API keys |
| Activity | Everything done on the server, newest first |

Changes apply **straight away**, with no restart. A value set here wins over the deployment's
configuration. "Use deployment value" goes back to it.

**Open Argus** opens the main app, where you're its administrator (the Business page, accounts
and so on) without any API key.

## 4. What a reviewer can check

* `argus/accounts/owner.py`, `argus/api/owner_routes.py`: set-up, sign-in, lock-out, alerts,
  sessions and the owner's own security.
* `argus/security/totp.py`: authenticator codes (checked against RFC 6238's test value) and the
  QR code.
* `argus/core/runtime_config.py`: which settings can change, their checks, encryption and live
  application; `argus/api/owner_console_routes.py`: health, settings, plans, keys and activity.
* `argus/api/deps.py`: the owner's session in the main app, and the owner-only switch.
* `argus/web/admin.html`, `argus/web/js/admin.js`: the console.
* `tests/test_owner_console.py`:
  * authenticator codes;
  * set-up refused without the right email and key, and only once;
  * sign-in needs both factors, and codes and recovery codes work once;
  * lock-out and the alert emails;
  * settings checked, encrypted, never shown or logged, and applied live;
  * plan allowances;
  * fresh codes for changes;
  * health checks;
  * the main app and the owner-only switch;
  * no administrator key recreated;
  * password, recovery codes and a new phone;
  * not available in Argus Personal.
