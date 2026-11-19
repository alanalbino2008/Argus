# 48 — Account Emails and Password Resets (Plain-English Guide)

> Purpose: explain the emails Argus sends to the people who have Argus accounts, and how someone
> who forgot their password gets back in. Useful for questions like:
> * "what will customers receive, and when?"
> * "what happens if our mail server is down?"
> * "how does 'Forgot your password?' stay safe?"

## 1. The emails

**Account emails** are always sent, because they're about the account itself:

| When | Email |
|---|---|
| Someone creates an account | Welcome, with the trial's end date |
| A subscription is paid | Thank you: your plan is active, paid until… |
| A renewal payment fails | Action needed: Argus keeps working while it's retried; how to update the card |
| The payment then goes through | Your payment went through |
| The plan changes | Your plan is now… |
| The customer cancels | Your subscription is cancelled; Argus works until… |
| The subscription ends | It has ended; cases stay readable and exportable |
| Credits are bought | 500 credits added |
| A password reset is asked for | The reset link |
| The password is changed | Confirmation, and every computer was signed out |

**Reminders**: the trial ends in three days, and the trial has ended (sent for a week after it
ends). Each reminder has a one-click **unsubscribe** link, which mail apps also offer as a
button; once someone unsubscribes, no more reminders go to them.

Emails say what happened and what to do, in plain words. They contain only account details
(name, plan, dates, credits), never anything about investigations.

## 2. Reliable sending

* Every email goes into an **outbox** first. Each one has a unique label, so it's sent exactly
  once even when Stripe repeats itself or several servers run.
* If the mail server is down, Argus tries again after 1 minute, 5 minutes, 30 minutes, 2 hours
  and 12 hours, then gives up and shows the failure.
* Once an email is sent, its text is deleted. Only the subject, date and whether it arrived are
  kept, shown on the **Business** page for each account.

## 3. Forgot your password?

1. On Argus Personal's sign-in screen, **Forgot your password?** opens the account service's
   reset page. The person types their email.
2. The answer is the same whether or not that email has an account, so nobody can use it to find
   out who has one.
3. If it does, a link is emailed. It works **once**, for **one hour**, and asking again cancels
   the earlier link. At most three links an hour are sent to one account.
4. The person chooses a new password (at least 12 characters, not a common one). A weak try
   doesn't use the link up.
5. Every computer signed in to the account is **signed out**, the lockout after wrong passwords
   is cleared, and a "password changed" email is sent. If it wasn't them, they know at once.

Behind the scenes:

* the secret part of the link is after `#` in the address, so it never reaches server logs, and
  the page removes it from the address bar straight away;
* only a fingerprint (hash) of the secret is stored;
* every reset is in the audit log.

## 4. For the operator

Emails use the SMTP server already set for Argus notifications. Set the sender and a support
address, and set up SPF and DKIM for the sender's domain so emails reach inboxes. Steps are in
`docs/DEPLOYMENT.md` ("Account emails").

## 5. What a reviewer can check

* `argus/accounts/emails.py`: every email's wording, and the unsubscribe links.
* `argus/accounts/mailer.py`: queueing, sending, retries and the trial reminders.
* `argus/storage/account_mail_repo.py`: the outbox and the reset links.
* `argus/api/account_routes.py`: reset and unsubscribe endpoints; `argus/api/billing_routes.py`
  (`_tell`): which payment event sends which email.
* `argus/web/reset.html` and `argus/web/js/reset.js`: the reset page.
* `tests/test_account_emails.py`:
  * the wording, with names escaped;
  * the welcome email and each payment email, sent once each;
  * reminders and unsubscribing;
  * the whole password reset;
  * a mail server that's down;
  * no email configured.
