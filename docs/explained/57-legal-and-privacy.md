# 57 — Legal Documents and Privacy (Plain-English Guide)

> Purpose: explain the legal documents Argus gives you, how customers accept them, and how
> customers' privacy rights work. Useful for questions like:
> * "do I have terms and a privacy policy?"
> * "a customer asked for their data / to be deleted: what do I do?"
>
> **Not legal advice.** The documents are a careful starting point written for how Argus
> actually works, but they must be reviewed by a lawyer who knows your business and where you
> sell before you rely on them.

## 1. The documents

Six pages, served by your account service at `https://<your server>/legal/...`:

| Page | What it covers |
|---|---|
| `/legal/terms` | Terms of Service: what Argus is, who may use it, plans, payment, credits, lawful use, responsibility, changes |
| `/legal/privacy` | Privacy Policy: what you hold about customers, why, for how long, and their rights |
| `/legal/acceptable-use` | Acceptable Use Policy: what Argus is for, and what it must never be used for (stalking, profiling children, getting into accounts...) |
| `/legal/refunds` | Refunds and Cancellation |
| `/legal/dpa` | Data Processing Agreement, for business customers |
| `/legal/subprocessors` | The providers you use and what each receives |

They say what Argus really does. Cases stay on the investigator's computer. The account
service holds only account, computer, payment and credit records. Lookups and AI requests
pass through without being kept.

## 2. Setting them up (owner console → Legal)

1. Fill in your **business details**: legal name, company number, address, contact email,
   privacy contact, governing law, data protection regulator, hosting provider and email
   provider (as "Name | Location", for example `Hetzner | Germany (EU)`).
2. Read the pages (links at the top of the Legal tab). Until they're published they show
   "Draft".
3. **Have a lawyer review them.** Then tick *A lawyer has reviewed these documents*.
4. **Publish**: set *Published version* to today's date (e.g. `2026-11-20`).

Health shows a warning until all of this is done.

## 3. How customers accept them

* **New accounts**: once published, creating an account needs the box *I agree to the Terms
  of Service and Acceptable Use Policy, and I've read the Privacy Policy* to be ticked. The
  version and time are recorded.
* **When you change them**: set a new *Published version* date. Each customer's Argus asks
  them, at its next check-in (within a day), to read and accept the new version. Until they
  do, they can still open and export everything, and backups keep working, but new work waits.
* Accounts you create for a Business team accept at their first sign-in, the same way.

## 4. Customers' data rights

In Argus Personal, Settings → *Your Argus subscription* → **Your data and the legal side**:

* **Download my account data**: everything the account service holds about them, as a file
  (account, terms accepted, computers, credits and their history, payments, emails sent,
  team, and the security log about them).
* **Delete my account** (password and typing DELETE). This:
  * deletes the customer at Stripe, which also ends any subscription straight away;
  * erases their name, email, password, computers, emails, reset links and invitations;
  * keeps payment and credit records under an anonymous account number, because tax law
    requires them (6 years in the UK);
  * leaves their cases on their computer, untouched.

A team owner must remove their members first: those accounts belong to the members.

If a customer emails instead, you can point them to these buttons.

## 5. Keeping only what's needed

* Records of emails sent, expired password-reset links and expired invitations are removed
  after **6 months**. Computers signed out more than **a year** ago are forgotten. This runs
  daily, on its own.
* **Case reviews for investigators**: cases nobody has touched for 12 months are marked
  *Review* in the Cases list, with a reminder that data protection law expects personal
  information to be kept only while it's needed (`ARGUS_CASE_REVIEW_MONTHS`; 0 turns it off).

## 6. What already protected people before this

* Every case records its purpose, and the investigator confirms it's legitimate.
* Argus refuses to profile children.
* Everything is in a tamper-evident audit log.
* Cases can be encrypted with the case vault, and backups are encrypted.
