# 39 — Phone Footprint (Plain-English Guide)

> Purpose: explain what Argus learns from a phone number, how it finds where a number or email
> address has been published, and what it deliberately doesn't do. Useful for questions like:
> * "who is behind the number on this scam text?"
> * "is this even a real number?"
> * "why doesn't Argus check which apps the number is on?"

## 1. Why this matters

Scams, harassment and fake charities often come with a phone number. The number itself says more
than it seems. And the same number has often been used before, in an advert, a forum post or a
company listing, or reported by other people on a "who called me?" site. Those earlier uses are
often what identifies the person behind it.

## 2. What the number itself says

Argus uses Google's libphonenumber, the rules Android phones use to check and format numbers. It
covers every country and works **offline**: nothing is sent anywhere, so it is safe even in
anonymous cases.

| Fact | Why it matters |
|---|---|
| **Valid or not** | Some numbers aren't real. The UK's 07700 900xxx range, for example, is reserved for TV and film. A number that isn't real suggests a typo, a fake, or someone covering their tracks |
| **Country and area** | for landlines, the area (for example "London") |
| **Line type** | mobile, landline, **VoIP (internet phone)**, toll-free, premium-rate, personal number. VoIP and personal numbers are often chosen to hide who is behind a number and where they are, so Argus flags them |
| **Original carrier** | the mobile network the number was first issued by (it may have moved since) |
| **Time zone** | useful when someone's working hours are in question |
| **How it's written** | "+44 20 7946 0000", "020 7946 0000", "02079460000": used to search for it |

## 3. Where it has been published

Argus asks a web search engine for the number in each of the ways people write it, or for an
email address exactly. Then it **checks every result**: a page is kept only if the number or
address really appears in it. Search engines often return near misses (one digit different),
and those are dropped.

The pages are sorted by what they are:

* **Nuisance-call report sites** ("who called me?" sites): other people have reported the number.
  Shown first, as *worth checking*.
* **Paste sites**: often leaks. Also *worth checking*.
* **Social media**, **classifieds and marketplaces**, and other web pages.

These pages belong to other people, so Argus records them but never scans them. The phone
playbook preserves the most telling ones as evidence, with fingerprints and a chain of custody.

**Paying for searches.** Searching needs a search key (the Brave Search API):

* **your own key** (`ARGUS_WEB_SEARCH_API_KEY`): searches go straight from your Argus, privately,
  and cost no credits;
* **Argus Connect** with an Argus account: one credit per search, refunded when nothing is found.

Numbers that aren't real are never searched, so they cost nothing.

## 4. What Argus deliberately doesn't do

Some tools claim to show which messaging apps (WhatsApp, Telegram, Signal…) a number is
registered with. They do it by misusing the apps' contact matching: they pretend the number is in
a phone's address book and see whether the app recognises it. Argus doesn't do this:

* it breaks the apps' terms;
* it is unlawful in many places;
* it can alert the person, or put them at risk.

The same information can sometimes be seen lawfully, by an investigator who already has the
number saved on a phone. That is their decision to take, not Argus's.

## 5. In the playbooks

* **Phone number**:
  1. the number's facts and its web mentions;
  2. preserves the pages that mention it, reports first;
  3. flags, as *worth checking*:
     * VoIP and personal lines;
     * numbers that aren't real;
     * reports on nuisance-call and paste sites.
* **Email footprint**: also searches for mentions of the address.

## 6. In the graph

Clicking a number shows a **"Phone number"** panel:

* validity;
* line type;
* carrier;
* area;
* time zone;
* the ways it's written.

Clicking a number or email address shows **"On the web"**: the pages confirmed to mention it, and
what kind of site each one is.

## 7. What a reviewer can check

* `argus/modules/identity/phone_recon.py`: the number's facts (`describe`).
* `argus/modules/identity/web_mentions.py`:
  * the search;
  * the check that each page really mentions the number (`phone_pattern`);
  * the kinds of page (`kind_of`).
* `argus/accounts/connectors.py`: web search as a fixed, paid lookup.
* `argus/intel/playbooks.py`: the phone playbook and its findings.
* `tests/test_phone.py`:
  * a London landline;
  * mobile, VoIP and TV-reserved numbers;
  * the facts module contacting nobody;
  * the number matched however it is written;
  * near misses dropped;
  * exact email search;
  * invented numbers costing nothing;
  * the paid lookup;
  * Argus Connect charging and refunds;
  * the playbook's findings.
