# 19 — Brand Impersonation: Lookalike Domains (Plain-English Guide)

> Purpose: explain how Argus finds the domains attackers register to impersonate an
> organisation. It's useful for "what is typosquatting / an IDN homograph attack?", "what
> is digital risk protection?" and "how do you avoid false positives?" questions.

## 1. The threat

Phishing rarely uses the victim's real domain, because DMARC and mail filtering make that
harder. Instead attackers register a domain that **looks** right:

| Technique | Example for `acme.com` | Why it works |
|---|---|---|
| Combosquatting | `acme-login.com`, `secure-acme.com`, `acmepay.com` | The most common pattern in real campaigns: the brand is spelled correctly |
| Homoglyph | `acrne.com` (rn → m), `acme-c0rp.com` | Letters that look alike at a glance |
| IDN homograph | `аcme.com` with a Cyrillic "а" (really `xn--cme-5cd.com`) | Pixel-identical in many fonts |
| Typo | `acm.com`, `acmme.com`, `acne.com` | Catches mistyped addresses and replies |
| Other ending | `acme.co`, `acme.net`, `acme.co.uk` | Users rarely check the TLD |
| Doppelganger | `wwwacme.com`, `mailacme.com` | A missing dot |
| Bitsquat | `ccme.com` | Hardware memory errors misdirect real traffic |

This is the core of **Digital Risk Protection**, a market served by commercial products.
Free tools such as dnstwist list which lookalikes are registered; Argus also judges them,
turns the dangerous ones into attack paths, and alerts when a new one appears.

## 2. How Argus does it

1. **Generate** candidates for the scan's main domain (`argus/intel/lookalikes.py`). They come
   most dangerous first and are capped (1,500 by default), so the cap keeps the useful ones.
2. **Check which exist**, using only DNS questions to public resolvers
   (`modules/threat_intel/lookalike_domains.py`).
3. **Judge** each registered lookalike:
   * **Can it do email?** An MX record means it can send and receive mail: ready-made phishing
     infrastructure.
   * **Is it yours?** If it shares your name servers or IP addresses, it's almost certainly a
     defensive registration. It's labelled *Yours* and never reported as a threat.
   * **Parked?** Name servers of parking and resale services suggest a speculator rather than
     an attacker (yet).
   * A **risk score** combines the technique, whether it has a credibility word like "login" or
     "pay", email capability, whether it's live, and the verdict.
4. **Attack paths**: impostors with email (or high risk) become individual findings, mapped to
   ATT&CK **T1583.001** (Acquire Infrastructure: Domains) → **T1566** (Phishing). The guidance
   covers registrar and host abuse reports, UDRP or Nominet DRS for trademark abuse, blocking at
   the mail gateway and proxy, and defensive registration. The rest go on a single **watchlist**
   path instead of flooding the list.
5. **Monitoring**: re-scans compare results, so a newly registered impostor raises a drift
   alert. That's the moment that matters, often days before the phishing emails go out.

The demo shows this: `acme-corp-login.example` (with mail) appeared since the previous scan,
and the drift report flags it as a new attack path.

## 3. Accuracy: avoiding false alarms

| Pitfall | How Argus handles it |
|---|---|
| **Wildcard TLDs**: some endings answer for every name, so everything looks "registered" | For each TLD, a random, certainly-unregistered name is checked first. Where it resolves, address answers prove nothing and only name-server delegation counts |
| **Your own defensive registrations** | Shared name servers or IPs mean *Yours*, never a finding |
| **Nonexistent domains** | NXDOMAIN (no such domain) is distinguished from "no such record" |
| **Floods of low-value results** | Individual findings only for email-capable or high-risk impostors; the rest are summarised |

## 4. Safety: never touching third parties

A lookalike is someone else's domain, possibly a criminal's. Argus:

* only asks **public DNS**: nothing is sent to the lookalike's servers or to the target;
* marks every lookalike **`out_of_scope`**. The scan engine then records it but never runs any
  module against it. This is enforced centrally in the engine, not left to each module, and a
  test runs a full scan with a spy module to prove it;
* excludes lookalikes from the target's asset counts and report inventory, because they aren't
  the target's assets.

## 5. Interview talking points

* "I added **digital risk protection**: combosquatting, homoglyphs, IDN homographs (punycode),
  TLD swaps, typos and bitsquats, generated most-dangerous-first under a bound."
* "Detection is **passive DNS only**, with **wildcard-TLD calibration** and **ownership
  detection** to keep false positives down."
* "Third-party assets are **out of scope by construction**: the engine refuses to expand them,
  and a test proves no module ever runs on one."
* "Monitoring turns it into **early warning**: a newly registered impostor is a drift alert,
  mapped to ATT&CK Resource Development → Phishing."
* "The linter flagged my Cyrillic test data as confusable characters, which is exactly the
  attack. The source now uses explicit `а`-style escapes."
