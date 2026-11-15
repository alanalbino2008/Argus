# 21 — Security Rating (Plain-English Guide and Methodology)

> Purpose: explain how Argus turns a scan into an A–F grade, and why each rule exists. It's
> useful for "how would you design a security score?", "how do you avoid misleading
> metrics?" and "what is vendor risk management?" questions. This page is also the published
> methodology (version `2026.11-1`).

## 1. Why a rating

Security teams, buyers, insurers and supply-chain managers want one comparable answer: *how
exposed is this organisation?* Commercial ratings (SecurityScorecard, BitSight) answer it, and
are often criticised as **black boxes**: a grade changes and nobody can say why. Argus's rating is
built to be explained. Every point lost is a finding you can open, and every finding has its fix.

## 2. The eight factors

| Factor | Weight | What lowers it |
|---|---|---|
| Vulnerabilities & patching | 20% | Exploitable public services (CISA KEV, EPSS, CVSS), unsupported software |
| Leaks & data exposure | 18% | Breached credentials, secrets in public code, exposed files (`.git`, `.env`), public cloud storage |
| Network exposure | 15% | Risky services reachable from the internet (RDP, databases, SMB…); a very large exposed surface |
| Web & TLS | 12% | Weak browser security headers, expired or expiring certificates, untrusted certificates, information leaks, no `security.txt` |
| Email security | 10% | Spoofable domain (no or weak DMARC), missing or permissive SPF |
| Brand & reputation | 10% | Impostor domains, impersonation campaigns, malicious reputation |
| DNS health | 8% | Dangling records that allow subdomain takeover |
| Social engineering | 7% | Publicly identifiable staff and the information attackers need to phish them |

Strengths are credited too. DMARC `p=reject`, SPF `-all`, strong security headers and a
`security.txt` are listed as strengths and cost nothing.

## 3. Scoring

1. **Issues.** Most are the curated **attack paths** (each rule maps to one factor). A few are
   direct **measurements** (DMARC and SPF policy, header grade, `security.txt`, certificate
   expiry). Measurements never double-count what an attack path already covers.
2. **Points.** Critical 35, high 20, medium 10, low 4.
3. **Diminishing returns.** Within a factor, the most severe issue costs full points, then 60%,
   40%, 30% and 20% for the rest. The second open database matters, but less than the first. A
   factor never goes below 0.
4. **Overall score.** The weighted average of the **assessed** factors.
5. **Caps.** Critical findings cap the score. One or more critical issues → at most **69 (D)**.
   Three or more → at most **59 (F)**. An actively exploited vulnerability isn't offset by good
   email hygiene. Both the capped and uncapped scores are shown.
6. **Grade bands.** A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F < 60.

## 4. Coverage honesty

A factor with no data isn't 100. It's **not assessed**: for example, Web & TLS in a passive-only
scan never contacts the website. Unassessed factors are left out of the average, and the
rating's **confidence** is the share of total weight that was assessed. Below 60% the grade is
marked **provisional**. Third parties' assets (impostor domains, related but unauthorised
domains) never affect the rating.

## 5. What to fix first

For every issue, Argus reports:

* **Impact**: what it costs the score before caps, its real share of the weighted average;
* **Gain**: what the actual (capped) score would gain if only this were fixed. This is often 0
  while other critical issues still hold the cap, which is why both are shown.

The **fastest route to the next grade** takes critical issues first (they're what caps the
grade), then the highest impact, until the next grade band is reached. In the demo, fixing the
exploited VPN vulnerability, the leaked AWS key and the exposed `.git` directory moves Acme from
**F to D**.

## 6. Trends and benchmarks

Each completed scan's rating is stored, so a target shows its **trend**. The demo drops from D
(69) to F (59) as new exposures appear.

**Benchmarks are honest by construction.** An organisation is compared only with the **other
organisations assessed in the same workspace** (a supplier portfolio, a client base), and only
when there are at least three. Argus never shows invented "industry averages". The **Ratings**
page is the portfolio view used for vendor-risk management: every organisation, weakest first,
with grade, trend, weakest area and benchmark.

## 7. Versioning

The methodology has a version. Ratings computed under an older methodology are recomputed, not
compared with new ones, so a trend never mixes two scoring systems.

## 8. Interview talking points

* "I designed a **transparent rating**: published weights, every point traceable to a finding
  and its fix, so it can be explained to a board or challenged by a supplier."
* "It's **honest about coverage**: unassessed factors reduce confidence instead of counting as
  perfect."
* "**Caps** stop critical issues being averaged away. I separate *impact* from *gain* because a
  fix can matter without moving a capped score yet."
* "Benchmarks are **portfolio-relative**, never invented averages, and need at least three peers."
* "The methodology is **versioned**, so trends never compare two different scoring systems."
