# 18 — Guided First Scan (Plain-English Guide)

> Purpose: explain how Argus helps newcomers scan responsibly. It's useful for "how do you
> build security tools that are safe to put in people's hands?" and "what are the legal
> limits of OSINT?" questions.

## 1. Why a guided scan

The first few minutes decide whether someone understands a tool, or misuses it. A blank
"enter a target" box invites two mistakes: scanning something you have no right to (a big
company "just to see", your university), and not understanding what you are looking at
afterwards. **Guided first scan** turns that first run into a short lesson:

| Step | What happens | What it teaches |
|---|---|---|
| **1. Target** | Examples of good first targets (your own domain, a bug bounty scope, a CTF) and of targets that need permission | Authorisation comes first |
| **2. Check** | A server-side pre-flight check: target type, whether it is allowed at all, warnings, and a recent scan of the same target if there is one | Legal and ethical context |
| **3. How** | Passive (public sources only) vs Standard (adds light, ordinary requests to the target), and how far to follow leads | Passive vs active reconnaissance |
| **4. Run** | Live counts and the sources being consulted, in plain English, then "what an attacker could learn" with the top attack path and its first fix | How findings become risk |

It ends with next steps: open the attack paths, keep watching the target, or create the client
report. A **Getting started** checklist on the home page tracks progress across the whole
workflow (demo, first scan, attack paths, monitoring, alert destinations, reports, schedules),
computed from what the workspace has really done.

## 2. Guidance, not just blocking

Argus already **blocks** what must never be scanned from a server: private, loopback and
cloud-metadata addresses (SSRF protection). The pre-flight check adds **judgement** for
targets that are reachable but sensitive (`argus/security/scope.py`):

| Target | Level | Why |
|---|---|---|
| Government, military, police, NHS (`.gov`, `.gov.uk`, `.police.uk`, `.nhs.uk`…) | danger | Needs written authorisation, e.g. an official disclosure programme |
| Large organisations (Google, Microsoft, GitHub, banks…) | danger | Only within a bug bounty programme's scope, following its rules |
| Universities and colleges (`.ac.uk`, `.edu`) | warning | Their IT security team must agree, even if you study there |
| Email, username, phone, person | warning | The results are personal data and need a lawful basis (UK GDPR) |
| IP address | info | Shared hosting puts many organisations on one address |
| Placeholder domains (`example.com`, `.test`) | info | Nothing real to find; the demo is better |
| Standard mode | info | Which checks will contact the target |

It warns rather than blocks, because authorised testers legitimately assess all of these.
For "danger" targets the wizard asks for a second confirmation ("I have **written**
authorisation… and will follow its rules") and clears the default purpose, so the person must
describe their real engagement.

**Accountability**: when any scan starts (guided or not), the server recomputes the warnings
itself and records their codes in the audit entry (`scope_warnings`). So the log always shows
what the person was told, and the browser can't hide it.

The legal background: in the UK, unauthorised access to computer material is an offence under
the **Computer Misuse Act 1990**, and investigating an individual means processing personal
data under **UK GDPR**. Passive OSINT is lower-risk than active testing, but the professional
habit is the same: get permission first and stay in scope.

## 3. A bug the guide found

Testing the wizard with a placeholder domain produced an attack path: *"argus-guide.example
can be spoofed in phishing emails"*. The domain doesn't exist, so it has no DMARC record,
but there's nothing to spoof either: receiving mail servers reject mail from nonexistent
domains. The DNS collector now records whether the domain exists (an authoritative NXDOMAIN
with no answers at all), and the spoofing rule ignores domains that don't. Regression tests
cover both.

## 4. Interview talking points

* "I designed the first-run experience around **responsible use**: the tool teaches
  authorisation, passive vs active reconnaissance and data protection before it scans."
* "Hard safety limits are **enforced server-side** (SSRF blocking). Judgement calls are
  **warnings with acknowledgement**, and the server records what was shown in the audit log."
* "The pre-flight endpoint makes the guidance **truthful**: it lists exactly which sources will
  run and which contact the target, from the same catalogue the engine uses."
* "Building the onboarding found a **false positive** in the attack-path engine, which I fixed
  at the source."
