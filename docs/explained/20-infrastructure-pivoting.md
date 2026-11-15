# 20 — Infrastructure Pivoting (Plain-English Guide)

> Purpose: explain how Argus finds the rest of an organisation's infrastructure, and an
> attacker's, from a single domain. It's useful for "what is pivoting in threat
> intelligence?", "how do you attribute infrastructure?" and "how do you keep OSINT in scope?"
> questions.

## 1. The idea

Organisations, and attackers, reuse things. The same Google Analytics account goes on the
main site and the careers site. The same organisation name appears on every OV certificate.
The company runs its own name servers. Each shared thing is a **pivot**: follow it backwards and
you find related domains that subdomain searches never reveal, such as forgotten marketing
sites, acquisitions and regional domains. That forgotten estate is a common way in.

## 2. The pivots and how much each one proves

| Pivot | How Argus finds it (all passive) | Weight |
|---|---|---|
| Analytics, ad and tag IDs (Google Analytics, GA4, Tag Manager, AdSense, Meta pixel) | Read from the homepage **as archived by the Internet Archive** (the target isn't contacted), then reverse-looked-up | 0.90 |
| The target's own name servers (`ns1.acme.com`) serving another domain | Shared-DNS lookup | 0.80 |
| Certificate organisation (`O=`) | The domain's OV/EV certificate from Certificate Transparency (crt.sh), then every certificate issued to that organisation | 0.75 |
| Other dedicated name servers | As above, ignoring big DNS providers | 0.55 |
| Same IP address | Reverse-IP, counted only if few domains share it | 0.40–0.45 |

**Combining evidence**: each domain's confidence is a **noisy-OR**, `1 − Π(1 − weight)`, with
each kind of evidence counted once. Two independent signals beat one. Three co-hosting
coincidences are still only one kind of evidence. A shared IP **never attributes a domain on
its own**, because its weight is below the 0.5 threshold.

**What doesn't count**: generic infrastructure that millions of unrelated customers share.
That means big DNS providers (Cloudflare, Route 53, GoDaddy…), CDN and hosting companies'
certificate organisations, and IP addresses with more than 15 domains (shared hosting).
Confidence ≥ 80% is "likely the same organisation"; 50–80% is "possibly related".

## 3. Discovery is not authorisation

A domain that probably belongs to the target is still **not in the scope** the person was
authorised to assess. Argus records related domains with their evidence and confidence, marks
them **out of scope**, and never scans them. The **Investigate** button starts the guided scan
for that domain, which asks for authorisation like any other.

## 4. Mapping attacker infrastructure

Pivoting works on attackers too. For impostor domains found in Phase 19, Argus looks up what
else is hosted on the same server and keeps the domains that also imitate the brand. That
comparison undoes look-alike substitutions, so `acrne-sso.com` reads as "acme". Several lures on
one server is the signature of an **organised campaign**, which becomes a single attack path
(T1583.001/T1583.003 → T1566). Its first piece of advice: report the whole cluster in one abuse
report, because taking down one domain leaves the rest.

This needed one careful exception in the scan engine. Third parties' assets are normally never
processed. A module may examine them only if it is declared **third-party-safe**: it never
contacts the asset and only asks public databases about it. The infrastructure-pivot module is
the only one, it acts only on domains already judged to be impostors, and a test checks that
ordinary modules still never see a third party's domain.

## 5. The graph

The shared things become nodes: the analytics ID, the certificate organisation, the name
server and the IP. The graph then shows *why* two domains are linked, e.g. `acme-corp.example →
G-ACME2026X1 ← acme-corp-careers.example`, the way analysts draw it in Maltego.

## 6. Limits

The reverse-lookup sources are free and rate-limited. An optional HackerTarget API key
(`ARGUS_HACKERTARGET_API_KEY`) raises the limit. Pivots only find what those databases have
seen, and archived homepages may be old. Attribution is probabilistic: check before acting.

## 7. Interview talking points

* "I implemented **infrastructure pivoting** on analytics IDs, certificate organisations, name
  servers and co-hosting, all passive (even the homepage comes from the Internet Archive)."
* "Attribution is **probabilistic**: weighted evidence combined with a noisy-OR, generic
  infrastructure excluded, and a shared IP never enough on its own."
* "**Discovery isn't authorisation**: related domains are recorded out of scope, and
  investigating one goes through the authorisation flow."
* "The same technique maps **attacker campaigns**: impostors sharing a server become one
  finding, with look-alike normalisation so `acrne-sso.com` is recognised."
* "The engine gained a principled, **narrow exception** for third-party-safe modules, tested
  both ways."
