# Watch a term on the dark web — selector watches

Until now, exposure monitoring could watch two things: a **domain you own** (verified in Have I Been
Pwned) and your **supplier register**. That is the right model for "has my organisation been breached?"
— but investigators and brand-protection teams need to watch things that are not domains they control:
a product codename before launch, an executive's personal address, a forum username, a card BIN, a
campaign name. **Selector watches** add exactly that.

## What a selector watch does

On the **Exposure** page, **Watch a term** opens a box where you type one selector and a basis. From
then on, every check asks the dark-web and leak sources about that term and raises findings — scored,
triaged, alerted and exported through the same machinery as domain exposure:

| Source | What it answers | Needs |
|---|---|---|
| **Ransomware leak feeds** | the term named as a victim on a ransomware group's leak site | nothing (works out of the box) |
| **Dark-web index** | onion-site titles/snippets mentioning the term | a provider (`ARGUS_DARKWEB_INDEX_URL`) |
| **Paste / leak forums** | paste-site and leak-forum posts mentioning the term | a provider (`ARGUS_PASTE_MONITOR_URL`) |

Findings appear under two new headings — **Dark-web index mentions** (`darkweb_mention`) and
**Paste & leak-forum posts** (`paste_leak`) — alongside the existing breach and ransomware findings.

## The line Argus does not cross

Argus **never opens an onion service**. The dark-web index source reads only a **clearnet index** of
onion titles and snippets (a self-hosted Ahmia/Elasticsearch, or a licensed index you point Argus at).
So a finding tells you *where* a term appears and preserves the onion address as a reference — it never
downloads the criminal content itself, and no Tor route is required. The paste source is the same: it
reads an index of paste/forum posts, not the forums directly.

Both providers are **off until an admin configures them** (exactly like the custom breach provider), and
both go out through the same SSRF guard as every other Argus fetcher: private, loopback and link-local
hosts are refused, including on redirects. Results are capped (`ARGUS_DARKWEB_LOOKUPS_MAX`, default 100),
and only metadata is kept — the title, the snippet, the date, the reference — never leaked files.

## How findings are scored

Dark-web and paste findings are scored **conservatively**, because a mention is not proof:

- a bare mention, not recent → **low**;
- leak-looking (words like *dump*, *combolist*, *database*, *credentials*, *fullz*) **or** recent → **medium**;
- leak-looking **and** recent → **high**.

Only high/critical findings auto-open remediation tasks, so the noise of a passing mention does not
create work. Each finding is flagged *"looks like a leak: verify"* where the signal words appear, so an
analyst always confirms before acting.

## Where it fits

A selector watch is stored as an exposure watch with scope `selector`, so everything you already know
works on it: the **findings list** and its severity ordering, **triage** (resolved / accepted / reopen),
**alerts** to Slack/Teams/email/SIEM (which never carry personal data), the **CSV export**, and
**remediation** tracking. `POST /api/exposure/selectors` creates one; it is audited like every other
watch, and only an admin can delete it.

This is the first of a sequence strengthening dark/deep-web coverage. Next come a first-class paste/leak
source view, stealer-log intelligence by identifier, and a ransomware-ecosystem intelligence hub.
