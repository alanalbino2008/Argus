# Ransomware intelligence hub

Ransomware crews run "leak sites" where they name the organisations they have hit and threaten to
publish stolen data. Watching that ecosystem tells a defender who is being hit, by whom, in which
sectors and countries — and when a **new crew** appears, which usually means a fresh operation or a
rebrand of an old one. Argus already matched your domains and suppliers against these posts; the
**Ransomware** page turns the whole landscape into an at-a-glance hub.

## What the page shows

A new **Ransomware** item in the sidebar opens the hub (read-only):

- **Headline stats** — leak-site posts in the last 7 and 30 days, how many groups are currently active,
  and how many groups the feed tracks in total.
- **Activity** — a 14-day bar chart of posts per day, so a surge is obvious.
- **Newly appeared groups** — group names Argus had not seen before this check, called out at the top. A
  new name is a strong signal: verify whether it is a new operation or a rebrand.
- **Group / sector / country breakdowns** — the busiest of each, as chips you click to filter.
- **Recent posts** — the latest victims, newest first, filterable by group, sector, country or a free-text
  search over the victim and site.

Click any group (in the chips, the breakdowns, a new-group callout, or a row) to filter the whole view
to that crew; a search box filters by victim name. **Clear filters** resets it.

## Where the data comes from, and what Argus does not do

The hub reads the **same public research feed** as the exposure monitor (ransomware.live's API, which
indexes the posts groups publish). **Argus never visits a leak site** — those are Tor hidden services run
by criminals — and only metadata is handled: the victim name, the group, the date, the sector and the
country. No stolen files are fetched or stored. If the feed is turned off
(`ARGUS_RANSOMWARE_FEED_URL` empty), the page says so.

## New-group detection

Argus keeps a small snapshot of the group names it has seen before (in its key–value state store). On
each fetch, any group in the recent window that is **not** in that snapshot is reported as new, and the
snapshot is updated — so a group is flagged once, when it first appears, and not again. This is
ecosystem-wide, independent of your watches.

## How it relates to watches

The hub is for **situational awareness**; it does not replace watches. To be *alerted* when a specific
organisation is named — yours, a supplier, or any term — use a domain watch, the supplier sweep, or a
**selector watch** (Watch a term) on the Exposure page: those raise alerts to Slack, Teams, email and
your SIEM. The hub is where you browse the landscape and spot new crews; the watches are where you get
told about the victims you care about.

This completes the four-part strengthening of Argus's dark/deep-web coverage: selector watches, the
paste/leak-forum sources, infostealer intelligence, and now the ransomware hub.
