# 116. One timeline, activity patterns, and people on the map

## One timeline

The case's **Timeline** now includes the confirmed online life of every person on the People tab
(accounts created, archived and renamed, channel posts, documents, notices, court cases), labelled
*Person (People tab)*, alongside the case's events, evidence, scans, photo dates and the facts found
by its scans. Entries keep the precision their source gave (a year, a month or a day). They are in
the timeline export (CSV) and the case report too.

## When they are active, and the gaps

A person's **Timeline** section shows:

* **activity by hour** (UTC): when they post in their public Telegram channels and create accounts,
  with the busiest hours highlighted. With a known time zone, local time is UTC plus that offset. A
  handful of samples says little, and the chart says how many it rests on;
* **gaps**: stretches of a year or more between dated findings with nothing found, which can mean a
  break, another identity, or simply sources that do not reach back.

## People on the map

Towns linked to a person become places on the case's **Map**:

* the known town;
* a town learned from a confirmed account;
* the location a confirmed account gives.

They are listed as places to look up, which is done with the map's own geocoding, on request and
through the case's route. This stays at town level: Argus does not work out street addresses or homes,
and does not track anyone live. Photos added as evidence still appear where their own GPS data puts
them.

The big networks do not show the location tags on posts to visitors who are not signed in, so those
are not collected.
