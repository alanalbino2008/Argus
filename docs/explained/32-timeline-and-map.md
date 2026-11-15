# 32 — Timeline & Map (Plain-English Guide)

> Purpose: explain how Argus shows a whole case in time and on a map, and why its map works
> differently from an ordinary web map. Useful for questions like:
> * "how do you build a timeline from scattered evidence?"
> * "why would a web map be a privacy risk for an investigator?"
> * "what is geocoding?"

## 1. Why this matters

Investigations are told in time and place: who did what, when, and where. Mistakes are found the
same way: a photo "from yesterday" whose camera says last year; a company "based in London" whose
director's photos are all taken abroad. Laying everything out on one timeline and one map makes
gaps, clusters and contradictions visible at a glance.

## 2. The timeline

Each case has a **Timeline** tab. It brings together everything with a date, without the
investigator re-typing anything:

| Kind | Where it comes from |
|---|---|
| Event | added by the investigator |
| Account change | the account watcher (phase 30) |
| Capture / evidence added | when each page was preserved or file added |
| Scan | linked investigations |
| Photo taken | read from each photo's own metadata (phase 31) |

Details that matter:

* **Photo dates are labelled honestly.** If a camera didn't record its time zone, the time is
  marked *approximate* (~). It is never silently shifted.
* **No duplicates.** If the investigator already added "Photo taken" for a file, Argus doesn't add
  it again.
* **A true time scale.** The activity chart above the list counts entries per day, month or year,
  and includes empty periods, so a two-year silence looks like one. Clicking a bar focuses on that
  period; the pills filter by kind.
* **Export.** CSV for spreadsheets. Any cell starting with `=`, `+`, `-` or `@` is neutralised, so
  a hostile value collected from the web cannot run as a formula when the file is opened (a known
  attack called CSV injection). A test checks this.

## 3. The map

The **Map** tab shows:

* **places with coordinates**, typed or pasted in the forms people use:
  * `51.5007, -0.1246`;
  * `51°30'02.5"N 0°07'28.6"W`;
  * `40.7128° N, 74.0060° W`;
  * an OpenStreetMap or Google Maps link;
* **photos with GPS**, read from the evidence itself;
* **addresses looked up** on request (below).

Clicking a place shows its details; **Show all** fits everything on screen. **Google Earth (KML)**
exports the places for Google Earth or any GIS tool. A test checks that a hostile place name such
as `<b>Shed</b>` stays as text in the file rather than becoming markup.

`0, 0` is ignored. That point in the ocean off Africa ("null island") is what broken data usually
says, never a real place in a case.

## 4. Why the map images come from Argus

An ordinary web map makes your **browser** download small square map images ("tiles") of the
area you're looking at. So the map provider learns, from your own internet connection, exactly
which streets you're studying, and when. For an investigator looking at a subject's home or
workplace, that is a leak.

Argus's map works differently:

* the **server** fetches the tiles and serves them from Argus's own address, so the browser only
  ever talks to Argus;
* tiles are checked (images only, size-limited) and cached, so the provider sees far fewer
  requests (and a test checks the second request is served from the cache);
* the map is drawn by Argus's own code: no mapping library and no scripts from other websites;
* the map provider and the credit shown are set by the operator (`ARGUS_MAP_TILE_URL`), so a
  newsroom can use its own map server and keep even that in-house.

## 5. Looking up an address (geocoding)

Turning "10 Downing Street, London" into map coordinates is called **geocoding**. It means sending
the address to a geocoding service (OpenStreetMap's Nominatim by default), so Argus only does it
when the investigator presses **Find on map**, and:

* it goes through the case's route (Tor or a VPN); an **anonymous** case refuses to look up an
  address directly;
* at most one look-up a second, as the public Nominatim service asks;
* the result is stored on the entity, marked "looked up" rather than "given", and the look-up is
  in the audit log;
* operators can point it at their own Nominatim, or switch it off.

## 6. What a reviewer can check

* `argus/intel/places.py`: reading coordinates, building the timeline and places, KML and the
  formula-safe CSV.
* `argus/api/map_routes.py`: the endpoints, photo-metadata cache, geocoding through the route,
  and the tile proxy and cache.
* `argus/web/js/views/casemap.js`: the timeline chart and the dependency-free map.
* `tests/test_case_map.py`:
  * every coordinate format;
  * timeline order, kinds and de-duplication;
  * CSV injection;
  * KML escaping;
  * geocoding, including that anonymous cases refuse to go direct;
  * the tile cache and its refusals;
  * viewer permissions and restricted cases.
