# UI/UX pass: navigation, orientation and accessibility

An evidence-based review of the whole interface. Every page was loaded at desktop (1440×900) and phone
(390×844) widths, screenshotted, and checked automatically for script errors, horizontal overflow,
controls without an accessible name, form fields without a label, and page headings. The fixes below
came out of that audit, and the same audit was re-run afterwards: every page now comes back clean.

## Getting around

**A grouped sidebar.** Sixteen destinations in one flat column were hard to scan, and on a 900px-tall
laptop screen the last ones (Ratings, Settings) fell off the bottom. The rail is now grouped by job —
**Investigate** (Overview, Cases, Graph, Paths, People, History), **Watch** (Monitor, Exposure,
Ransomware, Suppliers) and **Act** (Fixes, Compliance, Ratings) — and fits a 900px screen without
scrolling (it scrolls, rather than clipping, on anything shorter).

**Phones: four tabs and "More".** The bottom bar used to cram all sixteen pages into a strip that
scrolled sideways, clipping labels and hiding where you were. It now shows the four everyday pages —
Overview, Cases, Monitor, Exposure — and **More**, which opens a sheet with every page in the same three
groups. "More" lights up when you are on one of the others.

**The top bar says where you are.** It used to read "No investigation open" on every page, including
ones with nothing to do with investigations — it read like an error. It now names the page; once an
investigation is open, it shows the investigation and its scan status, as before.

**Each tab has its own title** ("Exposure · Argus", "acme-corp.example · Attack paths · Argus"), so
browser tabs, history and bookmarks are told apart. Ransomware also gained a keyboard shortcut (**A**).

## No dead ends

Graph, Attack paths and People need an investigation. With none open they offered only "New
investigation" or "Try the demo" — even when finished investigations were sitting in History. They now
also list the **three most recent investigations, one click to open**, landing you on the page you were
on.

## Accessibility and polish

- Every control has an accessible name and every field a label (the icon-only "+" on phones, nine
  Settings fields, the History filter).
- Every page has exactly one top-level heading (Graph, Attack paths and People had none).
- Buttons inside empty states showed **36px, half-transparent icons** everywhere in the app, because the
  rule meant for the empty-state illustration also matched them; they are button-sized again.
- On phones, the Security ratings grade cards were crushed five to a row (numbers cut off) and the
  portfolio table spilled off-screen; the cards now wrap and the table scrolls.
- Seed nodes in the graph were meant to be bold but used a font weight the graph library rejects; fixed.

## Guarding against a blank screen

A single bad import (a name imported twice, or a name a module does not export) stops the whole
single-page app from starting — a blank screen with no server error, and `node --check` on a `.js` file
does not notice. `tests/test_web_modules.py` now parses every browser module as an ES module, checks every
imported name is really exported, and checks the sidebar, page sections and page titles agree.
