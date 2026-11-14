# 08 — Interface Design (Plain-English Guide)

> Purpose: explain the thinking behind Argus's interface — useful when asked "how did you design
> the UX?" or "how did you keep the front end secure?".

## 1. Goals

**Calm, clear, modern.** Security tools are often cramped dashboards full of numbers. Argus aims for
the opposite: one job per page, generous spacing, one accent colour, and explanations one hover away.

## 2. Structure: one page per job

| Page | Question it answers |
|---|---|
| **Overview** | *How exposed is this target, and what should I look at first?* — risk gauge, attack paths by severity, what was found, exposure flags, exports |
| **Graph** | *How does everything connect?* — interactive graph with a side panel |
| **Attack Paths** | *How would an attacker get in, and what do I fix first?* |
| **Monitoring** | *What changed since last time?* — alerts and watched targets |
| **History** | *What have we investigated before?* |
| **Settings** | Theme, API keys, tamper-evident audit log, plugins |

With nothing open, the Overview becomes a welcome page with **Start an investigation** and **Try the
demo**, so a first-time visitor (or an admissions tutor) is never staring at an empty screen.

## 3. Making a busy graph feel calm

* **Icons and colours per entity type**, and **size by importance** (more connections = bigger).
* **Labels at a constant, readable size on screen.** When zoomed out, only the important nodes are
  labelled (the target, hubs, the selection and highlighted paths); zoom in and the rest appear.
  Earlier attempts either overlapped labels or shrank them until they were unreadable — this is the
  approach professional graph tools use.
* **Connection labels only on hover**, with the hovered node's neighbourhood highlighted.
* **Layouts account for label size**, so text doesn't collide.
* During live scans the layout re-settles **in batches** rather than jumping on every discovery.
* **"Show on graph"** fades everything except an attack path, which glows red.

## 4. Connecting everything

Select any entity and the side panel shows **its facts, what it's connected to (clickable), every
attack path it's part of, and other investigations it appeared in**. Attack paths link back to the
graph; alerts link to "what changed"; the history links to compare and watch.

## 5. Smoothness and help

* Pages fade in; dialogs scale in; toasts confirm actions instead of pop-up boxes.
* A progress bar and **Stop** button appear while a scan runs.
* **Light and dark themes** (following the operating system by default), applied before the first
  paint so there's no flash.
* A four-step **first-run tour**, "?" tooltips on every metric, and **keyboard shortcuts** (`?`).
* Works on phones: navigation moves to the bottom and layouts stack.

## 6. Security by construction

Everything Argus displays comes from the *target* — DNS records, banners, profile names — so the
interface treats it all as hostile. The new front end builds HTML with an `html` template that
**escapes every value automatically**; only internally generated markup (icons) can opt out. That
makes the stored-XSS bug class from Phase 2 structurally hard to reintroduce. There are still no
inline scripts, so the strict Content-Security-Policy (`script-src 'self'`) stays in force.

## 7. Engineering notes

* Plain JavaScript **ES modules** (no build step): `api.js` (auth, errors, downloads), `state.js`
  (a tiny observable store), `graph.js`, `live.js` (WebSocket), one module per page.
* Design tokens (colours, spacing, radii) are CSS custom properties; the dark theme just redefines them.
* Verified with browser automation: a walkthrough of every page and dialog in light and dark mode,
  a live scan, and a phone viewport — with zero JavaScript errors. Visual review caught and fixed:
  cropped node icons (SVGs need explicit sizes), unstyled icons rendering huge, a cross-fade that
  briefly showed two pages, and a phone header that wrapped one word per line.
