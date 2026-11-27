# Command palette, WCAG 2.1 AA, and a navigable Settings page

Three improvements to how Argus is used day to day.

## Search and jump: the command palette (Ctrl K / ⌘K)

Argus has sixteen sections, and finding a page by its icon gets slow. Press **Ctrl K** (⌘K on a Mac) —
or click **Search…** in the top bar, or the magnifier on a phone — and type:

- a **page** ("rans" → Ransomware), with its single-key shortcut shown beside it;
- a recent **investigation** by its target ("acme" → acme-corp.example), opened in one keystroke;
- a **case** by its title;
- a **setting** ("api keys", "retention") — Settings opens scrolled to that section;
- an **action**: New investigation, Investigate a person, Watch a term on the dark web, Watch a domain
  for exposure, Guided first scan, Toggle theme, Keyboard shortcuts. Actions that change data are only
  offered to analysts and administrators.

Matching is forgiving: every word you type must appear, a match at the start ranks highest, and an
abbreviation still finds a page by its letters in order ("rnsm" → Ransomware). That last rule looks only
at the visible name, never at hidden keywords — otherwise a few letters scattered across a long keyword
list would put unrelated actions on top (a real bug the browser tests caught before release). ↑/↓ move,
Enter opens, Esc closes; it works while you are typing in a field, as in other apps. It is an accessible
combobox: the highlighted result is announced to screen readers.

## Accessible to WCAG 2.1 AA — and kept that way

**axe-core** (the industry-standard accessibility engine) now checks every page against WCAG 2.1 A and
AA: each page in light and dark at desktop size, each page on a phone, and with the command palette and
the phone's "More" sheet open — 47 page states. The first run found four problems, all fixed:

| Problem | Where | Fix |
|---|---|---|
| **Text contrast** too low (584 elements) | Muted text everywhere (3.85:1), and severity colours (red, orange, amber, green, grey) used as text or under white text (2.1–3.95:1) | Muted text darkened (light) / lightened (dark) to 4.8:1. Severity colours keep their vivid shade for fills and dots, and gain a **text** shade and a **solid** shade (for white text) — each pair computed to pass, in both themes |
| Filter buttons marked up as tabs | Open/Resolved, 30/90/180 days, To review/Theirs… | Marked up as what they are: a group of toggle buttons, each announcing whether it is pressed |
| A progress bar without a name | The getting-started checklist | Named |
| A scrollable panel keyboard users could not reach | The graph's side panel | Focusable |

After the fixes, **all 47 states pass with zero violations**. The check runs in CI as its own job
("Accessibility (axe, WCAG 2.1 AA)"), so a regression — text that loses its contrast, a control without a
name, broken ARIA — fails the build instead of shipping. It was proven to work by reintroducing the old
grey: the job failed and named the problem.

## Settings you can find your way around

Settings is seventeen sections — about six screens. It now has a **sticky index** beside it ("On this
page"), grouped by purpose — **You**, **Workspace**, **Data & evidence**, **Access & integrations** — that
highlights the section you are reading as you scroll. Clicking a section scrolls to it and moves keyboard
focus to its heading (outlined, so you can see where you landed). **Find a setting** filters the page as
you type. On a phone the index becomes rows of chips above the page. Every section is also in the command
palette.

The Overview page was reviewed too and left as it is: a dense, well-structured dashboard that already
reads top-down from the rating and the fastest route to a better grade.
