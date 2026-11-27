// Settings is seventeen sections long (about six screens). This adds, after it renders, a sticky
// "On this page" index grouped by what the sections are for, a "Find a setting" filter, and scroll-spy
// that highlights the section you are reading. The section cards themselves are untouched.

import { html, setHTML } from "./dom.js";

export const SETTINGS_GROUPS = [
  ["You", ["Appearance", "Your access", "Your sessions", "Argus on this computer", "Your Argus subscription", "Your own API keys"]],
  ["Workspace", ["Workspace", "Workspace usage", "People with access", "Investigator safety", "Two-person approval", "Report branding"]],
  ["Data & evidence", ["Backups", "Case vault", "Data retention", "Integrity", "Verify a report"]],
  ["Access & integrations", ["API & integrations", "API keys", "Provisioning (SCIM)", "Network access", "Audit log", "Plugins"]],
];

/** "Workspace: Red Team" is the workspace section whatever the workspace is called. */
export const canonical = (title) => (title.startsWith("Workspace:") ? "Workspace" : title);
export const sectionId = (title) => `settings-${canonical(title).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "")}`;

let query = "";
let observer = null;

export function buildSettingsIndex(root) {
  const page = root.querySelector(".page");
  if (!page) return;
  observer?.disconnect();
  const head = page.querySelector(".page-head");
  const cards = [...page.querySelectorAll(".card")].filter((c) => c.querySelector(":scope > .card-head h2"));
  const sections = cards.map((card) => {
    const h2 = card.querySelector(":scope > .card-head h2");
    const title = h2.textContent.trim();
    card.id = sectionId(title);
    h2.tabIndex = -1; // a jump moves focus here, so screen readers follow
    return { card, h2, title };
  });

  // [index | content], the page wide enough for both
  const layout = document.createElement("div");
  layout.className = "settings-layout";
  const nav = document.createElement("nav");
  nav.className = "settings-index";
  nav.setAttribute("aria-label", "Settings sections");
  const content = document.createElement("div");
  content.className = "settings-content";
  for (const child of [...page.children]) if (child !== head) content.append(child);
  layout.append(nav, content);
  page.append(layout);
  page.style.maxWidth = "1320px";

  const known = new Set(SETTINGS_GROUPS.flatMap(([, titles]) => titles));
  const groups = [...SETTINGS_GROUPS.map(([label, titles]) => [label, sections.filter((s) => titles.includes(canonical(s.title)))]),
    ["More", sections.filter((s) => !known.has(canonical(s.title)))]].filter(([, items]) => items.length);
  setHTML(nav, html`<label class="sr-only" for="settings-filter">Find a setting</label>
    <input id="settings-filter" class="input sm" type="search" placeholder="Find a setting…" value="${query}" autocomplete="off">
    ${groups.map(([label, items]) => html`<div class="settings-index-group"><div class="settings-index-label">${label}</div>
      ${items.map((s) => html`<a href="#${s.card.id}" data-section="${s.card.id}">${canonical(s.title)}</a>`)}</div>`)}
    <p class="muted small settings-none" hidden>No setting matches.</p>`);

  nav.addEventListener("click", (e) => {
    const link = e.target.closest("a[data-section]");
    if (!link) return;
    e.preventDefault(); // keep the hash route on #/settings
    const target = document.getElementById(link.dataset.section);
    jump(target);
  });
  const filter = nav.querySelector("#settings-filter");
  filter.addEventListener("input", () => { query = filter.value; applyFilter(nav, sections); });
  applyFilter(nav, sections);

  // scroll-spy: the section nearest the top of the view is the current one
  observer = new IntersectionObserver((entries) => {
    const visible = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
    if (!visible.length) return;
    nav.querySelectorAll("a[data-section]").forEach((a) => {
      const here = a.dataset.section === visible[0].target.id;
      a.classList.toggle("active", here);
      if (here) a.setAttribute("aria-current", "location"); else a.removeAttribute("aria-current");
    });
  }, { root: root.closest(".view"), rootMargin: "0px 0px -70% 0px" });
  sections.forEach((s) => observer.observe(s.card));
}

function applyFilter(nav, sections) {
  const q = query.trim().toLowerCase();
  let shown = 0;
  for (const s of sections) {
    const match = !q || s.card.textContent.toLowerCase().includes(q);
    s.card.hidden = !match;
    nav.querySelector(`a[data-section="${s.card.id}"]`)?.toggleAttribute("hidden", !match);
    shown += match;
  }
  nav.querySelectorAll(".settings-index-group").forEach((g) => { g.hidden = !g.querySelector("a:not([hidden])"); });
  nav.querySelector(".settings-none").hidden = shown > 0;
}

/** Scroll a section into view and move focus to its heading. */
export function jump(card) {
  if (!card) return;
  const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  card.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
  card.querySelector(":scope > .card-head h2")?.focus({ preventScroll: true });
}

/** From elsewhere (the command palette): open Settings at a section once it has rendered. */
export function openSection(go, title) {
  query = "";
  go("settings");
  const id = sectionId(title);
  const started = Date.now();
  const tryJump = () => {
    const card = document.getElementById(id);
    if (card && card.closest(".settings-content")) return jump(card);
    if (Date.now() - started < 4000) setTimeout(tryJump, 100);
  };
  tryJump();
}
