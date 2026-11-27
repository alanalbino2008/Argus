// The command palette (⌘K / Ctrl K): type to jump to any page, investigation or case, or run an action.
// With sixteen sections, finding a page by its name is faster than finding its icon.
//
// Accessible as a combobox: the input owns a listbox, the highlighted option is announced through
// aria-activedescendant, and ↑/↓, Enter and Esc work as they do everywhere else.

import { api } from "./api.js";
import { ico } from "./components.js";
import { $, closeModal, html, on, openModal, setHTML, timeAgo, trusted } from "./dom.js";
import { rank } from "./fuzzy.js";
import { SETTINGS_GROUPS, openSection } from "./settings-index.js";

const STALE_MS = 30_000;
let ctx = null;
let loaded = { at: 0, investigations: [], cases: [] };
let shown = [];
let active = 0;

export const SHORTCUT = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || "") ? "⌘K" : "Ctrl K";

/** ``context``: { go(view), actions, titles: {view: name}, hints: {view: key}, showCase(id), canEdit() }. */
export function initPalette(context) {
  ctx = context;
  const input = $("#palette-input");
  const list = $("#palette-list");
  input.addEventListener("input", () => { active = 0; render(); });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (!shown.length) return;
      active = (active + (e.key === "ArrowDown" ? 1 : -1) + shown.length) % shown.length;
      highlight();
    } else if (e.key === "Enter") {
      e.preventDefault();
      run(shown[active]);
    }
  });
  on(list, "mousemove", "[data-index]", (_e, el) => {
    const i = Number(el.dataset.index);
    if (i !== active) { active = i; highlight(); }
  });
  on(list, "click", "[data-index]", (_e, el) => run(shown[Number(el.dataset.index)]));
  document.querySelectorAll("[data-open-palette]").forEach((b) => b.addEventListener("click", openPalette));
}

export function openPalette() {
  if (!ctx) return;
  const input = $("#palette-input");
  input.value = "";
  active = 0;
  render();
  openModal("palette-modal");
  setTimeout(() => input.focus(), 0);
  if (Date.now() - loaded.at > STALE_MS) load().then(render);
}

async function load() {
  const [investigations, cases] = await Promise.all([
    api.get("/api/investigations?limit=8").catch(() => []),
    api.get("/api/cases").catch(() => []),
  ]);
  loaded = { at: Date.now(), investigations: investigations || [], cases: (cases || []).slice(0, 30) };
}

function commands() {
  const { actions, titles, hints, go } = ctx;
  const edit = ctx.canEdit();
  const act = (label, keywords, runner, hint = "", needsEdit = false) =>
    !needsEdit || edit ? [{ kind: "Action", icon: "sparkle", label, keywords, hint, run: runner }] : [];
  const open = (id) => () => openForm(id);
  const items = [
    ...act("New investigation", "scan start target domain ip", () => actions.newInvestigation(), "N", true),
    ...act("Investigate a person", "people name username email phone one box", open("investigate-form"), "", true),
    ...act("Watch a term on the dark web", "selector dark web paste leak brand codename", open("selector-form"), "", true),
    ...act("Watch a domain for exposure", "breach stealer exposure", open("exposure-form"), "", true),
    ...act("Guided first scan", "help start tutorial", () => actions.guide(), "", true),
    ...act("Toggle light / dark theme", "theme dark light mode", () => window.argusTheme?.toggle(), "T"),
    ...act("Keyboard shortcuts", "help keys", () => openModal("shortcuts-modal"), "?"),
  ];
  for (const el of document.querySelectorAll(".nav .nav-item[data-view]")) {
    if (el.hidden) continue;
    const view = el.dataset.view;
    items.push({ kind: "Page", icon: null, svg: el.querySelector("svg")?.outerHTML, label: titles[view] || view,
                 keywords: `go page ${view} ${el.title || ""}`, hint: hints[view] || "", run: () => go(view) });
  }
  for (const [group, titles] of SETTINGS_GROUPS) {
    for (const title of titles) {
      items.push({ kind: "Setting", icon: "settings", label: title, keywords: `settings ${group}`,
                   hint: "", run: () => openSection(go, title) });
    }
  }
  for (const inv of loaded.investigations) {
    items.push({ kind: "Investigation", icon: "history", label: inv.target, keywords: `investigation ${inv.status} ${inv.name || ""}`,
                 hint: timeAgo(inv.completed_at || inv.created_at), run: () => actions.open(inv.id) });
  }
  for (const c of loaded.cases) {
    items.push({ kind: "Case", icon: "report", label: c.title, keywords: `case ${c.status || ""} ${c.purpose || ""}`,
                 hint: c.status || "", run: () => ctx.showCase(c.id) });
  }
  return items;
}

function openForm(formId) {
  const form = document.getElementById(formId);
  if (!form) return;
  form.reset();
  const error = form.querySelector(".error-text");
  if (error) error.textContent = "";
  openModal(form.closest(".modal-root").id);
}

function render() {
  const query = $("#palette-input").value;
  shown = rank(commands(), query, 40);
  if (active >= shown.length) active = 0;
  const list = $("#palette-list");
  if (!shown.length) {
    setHTML(list, html`<li class="palette-empty" role="presentation">Nothing matches “${query}”.</li>`);
    $("#palette-input").removeAttribute("aria-activedescendant");
    return;
  }
  setHTML(list, html`${shown.map((item, i) => html`<li id="palette-opt-${i}" class="palette-option" role="option" aria-selected="${i === active}" data-index="${i}">
    <span class="palette-icon" aria-hidden="true">${item.icon ? ico(item.icon) : item.svg ? trusted(item.svg) : "" /* Argus's own sidebar icon, never data */}</span>
    <span class="palette-label">${item.label}</span>
    <span class="palette-kind">${item.kind}</span>
    ${item.hint ? html`<span class="palette-hint ${item.hint.length === 1 ? "kbd" : ""}">${item.hint}</span>` : ""}
  </li>`)}`);
  highlight();
}

function highlight() {
  const list = $("#palette-list");
  list.querySelectorAll("[role=option]").forEach((el) => el.setAttribute("aria-selected", String(Number(el.dataset.index) === active)));
  const current = document.getElementById(`palette-opt-${active}`);
  if (current) {
    $("#palette-input").setAttribute("aria-activedescendant", current.id);
    current.scrollIntoView({ block: "nearest" });
  }
}

function run(item) {
  if (!item) return;
  closeModal("palette-modal");
  setTimeout(() => item.run(), 0); // after the palette has handed focus back
}
