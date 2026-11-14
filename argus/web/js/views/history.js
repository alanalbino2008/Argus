// History: every investigation, searchable, with open / compare / watch / delete.

import { api, enc } from "../api.js";
import { empty, ico, statusBadge } from "../components.js";
import { $, confirmDialog, html, on, setHTML, timeAgo, toast } from "../dom.js";
import { on as onState, state } from "../state.js";

let root;
let actions;
let rows = null;
let query = "";
let timer = null;

export function initHistory(el, appActions) {
  root = el;
  actions = appActions;
  onState("history-changed", () => { rows = null; if (root.classList.contains("active")) refresh(); });
  root.addEventListener("input", (e) => {
    if (e.target.id !== "history-search") return;
    query = e.target.value;
    clearTimeout(timer);
    timer = setTimeout(refresh, 250);
  });
  on(root, "click", "[data-act]", async (e, btn) => {
    e.stopPropagation();
    const { act, id } = btn.dataset;
    if (act === "compare") return actions.openDiff(id);
    if (act === "watch") return actions.newInvestigation({ target: btn.dataset.target, type: btn.dataset.type, watch: true });
    if (act === "new") return actions.newInvestigation();
    if (act === "demo") return actions.loadDemo();
    if (act === "delete") {
      const ok = await confirmDialog({ title: "Delete this investigation?", message: "All of its findings are permanently removed. This can't be undone.", confirm: "Delete", danger: true });
      if (!ok) return;
      try {
        await api.del(`/api/investigation/${enc(id)}`);
        toast("Investigation deleted");
        if (state.investigation?.id === id) actions.close();
        refresh();
      } catch (err) {
        toast(err.message, "error");
      }
    }
  });
  on(root, "click", "tr[data-id]", (_e, tr) => actions.open(tr.dataset.id));
}

export async function refresh() {
  try {
    rows = await api.get(`/api/investigations?limit=200${query ? `&target=${enc(query)}` : ""}`);
  } catch {
    rows = rows || [];
  }
  render();
}

function render() {
  const focused = document.activeElement?.id === "history-search";
  setHTML(root, html`<div class="page">
    <div class="page-head">
      <div><h1>History</h1><p>Every investigation is saved. Open one to explore it, compare it with an earlier scan, or keep watching it.</p></div>
      <button class="btn primary" data-act="new">${ico("plus")}New investigation</button>
    </div>
    <div class="card">
      <div style="padding:14px 16px;border-bottom:1px solid var(--border)">
        <input id="history-search" class="input" type="search" placeholder="Filter by target…" value="${query}" style="max-width:320px">
      </div>
      ${rows === null ? html`<div class="card-pad"><p class="muted">Loading…</p></div>`
        : !rows.length ? empty("history", query ? "No matches" : "No investigations yet", query ? "Try a different filter." : "Start your first investigation, or load the demo to explore Argus.",
          query ? "" : html`<div class="hero-actions" style="justify-content:center"><button class="btn primary" data-act="new">${ico("plus")}New investigation</button><button class="btn" data-act="demo">Try the demo</button></div>`)
        : html`<table class="table"><thead><tr><th>Target</th><th>Status</th><th class="hide-sm">Entities</th><th class="hide-sm">Risk</th><th>When</th><th></th></tr></thead><tbody>
          ${rows.map((r) => html`<tr class="clickable" data-id="${r.id}" ${r.id === state.investigation?.id ? html`style="background:var(--accent-soft)"` : ""}>
            <td><b>${r.target}</b><div class="muted small">${r.target_type.replace("_", " ")}</div></td>
            <td>${statusBadge(r.status)}</td>
            <td class="hide-sm">${r.nodes_count}</td>
            <td class="hide-sm">${r.threat_exposure_score ?? "—"}</td>
            <td title="${r.created_at}">${timeAgo(r.created_at)}</td>
            <td class="actions">
              <button class="btn sm ghost" data-act="compare" data-id="${r.id}" title="Compare with the previous scan">${ico("compare")}<span class="hide-sm">Compare</span></button>
              <button class="btn sm ghost" data-act="watch" data-target="${r.target}" data-type="${r.target_type}" title="Re-scan on a schedule">${ico("eye")}<span class="hide-sm">Watch</span></button>
              <button class="btn sm ghost icon" data-act="delete" data-id="${r.id}" title="Delete" aria-label="Delete">${ico("trash")}</button>
            </td></tr>`)}
        </tbody></table>`}
    </div>
  </div>`);
  if (focused) {
    const input = $("#history-search");
    input.focus();
    input.setSelectionRange(input.value.length, input.value.length);
  }
}
