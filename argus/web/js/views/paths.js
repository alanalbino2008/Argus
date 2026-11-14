// Attack paths: the signature view. Ranked scenarios, filterable by severity.

import { empty, ico, pathCard, SEVERITIES } from "../components.js";
import { html, on, setHTML } from "../dom.js";
import { isRunning, on as onState, state } from "../state.js";

let root;
let actions;
let filter = "all";

export function initPaths(el, appActions) {
  root = el;
  actions = appActions;
  ["paths", "reset", "investigation"].forEach((e) => onState(e, render));
  on(root, "click", "[data-filter]", (_e, btn) => { filter = btn.dataset.filter; render(); });
  on(root, "click", "[data-action='show-path']", (_e, btn) => actions.showPath(state.paths.paths[Number(btn.dataset.index)]));
  on(root, "click", "[data-action='newInvestigation'], [data-action='loadDemo']", (_e, btn) => actions[btn.dataset.action]());
  render();
}

function render() {
  if (!root) return;
  const inv = state.investigation;
  if (!inv) {
    setHTML(root, html`<div class="page"><div class="card">${empty("paths", "No investigation open", "Attack paths connect individual findings into the scenarios an attacker would actually use.",
      html`<div class="hero-actions" style="justify-content:center"><button class="btn primary" data-action="newInvestigation">${ico("plus")}New investigation</button><button class="btn" data-action="loadDemo">Try the demo</button></div>`)}</div></div>`);
    return;
  }
  const data = state.paths;
  const all = data?.paths || [];
  const shown = all.map((p, i) => ({ p, i })).filter(({ p }) => filter === "all" || p.severity === filter);
  const counts = data?.summary?.by_severity || {};
  setHTML(root, html`<div class="page" style="max-width:980px">
    <div class="page-head">
      <div>
        <h1>Attack paths</h1>
        <p>How an attacker could chain what was found about <b>${inv.target}</b>, ranked by risk. Each card explains the route, the evidence and what to fix first.</p>
      </div>
    </div>
    ${data ? html`
      <div class="filters" style="margin-bottom:16px">
        <div class="segmented" role="tablist">
          <button class="${filter === "all" ? "active" : ""}" data-filter="all">All ${all.length}</button>
          ${SEVERITIES.map((s) => html`<button class="${filter === s ? "active" : ""}" data-filter="${s}">${s[0].toUpperCase() + s.slice(1)} ${counts[s] || 0}</button>`)}
        </div>
        <span class="muted small">${data.summary.rules_evaluated} rules evaluated</span>
      </div>
      ${shown.length ? shown.map(({ p, i }) => pathCard(p, i))
        : html`<div class="card">${empty("shield", all.length ? "Nothing at this severity" : "No attack paths found",
          all.length ? "Try another filter." : "None of the rules found supporting evidence. That's good news — watch the target to catch future changes.")}</div>`}`
      : html`<div class="card">${empty("paths", isRunning() ? "Discovery in progress" : "Analysing…", "Attack paths are calculated once the scan has finished collecting findings.")}</div>`}
  </div>`);
}
