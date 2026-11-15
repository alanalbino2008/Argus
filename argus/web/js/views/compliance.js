// Compliance mapping: Argus's evidence against Cyber Essentials, ISO 27001, NIST CSF 2.0 and DORA.

import { api, download } from "../api.js";
import { ico, severityPill } from "../components.js";
import { html, on, setHTML } from "../dom.js";
import { on as onState, state } from "../state.js";
import { trackFinding } from "./remediation.js";

let root;
let data = null;
let selected = "cyber_essentials";
let filter = "all";
const expanded = new Set(); // controls kept open across refreshes (e.g. while tracking several gaps)

const STATUS = { met: ["ok", "Met"], partial: ["warn", "Partially met"], gap: ["critical", "Gap"], not_assessed: ["", "Not assessed"] };
const COVERAGE = {
  direct: ["Direct", "Outside-in evidence can show this control failing or holding."],
  partial: ["Partial", "Outside-in evidence supports this control but cannot prove it."],
  process: ["Process", "Evidence comes from how security is run in Argus (monitoring, deadlines, reviews)."],
};
const canEdit = () => ["analyst", "admin"].includes(state.workspace?.role);
const chip = (s) => html`<span class="pill ${STATUS[s][0]}" style="text-transform:none">${STATUS[s][1]}</span>`;

function bar(c, total) {
  return html`<div class="cbar" role="img" aria-label="${c.met} met, ${c.partial} partially met, ${c.gap} gaps, ${c.not_assessed} not assessed">
    ${["met", "partial", "gap", "not_assessed"].map((s) => (c[s] ? html`<span class="cbar-${s}" style="flex:${c[s]}" title="${c[s]} ${STATUS[s][1].toLowerCase()}"></span>` : ""))}
  </div><div class="muted small" style="margin-top:4px">${c.met} met · ${c.partial} partial · ${c.gap} gap${c.gap === 1 ? "" : "s"} · ${c.not_assessed} not assessed (of ${total})</div>`;
}

function gapRow(g) {
  const owned = g.task ? html`<span class="pill" style="text-transform:none">Owned · ${g.task.status.replace("_", " ")}</span>`
    : canEdit() && g.kind === "attack_path" ? html`<button class="btn sm ghost" data-track="path" data-inv="${g.investigation_id}" data-id="${g.path_id}">Track fix</button>`
    : canEdit() && g.kind === "exposure" ? html`<button class="btn sm ghost" data-track="exposure" data-id="${g.finding_id}">Track fix</button>` : "";
  return html`<div class="list-row">${severityPill(g.severity)}<div class="list-main"><div class="list-title" style="white-space:normal">${g.title}</div>
    <div class="list-sub">${g.kind === "attack_path" ? "Attack path" : "Exposure"} · ${g.target}</div></div>${owned}</div>`;
}

function controlRow(c) {
  const [label, hint] = COVERAGE[c.coverage];
  return html`<details class="control control-${c.status}" data-ref="${c.ref}" ${expanded.has(c.ref) ? "open" : ""}>
    <summary>
      <span class="mono small control-ref">${c.ref}</span>
      <span class="control-title"><b>${c.title}</b><span class="muted small">${c.objective}</span></span>
      <span class="pill" title="${hint}" style="text-transform:none">${label}</span>
      ${chip(c.status)}
    </summary>
    <div class="control-body">
      <div class="section-title">Why</div><ul>${c.reasons.map((r) => html`<li>${r}</li>`)}</ul>
      ${c.evidence.length ? html`<div class="section-title">Evidence</div><ul class="small">${c.evidence.map((e) => html`<li><b>${e.label}</b>: ${e.detail}</li>`)}</ul>` : ""}
      ${c.gaps.length ? html`<div class="section-title">Findings against this control (${c.gap_count})</div><div class="list">${c.gaps.map(gapRow)}</div>` : ""}
    </div>
  </details>`;
}

function render() {
  const fw = data.frameworks.find((f) => f.id === selected) || data.frameworks[0];
  const controls = fw.controls.filter((c) => filter === "all" || c.status === filter);
  setHTML(root, html`<div class="page">
    <div class="page-head">
      <div><h1>Compliance</h1><p>What Argus's evidence says about the controls you are audited against. Every status shows its reasons and evidence, and gaps can be turned into tracked fixes.</p></div>
      <div class="page-actions">
        <button class="btn sm" data-act="csv">${ico("download")}${fw.name} (CSV)</button>
        <button class="btn sm" data-act="json">${ico("download")}Evidence pack (JSON)</button>
      </div>
    </div>
    <div class="guide-warning info" style="margin-bottom:16px">${ico("info")}<div class="small">${data.disclaimer}</div></div>
    <div class="fw-grid">${data.frameworks.map((f) => html`<button class="card card-pad fw-card ${f.id === fw.id ? "active" : ""}" data-fw="${f.id}" aria-pressed="${f.id === fw.id}">
      <div style="display:flex;justify-content:space-between;gap:8px;align-items:baseline"><b>${f.name}</b><span class="muted small">${f.version}</span></div>
      ${bar(f.counts, f.total)}
    </button>`)}</div>
    <div class="card card-pad" style="margin-top:16px">
      <div class="card-head"><div><h2>${fw.name} <span class="muted" style="font-weight:400">${fw.version}</span></h2><p class="muted small">${fw.summary} Assessed: ${fw.assessed_pct}% of mapped controls${fw.met_pct === null ? "" : `, ${fw.met_pct}% of those met`}.</p></div>
        <div class="segmented">${[["all", "All"], ["gap", "Gaps"], ["partial", "Partial"], ["met", "Met"], ["not_assessed", "Not assessed"]].map(([v, l]) => html`<button class="${filter === v ? "active" : ""}" data-filter="${v}">${l}</button>`)}</div></div>
      ${controls.length ? controls.map(controlRow) : html`<p class="muted">No controls with this status.</p>`}
    </div>
  </div>`);
}

export async function refresh() {
  if (!root) return;
  try {
    data = await api.get("/api/compliance");
  } catch (err) {
    setHTML(root, html`<div class="page"><p class="error-text">${err.message}</p></div>`);
    return;
  }
  render();
}

export function initCompliance(el) {
  root = el;
  onState("workspace", () => { data = null; });
  on(root, "click", "[data-fw]", (_e, btn) => { selected = btn.dataset.fw; filter = "all"; expanded.clear(); render(); });
  root.addEventListener("toggle", (e) => {
    const ref = e.target.dataset?.ref;
    if (ref) e.target.open ? expanded.add(ref) : expanded.delete(ref);
  }, true);
  on(root, "click", "[data-filter]", (_e, btn) => { filter = btn.dataset.filter; render(); });
  on(root, "click", "[data-act]", (_e, btn) => {
    const stamp = new Date().toISOString().slice(0, 10).replaceAll("-", "");
    if (btn.dataset.act === "csv") download(`/api/compliance/${selected}/export.csv`, `argus-${selected}-${stamp}.csv`);
    if (btn.dataset.act === "json") download("/api/compliance/evidence.json", `argus-compliance-evidence-${stamp}.json`);
  });
  on(root, "click", "[data-track]", async (e, btn) => {
    e.preventDefault();
    const source = btn.dataset.track === "path"
      ? { type: "attack_path", investigation_id: btn.dataset.inv, path_id: btn.dataset.id }
      : { type: "exposure", finding_id: btn.dataset.id };
    if (await trackFinding(source)) refresh();
  });
}
