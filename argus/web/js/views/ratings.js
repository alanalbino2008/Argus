// Security ratings: the shared grade badge, the per-investigation card, and the portfolio page
// (every organisation assessed in this workspace, with trend and benchmark).

import { api, enc } from "../api.js";
import { empty, ico } from "../components.js";
import { formatDate, html, on, setHTML } from "../dom.js";
import { on as onState } from "../state.js";

let root;
let actions;
let data = null;

export const gradeBadge = (grade, size = "") => html`<span class="grade ${size} grade-${grade || "none"}">${grade || "—"}</span>`;

export function sparkline(values, width = 90, height = 26) {
  if (!values || values.length < 2) return html`<span class="muted small">—</span>`;
  const min = Math.min(...values, 0);
  const max = Math.max(...values, 100);
  const points = values.map((v, i) => `${((i / (values.length - 1)) * (width - 4) + 2).toFixed(1)},${(height - 2 - ((v - min) / (max - min || 1)) * (height - 4)).toFixed(1)}`).join(" ");
  const last = values[values.length - 1];
  const colour = last >= values[0] ? "var(--ok)" : "var(--sev-critical)";
  return html`<svg class="sparkline" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-label="Score trend: ${values.join(", ")}"><polyline fill="none" stroke="${colour}" stroke-width="2" points="${points}"/></svg>`;
}

const change = (c) => (c === null || c === undefined ? "" : c === 0 ? html`<span class="muted small">no change</span>`
  : html`<span class="small" style="color:${c > 0 ? "var(--ok)" : "var(--sev-critical)"};font-weight:600">${c > 0 ? "▲" : "▼"} ${Math.abs(c)}</span>`);

// ------------------------------------------------------------------ the card on an investigation's overview
export function ratingCard(r, { onOpenIssue } = {}) {
  if (!r || !r.grade) return "";
  const issues = Object.fromEntries((r.issues || []).map((i) => [i.id, i]));
  const plan = (r.plan?.issues || []).map((id) => issues[id]).filter(Boolean);
  const bench = r.benchmark;
  return html`<div class="card card-pad rating-card" style="margin-top:16px">
    <div class="rating-head">
      ${gradeBadge(r.grade, "xl")}
      <div class="rating-summary">
        <h2>Security rating ${r.provisional ? html`<span class="pill warn" title="Less than 60% of the rating's weight could be assessed">provisional</span>` : ""}${r.live ? html` <span class="pill accent">live</span>` : ""}</h2>
        <p><b>${Math.round(r.score)}/100</b>${r.capped_at ? html` · capped at ${r.capped_at} by ${r.critical_issues} critical issue${r.critical_issues === 1 ? "" : "s"} (${Math.round(r.uncapped_score)} without the cap)` : ""} · confidence ${Math.round(r.confidence * 100)}%</p>
        <p class="muted small">${bench?.percentile != null ? html`Better than <b>${bench.percentile}%</b> of the ${bench.peers} other organisations assessed in this workspace (median ${Math.round(bench.median)}).` : html`Benchmarks appear once three or more organisations have been assessed in this workspace.`}</p>
      </div>
      <div class="rating-trend">${sparkline((r.history || []).map((h) => h.score), 120, 34)}<div class="muted small">${(r.history || []).length > 1 ? `${r.history.length} assessments` : "trend after the next scan"}</div></div>
    </div>
    <div class="rating-body">
      <div class="factor-list">${r.factors.map((f) => html`
        <div class="factor-row" title="${f.description}">
          <span class="factor-name">${f.name} <span class="muted small">${Math.round(f.weight * 100)}%</span></span>
          ${f.assessed ? html`<div class="bar-track"><div class="bar-fill grade-fill-${f.grade}" style="width:${Math.max(3, f.score)}%"></div></div>${gradeBadge(f.grade, "sm")}`
            : html`<span class="muted small" style="grid-column:span 2">not assessed in this scan</span>`}
        </div>`)}</div>
      <div class="rating-plan">
        ${plan.length ? html`<h3>Fastest route to ${gradeBadge(r.plan.reaches, "sm")}</h3>
          <ol>${plan.map((i) => html`<li><b>${i.title}</b><div class="muted small">${i.fix}</div></li>`)}</ol>`
          : r.grade === "A" ? html`<h3>${ico("check")} Top grade</h3><p class="muted small">Keep watching the target: the rating is recalculated after every scan.</p>`
          : html`<h3>Biggest improvements</h3><ol>${(r.issues || []).slice(0, 3).map((i) => html`<li><b>${i.title}</b><div class="muted small">+${i.impact} · ${i.fix}</div></li>`)}</ol>`}
        <p class="muted small" style="margin-top:8px">Methodology ${r.methodology}: every point lost is a finding you can open and fix.</p>
      </div>
    </div>
  </div>`;
}

// ------------------------------------------------------------------ the portfolio page
export function initRatings(el, appActions) {
  root = el;
  actions = appActions;
  onState("workspace", () => { data = null; });
  on(root, "click", "[data-open]", (_e, btn) => actions.open(btn.dataset.open));
}

export async function refresh() {
  if (!root) return;
  if (data === null) setHTML(root, html`<div class="page"><p class="muted">Calculating ratings…</p></div>`);
  try {
    data = await api.get("/api/ratings");
  } catch (err) {
    setHTML(root, html`<div class="page"><p class="error-text">${err.message}</p></div>`);
    return;
  }
  render();
}

function render() {
  const orgs = data.organisations;
  setHTML(root, html`<div class="page">
    <div class="page-head"><div><h1>Security ratings</h1>
      <p>Every organisation assessed in this workspace, graded A–F from what an attacker can see. Use it for your own estate, your suppliers or your clients.</p></div></div>
    ${!orgs.length ? html`<div class="card">${empty("rating", "No ratings yet", "Ratings are calculated from completed scans. Run a scan or explore the demo.")}</div>` : html`
    <div class="grid kpis" style="margin-bottom:16px">
      ${["A", "B", "C", "D", "F"].map((g) => html`<div class="card card-pad kpi-grade">${gradeBadge(g)}<div><b style="font-size:22px">${data.distribution[g]}</b><div class="muted small">organisation${data.distribution[g] === 1 ? "" : "s"}</div></div></div>`)}
    </div>
    <div class="card card-pad">
      <div class="card-head"><div><h2>Portfolio</h2><p class="muted small">Weakest first. Median score ${Math.round(data.median)}. Benchmarks compare each organisation with the others assessed here — never with invented industry averages.</p></div></div>
      <table class="table"><thead><tr><th>Organisation</th><th>Grade</th><th>Score</th><th>Trend</th><th>Weakest area</th><th>Benchmark</th><th>Assessed</th></tr></thead><tbody>
      ${orgs.map((o) => html`<tr>
        <td><button class="btn ghost sm" data-open="${o.investigation_id}" style="font-weight:600">${o.target}</button>
          ${o.critical_issues ? html`<div class="small" style="color:var(--sev-critical);padding-left:10px">${o.critical_issues} critical issue${o.critical_issues === 1 ? "" : "s"}</div>` : ""}</td>
        <td>${gradeBadge(o.grade)}${o.provisional ? html` <span class="pill warn">provisional</span>` : ""}</td>
        <td><b>${Math.round(o.score)}</b> ${change(o.change)}</td>
        <td>${sparkline(o.trend)}</td>
        <td>${o.weakest ? html`${o.weakest.name}<div class="muted small">${Math.round(o.weakest.score)}/100</div>` : "—"}</td>
        <td>${o.percentile != null ? html`better than ${o.percentile}%` : html`<span class="muted small">needs 3+</span>`}</td>
        <td>${formatDate(o.assessed_at)}</td></tr>`)}
      </tbody></table>
    </div>`}
  </div>`);
}

export const ratingUrl = (invId) => `/api/investigation/${enc(invId)}/rating`;
