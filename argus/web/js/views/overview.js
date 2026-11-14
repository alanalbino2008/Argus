// Overview: the landing page. Welcome + recent work when nothing is open; a calm,
// decision-oriented dashboard for the open investigation.

import { api } from "../api.js";
import { empty, gauge, ico, pathCard, skeletonRows, statusBadge, tip } from "../components.js";
import { formatDate, html, on, plural, setHTML, timeAgo } from "../dom.js";
import { typeInfo } from "../icons.js";
import { isRunning, on as onState, state } from "../state.js";

let root;
let actions;
let recent = null;

export function initOverview(el, appActions) {
  root = el;
  actions = appActions;
  ["investigation", "analytics", "paths", "attack", "reset"].forEach((e) => onState(e, render));
  onState("graph", () => { if (isRunning()) throttledRender(); });
  onState("history-changed", () => { recent = null; if (!state.investigation) render(); });

  on(root, "click", "[data-action]", (e, btn) => {
    const act = btn.dataset.action;
    if (act === "show-path") actions.showPath(state.paths.paths[Number(btn.dataset.index)]);
    else if (act === "open") actions.open(btn.dataset.id);
    else if (actions[act]) actions[act](btn.dataset);
  });
  render();
}

let pending = null;
function throttledRender() {
  if (pending) return;
  pending = setTimeout(() => { pending = null; render(); }, 700);
}

function welcome() {
  if (recent === null) {
    recent = [];
    api.get("/api/investigations?limit=6").then((rows) => { recent = rows; render(); }).catch(() => {});
  }
  return html`<div class="page">
    <div class="card hero">
      <div>
        <span class="pill accent" style="margin-bottom:14px">${ico("sparkle")} Attack-surface intelligence</span>
        <h1>See your organisation the way an attacker does.</h1>
        <p>Argus maps everything publicly discoverable about a target, connects the findings into the attack paths an adversary would actually use, and watches for changes.</p>
        <div class="hero-actions">
          <button class="btn primary" data-action="newInvestigation">${ico("plus")}Start an investigation</button>
          <button class="btn" data-action="loadDemo">${ico("sparkle")}Try the demo</button>
        </div>
      </div>
      <div class="steps">
        <div class="step"><span class="step-num">1</span><div><h3>Discover</h3><p>Domains, IPs, people, certificates and exposed services from public sources.</p></div></div>
        <div class="step"><span class="step-num">2</span><div><h3>Connect</h3><p>Findings are chained into ranked attack paths mapped to MITRE ATT&amp;CK.</p></div></div>
        <div class="step"><span class="step-num">3</span><div><h3>Watch</h3><p>Re-scan on a schedule and get alerted when the attack surface changes.</p></div></div>
      </div>
    </div>
    <div class="card card-pad" style="margin-top:16px">
      <div class="card-head"><h2>Recent investigations</h2><button class="btn ghost sm" data-action="goHistory">View all</button></div>
      ${recent.length ? html`<div class="list">${recent.map((r) => html`
        <div class="list-row clickable" data-action="open" data-id="${r.id}">
          ${statusBadge(r.status)}
          <div class="list-main"><div class="list-title">${r.target}</div><div class="list-sub">${r.target_type.replace("_", " ")} · ${plural(r.nodes_count, "entity", "entities")} · ${timeAgo(r.created_at)}</div></div>
          ${r.threat_exposure_score != null ? html`<span class="pill">risk ${r.threat_exposure_score}</span>` : ""}
        </div>`)}</div>`
        : html`<p class="muted">No investigations yet — start one, or load the demo to explore.</p>`}
    </div>
  </div>`;
}

function kpis(inv) {
  const a = state.analytics || {};
  const summary = state.paths?.summary;
  const bySev = summary?.by_severity || {};
  const running = isRunning();
  return html`<div class="grid kpis">
    <div class="card kpi">
      <div class="kpi-row">
        ${gauge(running && a.threat_exposure_score == null ? 0 : a.threat_exposure_score)}
        <div>
          <div class="kpi-label">Surface risk ${tip("0–100 score combining open ports, known vulnerabilities, exposed services and weak configurations. Lower is better.")}</div>
          <div class="kpi-sub">${a.threat_exposure_score == null ? "Calculated when the scan completes" : a.threat_exposure_score >= 45 ? "Needs attention" : "Looks manageable"}</div>
        </div>
      </div>
    </div>
    <div class="card kpi">
      <div class="kpi-label">Attack paths ${tip("Findings chained into realistic attacker scenarios. Each is scored by likelihood × impact.")}</div>
      <div class="kpi-value">${summary ? summary.total : "—"}</div>
      <div class="kpi-sub">${summary ? html`${bySev.critical ? html`<span class="pill critical">${bySev.critical} critical</span> ` : ""}${bySev.high ? html`<span class="pill high">${bySev.high} high</span>` : ""}${!bySev.critical && !bySev.high ? "No critical or high paths" : ""}` : running ? "Analysed when the scan completes" : ""}</div>
    </div>
    <div class="card kpi">
      <div class="kpi-label">Assets discovered</div>
      <div class="kpi-value">${state.entities.size}</div>
      <div class="kpi-sub">${plural(state.relations.size, "connection")}</div>
    </div>
    <div class="card kpi">
      <div class="kpi-label">ATT&amp;CK techniques ${tip("MITRE ATT&CK reconnaissance techniques this organisation is exposed to, based on what was found.")}</div>
      <div class="kpi-value">${state.attack ? state.attack.technique_count : "—"}</div>
      <div class="kpi-sub">Reconnaissance (TA0043)</div>
    </div>
  </div>`;
}

function assetBreakdown() {
  const counts = {};
  state.entities.forEach((e) => { if (e.depth > 0) counts[e.type] = (counts[e.type] || 0) + 1; });
  const rows = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const max = rows.length ? rows[0][1] : 1;
  if (!rows.length) return html`<p class="muted small">Nothing discovered yet.</p>`;
  return html`<div class="bar-list">${rows.map(([type, n]) => html`
    <div class="bar-row"><span>${typeInfo(type).label}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${Math.round((n / max) * 100)}%;background:${typeInfo(type).color}"></div></div>
      <b style="text-align:right">${n}</b></div>`)}</div>`;
}

function dashboard(inv) {
  const paths = state.paths?.paths || [];
  const flags = state.analytics?.risk_flags || [];
  return html`<div class="page">
    <div class="page-head">
      <div>
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">${statusBadge(inv.status)}<span class="muted small">${inv.target_type ? inv.target_type.replace("_", " ") : ""}</span></div>
        <h1>${inv.target || "Loading…"}</h1>
        <p>${inv.completed_at ? html`Scanned ${formatDate(inv.completed_at)}` : inv.created_at ? html`Started ${timeAgo(inv.created_at)}` : ""}${inv.purpose ? html` · ${inv.purpose}` : ""}</p>
      </div>
      <div class="page-actions">
        <button class="btn sm" data-action="compare" title="Compare with the previous scan">${ico("compare")}Compare</button>
        <button class="btn sm" data-action="watch" title="Re-scan on a schedule and alert on changes">${ico("eye")}Watch</button>
        <button class="btn sm" data-action="report" title="Printable executive report">${ico("report")}Report</button>
        <button class="btn sm primary" data-action="goGraph">${ico("graph")}Open graph</button>
      </div>
    </div>
    ${kpis(inv)}
    <div class="grid two" style="margin-top:16px">
      <div>
        <div class="card-head" style="margin-top:6px"><h2>Top attack paths</h2>${paths.length ? html`<button class="btn ghost sm" data-action="goPaths">View all ${paths.length}</button>` : ""}</div>
        ${state.paths ? paths.length ? paths.slice(0, 3).map((p, i) => pathCard(p, i, { compact: true }))
          : html`<div class="card">${empty("shield", "No attack paths found", "None of the attack-path rules found supporting evidence. Keep watching to catch changes.")}</div>`
          : html`<div class="card card-pad">${isRunning() ? html`<p class="muted small" style="margin-bottom:6px">Attack paths are analysed once discovery finishes.</p>` : ""}${skeletonRows(3)}</div>`}
      </div>
      <div class="grid">
        <div class="card card-pad"><div class="card-head"><h2>What was found</h2></div>${assetBreakdown()}</div>
        <div class="card card-pad">
          <div class="card-head"><h2>Exposure flags</h2><span class="muted small">${flags.length || ""}</span></div>
          ${flags.length ? flags.slice(0, 6).map((f) => html`<div class="flag"><span class="dot"></span><span>${f}</span></div>`) : html`<p class="muted small">${state.analytics ? "No exposure flags." : "Calculated when the scan completes."}</p>`}
        </div>
        <div class="card card-pad">
          <div class="card-head"><h2>Export</h2></div>
          <div class="hero-actions">
            <button class="btn sm" data-action="exportStix" title="For OpenCTI, MISP and other threat-intel platforms (TLP:AMBER)">${ico("download")}STIX 2.1</button>
            <button class="btn sm" data-action="exportNavigator" title="Open in MITRE ATT&CK Navigator">${ico("download")}ATT&amp;CK layer</button>
            <button class="btn sm" data-action="exportCsv">${ico("download")}Maltego CSV</button>
            <button class="btn sm" data-action="exportJson">${ico("download")}JSON</button>
          </div>
        </div>
      </div>
    </div>
  </div>`;
}

export function render() {
  if (!root) return;
  const inv = state.investigation;
  setHTML(root, inv ? dashboard(inv) : welcome());
}

