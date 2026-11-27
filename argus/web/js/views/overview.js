// Overview: the landing page. Welcome + recent work when nothing is open; a calm,
// decision-oriented dashboard for the open investigation.

import { api } from "../api.js";
import { empty, gauge, ico, pathCard, skeletonRows, statusBadge, tip } from "../components.js";
import { formatDate, html, on, plural, setHTML, timeAgo } from "../dom.js";
import { typeInfo } from "../icons.js";
import { isRunning, on as onState, state } from "../state.js";
import { checklistCard, hideChecklist } from "./guide.js";
import { ratingCard, ratingUrl } from "./ratings.js";

let root;
let actions;
let recent = null;
let checklist; // undefined = not loaded, null = nothing to show
let rating = { key: null, data: null };

function loadRating(inv) {
  // Recalculate when another investigation opens or this one finishes (paths are final then).
  const key = inv?.id && state.paths ? `${inv.id}:${inv.status}` : null;
  if (!key || key === rating.key) return;
  rating = { key, data: rating.data && rating.data.investigation_id === inv.id ? rating.data : null };
  api.get(ratingUrl(inv.id)).then((r) => { if (rating.key === key) { rating.data = r; render(); } }).catch(() => {});
}

export function initOverview(el, appActions) {
  root = el;
  actions = appActions;
  ["investigation", "analytics", "paths", "attack", "reset"].forEach((e) => onState(e, render));
  onState("graph", () => { if (isRunning()) throttledRender(); });
  onState("history-changed", () => { recent = null; checklist = undefined; if (!state.investigation) render(); });
  ["onboarding-changed", "workspace"].forEach((e) => onState(e, () => { checklist = undefined; if (!state.investigation) render(); }));

  on(root, "click", "[data-action]", (e, btn) => {
    const act = btn.dataset.action;
    if (act === "show-path") actions.showPath(state.paths.paths[Number(btn.dataset.index)]);
    else if (act === "hideChecklist") { hideChecklist(); checklist = null; render(); }
    else if (act === "checklist") runChecklistStep(btn.dataset.act);
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

async function runChecklistStep(act) {
  // Steps that need a finished investigation open the latest one first.
  if (["report", "goPaths"].includes(act) && !state.investigation) {
    if (!checklist?.latestId) return actions.toast("Run a scan or explore the demo first", "info");
    await actions.open(checklist.latestId);
  }
  actions[act]?.();
}

function welcome() {
  if (checklist === undefined) {
    checklist = null;
    checklistCard().then((c) => { checklist = c; if (!state.investigation) render(); });
  }
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
          <button class="btn primary" data-action="guide">${ico("sparkle")}Guided first scan</button>
          <button class="btn" data-action="newInvestigation">${ico("plus")}New investigation</button>
          <button class="btn ghost" data-action="loadDemo">Try the demo</button>
        </div>
      </div>
      <div class="steps">
        <div class="step"><span class="step-num">1</span><div><h3>Discover</h3><p>Domains, IPs, people, certificates and exposed services from public sources.</p></div></div>
        <div class="step"><span class="step-num">2</span><div><h3>Connect</h3><p>Findings are chained into ranked attack paths mapped to MITRE ATT&amp;CK.</p></div></div>
        <div class="step"><span class="step-num">3</span><div><h3>Watch</h3><p>Re-scan on a schedule and get alerted when the attack surface changes.</p></div></div>
      </div>
    </div>
    ${checklist ? checklist.render() : ""}
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
  // Lookalike domains belong to third parties: they are not the target's assets.
  state.entities.forEach((e) => { if (e.depth > 0 && !e.metadata?.out_of_scope) counts[e.type] = (counts[e.type] || 0) + 1; });
  const rows = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const max = rows.length ? rows[0][1] : 1;
  if (!rows.length) return html`<p class="muted small">Nothing discovered yet.</p>`;
  return html`<div class="bar-list">${rows.map(([type, n]) => html`
    <div class="bar-row"><span>${typeInfo(type).label}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${Math.round((n / max) * 100)}%;background:${typeInfo(type).color}"></div></div>
      <b style="text-align:right">${n}</b></div>`)}</div>`;
}

const VERDICT = {
  suspicious: ["critical", "Impostor"],
  parked: ["warn", "Parked"],
  yours: ["ok", "Yours"],
};

function lookalikePanel() {
  const seed = [...state.entities.values()].find((e) => e.depth === 0);
  const found = [...state.entities.values()].filter((e) => e.metadata?.lookalike)
    .sort((a, b) => b.metadata.lookalike.risk - a.metadata.lookalike.risk);
  if (!seed?.metadata?.lookalikes_checked && !found.length) return "";
  const threats = found.filter((e) => e.metadata.lookalike.verdict !== "yours");
  const mail = threats.filter((e) => e.metadata.lookalike.mx.length).length;
  return html`<div class="card card-pad" style="margin-top:16px">
    <div class="card-head"><div><h2>Brand impersonation</h2>
      <p class="muted small">${seed?.metadata?.lookalikes_checked || "Many"} lookalike domains checked (typos, look-alike letters, other endings, brand + keyword) · ${found.length} registered · <b>${threats.length}</b> not yours${mail ? html` · <b style="color:var(--sev-critical-text)">${mail} can send email</b>` : ""}</p></div></div>
    ${found.length ? html`<table class="table"><thead><tr><th>Domain</th><th>How it imitates you</th><th>Status</th><th>Email</th><th>Risk</th></tr></thead><tbody>
      ${found.slice(0, 12).map((e) => {
        const l = e.metadata.lookalike;
        const [cls, label] = VERDICT[l.verdict] || ["", l.verdict];
        return html`<tr>
          <td><b>${l.display}</b>${l.display !== e.value ? html`<div class="muted small mono" title="What the browser really visits">${e.value}</div>` : ""}</td>
          <td>${l.detail}<div class="muted small">${l.technique}</div></td>
          <td><span class="pill ${cls}">${label}</span></td>
          <td>${!l.mx.length ? html`<span class="muted small">No</span>` : l.verdict === "yours" ? html`<span title="${l.mx.join(", ")}">Yes</span>` : html`<span class="pill critical" title="${l.mx.join(", ")}">Yes</span>`}</td>
          <td><b>${l.risk}</b></td></tr>`;
      })}</tbody></table>
      <p class="muted small" style="margin-top:8px">Impostor domains are recorded but never investigated: they belong to third parties. “Yours” means it shares your name servers or hosting, so it is probably a defensive registration.</p>`
      : html`<p class="muted small">No registered lookalikes found — good. Keep watching the target to be alerted if one appears.</p>`}
  </div>`;
}

const EVIDENCE_LABEL = {
  analytics: "Same analytics ID",
  certificate_org: "Same certificate organisation",
  own_nameserver: "Your name server",
  nameserver: "Same name servers",
  shared_ip: "Same IP",
  shared_ip_small: "Same IP",
};

function relatedPanel() {
  const seed = [...state.entities.values()].find((e) => e.depth === 0);
  const related = [...state.entities.values()].filter((e) => e.metadata?.pivot)
    .sort((a, b) => b.metadata.pivot.confidence - a.metadata.pivot.confidence);
  const summary = seed?.metadata?.pivot_summary;
  if (!summary && !related.length) return "";
  return html`<div class="card card-pad" style="margin-top:16px">
    <div class="card-head"><div><h2>Related infrastructure</h2>
      <p class="muted small">Other domains that share something with ${seed?.value || "the target"} — an analytics ID${summary?.certificate_org ? html`, the certificate organisation <b>${summary.certificate_org}</b>` : ""}, name servers or hosting. They were <b>not scanned</b>: confirm they're in scope, then investigate them.</p></div></div>
    ${related.length ? html`<table class="table"><thead><tr><th>Domain</th><th>Linked by</th><th>Confidence</th><th></th></tr></thead><tbody>
      ${related.slice(0, 15).map((e) => {
        const p = e.metadata.pivot;
        const kinds = [...new Set(p.evidence.map((x) => EVIDENCE_LABEL[x.kind] || x.kind))];
        return html`<tr>
          <td><b>${e.value}</b><div class="muted small">${p.attribution}</div></td>
          <td>${kinds.map((k) => html`<span class="pill" style="margin:0 4px 4px 0">${k}</span>`)}
            <div class="muted small">${p.evidence.slice(0, 2).map((x) => x.detail).join(" · ")}</div></td>
          <td style="min-width:120px"><div class="progress" title="${Math.round(p.confidence * 100)}%"><span style="width:${Math.round(p.confidence * 100)}%;background:${p.confidence >= 0.8 ? "var(--ok)" : "var(--sev-medium)"}"></span></div>
            <span class="muted small">${Math.round(p.confidence * 100)}%</span></td>
          <td class="actions"><button class="btn sm" data-action="guide" data-target="${e.value}" title="Start a guided, authorised scan of this domain">Investigate</button></td></tr>`;
      })}</tbody></table>`
      : html`<p class="muted small">No related domains found${summary?.trackers?.length ? ` (tracking IDs checked: ${summary.trackers.join(", ")})` : ""}.</p>`}
  </div>`;
}

function dashboard(inv) {
  loadRating(inv);
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
    ${rating.data?.investigation_id === inv.id ? ratingCard(rating.data) : ""}
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
    ${relatedPanel()}
    ${lookalikePanel()}
  </div>`;
}

export function render() {
  if (!root) return;
  const inv = state.investigation;
  setHTML(root, inv ? dashboard(inv) : welcome());
}

