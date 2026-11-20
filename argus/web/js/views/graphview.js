// Graph workspace: canvas, toolbar, legend, and a side panel that connects the selected
// entity to everything else - its facts, neighbours, attack paths and other investigations.

import { imageSearchLinks } from "./research.js";
import { api, enc } from "../api.js";
import { empty, entityIcon, ico, severityPill } from "../components.js";
import { $, $$, formatDay, html, on, setHTML, timeAgo, toast } from "../dom.js";
import { ENTITY_TYPES, typeInfo } from "../icons.js";
import * as graph from "../graph.js";
import { isRunning, on as onState, state } from "../state.js";
import { addEntityToCase } from "./cases.js";

let actions;
let selected = null;
let pivotsFor = null;
let pivots = [];
// Argus Query Language: the last query, its result or error, the syntax help and link analysis.
let query = { text: "", result: null, error: null, busy: false };
let queryHelp = null;
let savedQueries = null; // the workspace's saved queries (loaded with the Query tab)
let hunt = null; // { text, busy, result, error } for a hunt across investigations
let saving = false; // the save form is open
let links = null; // { for: investigation id, data } from /links
let communityColours = false;
// Text that looks like a query rather than a name to find (operators, arrows, "path from", "*").
const AQL_HINT = /[:~=<>|]|->|<-|--|^\s*path\s+from\s|^\s*\*/i;

// Keys shown in their own panels (or not at all) rather than the generic details list.
const HIDDEN_META = new Set([
  "full_record", "profile", "lifecycle", "intel", "verified", "sources", "document", "secrets", "hostnames",
  "wayback", "passive_dns", "passive_sources", "security_txt", "public_code", "cloud_storage", "pgp_keys",
  "sample_keys", "archive_url", "exposed_files", "platforms_unreliable", "platforms_checked", "platforms_unreachable",
  "public_listing", "evidence", "file", "category", "live", "repository", "path", "repository_owner", "bucket",
  "provider", "ownership", "archived_on", "archived_status",
  "chain", "chains", "address_kind", "checksum", "asset", "balance", "total_received", "total_sent", "transactions",
  "explorer_url", "sanctions", "sanctioned_counterparties", "service", "coinjoins", "transactions_examined",
  "first_seen", "last_seen", "label", "ens", "traceable",
  "registry", "company_number", "legal_name", "company_status", "incorporated", "dissolved", "company_type", "sic_codes",
  "registered_address", "register_url", "registry_candidates", "lei", "jurisdiction", "entity_status", "head_office",
  "registered_as", "lei_status", "lei_url", "sec_cik", "ticker", "sec_name", "sic", "state_of_incorporation",
  "business_address", "former_names", "recent_filings", "sec_url", "sanction_matches", "offshore_leaks",
  "offshore_leaks_credit", "source_registry", "role", "appointed", "resigned", "nationality", "occupation", "born",
  "country_of_residence", "ch_officer_id", "ch_company", "officer_matches", "appointments_total", "via_possible_match",
  "crawl", "tracking_ids", "links_to_sites", "found_on", "on_site_domain", "hosted_elsewhere",
  "phone", "phone_valid", "web_mentions", "mention_kind", "snippet", "page_age",
  "network", "network_ranges", "networks_checked", "shared_provider", "holder", "matched_by",
  "insolvency_notices", "insolvency_notices_total", "insolvency_notices_checked", "insolvency_notice_match",
  "court_cases", "court_cases_total", "court_case_match", "matched_person", "same_name_elsewhere", "french_directorships",
  "opencorporates_officer_matches", "opencorporates_url", "legal_form_code", "activity_code", "company_size",
  "establishments", "country", "employees", "in_group", "insolvency", "industry",
  "mmh3", "md5", "sha256", "size", "content_type", "search_queries", "pivot_hub",
  "jarm", "probes_answered", "hassh_server", "hassh_server_algorithms",
]);

const CATEGORY_LABEL = {
  sensitive_file: "Sensitive file (archived)", credential_in_url: "Credentials in URL (archived)",
  admin_panel: "Admin / login panel", api: "API description", document: "Public document",
  code: "Public source code", exposed_file: "Exposed file", cloud_storage: "Cloud storage", robots: "Hidden from search engines",
};

const humanSource = (s) => String(s).replace(/_/g, " ");

export function initGraphView(appActions) {
  actions = appActions;
  graph.initGraph($("#cy"), {
    onSelect: (data) => { selected = data.id; showPane("details"); renderDetails(); },
    onDeselect: () => { selected = null; renderDetails(); },
  });

  $("#layout-select").addEventListener("change", (e) => graph.relayout(e.target.value));
  $("#btn-fit").addEventListener("click", graph.fit);
  $("#btn-zoom-in").addEventListener("click", () => graph.zoomBy(1.25));
  $("#btn-zoom-out").addEventListener("click", () => graph.zoomBy(0.8));
  $("#btn-panel").addEventListener("click", togglePanel);
  $("#workspace").addEventListener("transitionend", graph.resizeCanvas);
  $("#graph-search").addEventListener("keydown", (e) => {
    if (e.key === "Escape") { e.target.value = ""; clearQuery(); return; }
    if (e.key !== "Enter") return;
    const text = e.target.value.trim();
    if (!text) { clearQuery(); return; }
    if (!AQL_HINT.test(text)) { // a name: jump to it locally, else search for it as a query
      const id = graph.findNode(text);
      if (id) { clearQuery(); if (graph.selectNode(id)) return; }
    }
    runQuery(text);
  });
  on($("#pane-query"), "click", "[data-example]", (_e, el) => {
    $("#graph-search").value = el.dataset.example;
    runQuery(el.dataset.example);
  });
  on($("#pane-query"), "click", "[data-select]", (_e, el) => graph.selectNode(el.dataset.select));
  on($("#pane-query"), "click", "[data-query-path]", (_e, el) => {
    const route = query.result?.paths?.[Number(el.dataset.queryPath)];
    if (route) graph.highlightSet(route.nodes, route.edges);
  });
  on($("#pane-query"), "click", "[data-query-all]", () => highlightQuery());
  on($("#pane-query"), "click", "[data-query-clear]", () => { $("#graph-search").value = ""; clearQuery(); });
  on($("#pane-query"), "click", "[data-query-hunt]", () => runHunt(query.text));
  on($("#pane-query"), "click", "[data-query-save]", () => { saving = !saving; renderQuery(); });
  on($("#pane-query"), "submit", "form[data-save-form]", (e, form) => { e.preventDefault(); saveQuery(form); });
  on($("#pane-query"), "click", "[data-saved-run]", (_e, el) => {
    const sq = savedQueries?.find((q) => q.id === el.dataset.savedRun);
    if (sq) { $("#graph-search").value = sq.query; runQuery(sq.query); }
  });
  on($("#pane-query"), "click", "[data-saved-hunt]", (_e, el) => {
    const sq = savedQueries?.find((q) => q.id === el.dataset.savedHunt);
    if (sq) runHunt(sq.query);
  });
  on($("#pane-query"), "click", "[data-saved-alert]", (_e, el) => toggleSavedAlert(el.dataset.savedAlert));
  on($("#pane-query"), "click", "[data-saved-delete]", (_e, el) => deleteSaved(el.dataset.savedDelete));
  on($("#pane-query"), "click", "[data-hunt-open]", (_e, el) => actions.open(el.dataset.huntOpen, { view: "graph" }));
  on($("#pane-query"), "click", "[data-hunt-close]", () => { hunt = null; renderQuery(); });
  on($("#pane-intel"), "click", "[data-community-colours]", () => toggleCommunityColours());
  on($("#pane-intel"), "click", "[data-community]", (_e, el) => {
    const index = Number(el.dataset.community);
    const ids = Object.entries(links?.data?.community_of || {}).filter(([, c]) => c === index).map(([id]) => id);
    graph.highlightSet(ids);
  });

  on($(".panel-tabs"), "click", ".panel-tab", (_e, tab) => showPane(tab.dataset.pane));
  on($("#legend"), "click", ".legend-chip", (_e, chip) => {
    const visible = !graph.isTypeVisible(chip.dataset.type);
    graph.setTypeVisible(chip.dataset.type, visible);
    chip.classList.toggle("off", !visible);
  });
  on($("#pane-details"), "click", "[data-copy]", async (_e, el) => {
    try { await navigator.clipboard.writeText(el.dataset.copy); toast("Copied", "success"); } catch { toast("Copy failed: select the text instead", "error"); }
  });
  on($("#pane-details"), "click", "[data-to-case]", () => {
    const entity = selected && state.entities.get(selected);
    if (entity) addEntityToCase(entity, state.investigation?.id).catch((err) => toast(err.message, "error"));
  });
  on($("#pane-details"), "click", "[data-select]", (_e, el) => graph.selectNode(el.dataset.select));
  on($("#pane-intel"), "click", "[data-select]", (_e, el) => graph.selectNode(el.dataset.select));
  on($("#pane-details"), "click", "[data-open]", (_e, el) => actions.open(el.dataset.open));
  on($("#pane-details"), "click", "[data-path]", (_e, el) => actions.showPath(state.paths.paths[Number(el.dataset.path)]));
  on($("#graph-empty"), "click", "[data-action]", (_e, el) => actions[el.dataset.action]?.());

  onState("graph", () => { renderLegend(); renderEmpty(); });
  onState("entities-refreshed", () => renderDetails());
  onState("reset", () => {
    selected = null; pivotsFor = null; links = null; communityColours = false; hunt = null; saving = false; savedQueries = null;
    query = { text: "", result: null, error: null, busy: false };
    renderAll();
  });
  onState("investigation", renderEmpty);
  ["analytics", "attack", "paths"].forEach((e) => onState(e, () => { renderIntel(); renderDetails(); }));
  onState("analytics", () => loadLinks());
  onState("feed", renderActivity);
  document.addEventListener("argus:theme", graph.applyTheme);
  renderAll();
}

function renderAll() {
  renderLegend();
  renderEmpty();
  renderDetails();
  renderIntel();
  renderQuery();
  renderActivity();
}

// ------------------------------------------------------------------ Argus Query Language
async function runQuery(text) {
  const id = state.investigation?.id;
  if (!id) { toast("Open an investigation first"); return; }
  query = { text, result: null, error: null, busy: true };
  showPane("query");
  renderQuery();
  try {
    const result = await api.post(`/api/investigation/${enc(id)}/query`, { query: text });
    if (state.investigation?.id !== id || query.text !== text) return; // superseded
    query = { text, result, error: null, busy: false };
    highlightQuery();
  } catch (err) {
    if (query.text !== text) return;
    query = { text, result: null, error: { message: err.message, position: err.detail?.position ?? null }, busy: false };
    graph.clearHighlight();
  }
  renderQuery();
}

function highlightQuery() {
  const r = query.result;
  if (!r) return;
  if (!graph.highlightSet(r.node_ids, r.edge_ids)) graph.clearHighlight();
}

function clearQuery() {
  query = { text: "", result: null, error: null, busy: false };
  graph.clearHighlight();
  renderQuery();
}

async function ensureQueryHelp() {
  if (queryHelp) return;
  try { queryHelp = await api.get("/api/query/help"); renderQuery(); } catch { /* examples are optional */ }
}

function renderQuery() {
  const pane = $("#pane-query");
  if (!pane) return;
  if (hunt) { setHTML(pane, renderHunt()); return; }
  renderQueryMain(pane);
  pane.insertAdjacentHTML("beforeend", String(renderSaved()));
}

function renderQueryMain(pane) {
  const { text, result, error, busy } = query;
  if (busy) { setHTML(pane, html`<p class="muted small">Running <code>${text}</code>…</p>`); return; }
  if (error) {
    const caret = error.position != null ? `${" ".repeat(Math.max(0, error.position))}^` : "";
    setHTML(pane, html`<div class="query-error"><b>That query didn't run</b><div>${error.message}</div>
      ${caret ? html`<pre>${text}
${caret}</pre>` : ""}</div>${queryExamples()}`);
    ensureQueryHelp();
    return;
  }
  if (!result) {
    setHTML(pane, html`<p class="muted small">Type a query in the search box and press Enter. Esc clears it.</p>${queryExamples()}`);
    ensureQueryHelp();
    return;
  }
  const head = html`<div class="query-meta"><span><b>${result.count}</b> ${result.kind === "paths" ? "reachable" : "matches"} <span class="muted small">· ${result.elapsed_ms} ms</span></span>
    <span><button class="btn sm" data-query-all title="Highlight all results">Show all</button> <button class="btn sm" data-query-clear>Clear</button></span></div>
    <div class="query-actions"><button class="btn sm" data-query-hunt title="Run this query on every investigation">${ico("search")}Hunt across investigations</button>
      <button class="btn sm" data-query-save>${ico("plus")}Save</button></div>
    ${saving ? saveForm() : ""}`;
  let body = "";
  if (result.kind === "count") {
    body = html`<p class="muted small">Matching entities are highlighted on the graph.</p>`;
  } else if (result.kind === "groups") {
    const top = Math.max(1, ...result.groups.map((g) => g.count));
    body = html`${result.groups.map((g) => html`<div class="list-row"><div class="list-main"><div class="list-title">${g.key}</div>
      <div class="group-bar" style="width:${Math.round((g.count / top) * 100)}%"></div></div><span class="pill">${g.count}</span></div>`)}`;
  } else {
    const labels = new Map(result.rows.map((r) => [r.id, r.label]));
    const label = (nid) => labels.get(nid) || state.entities.get(nid)?.label || nid;
    body = html`${result.paths.length ? html`<div class="section-title">${result.kind === "paths" ? "Shortest routes" : "Matched patterns"}</div>
      ${result.paths.map((p, i) => html`<div class="list-row clickable query-path" data-query-path="${i}">
        <div class="list-main">${p.nodes.map((nid, j) => html`${j ? html` <b>→</b> ` : ""}${label(nid)}`)}</div>
        <span class="muted small">${p.edges.length} hop${p.edges.length === 1 ? "" : "s"}</span></div>`)}
      <div class="section-title" style="margin-top:12px">Results</div>` : ""}
      ${result.rows.length ? result.rows.map((r) => html`<div class="list-row clickable" data-select="${r.id}">${entityIcon(r.type)}
        <div class="list-main"><div class="list-title">${r.label}</div><div class="muted small">${r.type.replaceAll("_", " ")}${r.key_score != null ? ` · key ${r.key_score}` : ""}</div></div>
        <span class="muted small">${r.degree} link${r.degree === 1 ? "" : "s"}</span></div>`)
        : html`<p class="muted small">Nothing matches. Check the field names, or try a broader filter.</p>`}
      ${result.truncated ? html`<p class="muted small">Showing ${result.rows.length} of ${result.count}. Add <code>| limit n</code> or narrow the filter.</p>` : ""}`;
  }
  setHTML(pane, html`${head}${body}`);
}

function queryExamples() {
  if (!queryHelp) return "";
  return html`<div class="section-title" style="margin-top:14px">Try</div>
    ${queryHelp.examples.map((ex) => html`<button class="query-example" data-example="${ex.query}"><code>${ex.query}</code><span>${ex.explains}</span></button>`)}
    <details class="more" style="margin-top:10px"><summary class="muted small">Syntax</summary>
      ${queryHelp.syntax.map((s) => html`<div class="flag" style="display:block"><code>${s.form}</code><div class="muted small">${s.means}</div></div>`)}</details>`;
}

function saveForm() {
  return html`<form class="save-query" data-save-form>
    <input class="input" name="name" maxlength="120" placeholder="Name, e.g. Exploited CVEs" required>
    <label class="small"><input type="checkbox" name="alert"> Alert when a scan finds new matches</label>
    <select class="select" name="severity" aria-label="Alert severity">
      <option value="low">Low</option><option value="medium" selected>Medium</option><option value="high">High</option><option value="critical">Critical</option>
    </select>
    <button class="btn sm primary" type="submit">Save query</button></form>`;
}

let savedLoading = false;
async function loadSaved() {
  if (savedLoading) return;
  savedLoading = true;
  try { savedQueries = await api.get("/api/saved-queries"); } catch { savedQueries = []; } finally { savedLoading = false; }
  renderQuery();
}

function renderSaved() {
  if (savedQueries === null) { loadSaved(); return html`<p class="muted small">Loading saved queries…</p>`; }
  if (!savedQueries.length) return html`<div class="section"><div class="section-title">Saved queries</div><p class="muted small">Save a query to reuse it, share it with your team, hunt with it, or be alerted when a scan finds something new.</p></div>`;
  return html`<div class="section"><div class="section-title">Saved queries</div>
    ${savedQueries.map((q) => html`<div class="saved-query">
      <div class="list-main"><div class="list-title">${q.name}</div>
        ${q.alert ? html`<span class="pill ${q.severity === "critical" || q.severity === "high" ? "high" : "accent"}" title="Alerts when a scan finds new matches">alerts · ${q.severity}</span>` : ""}
        <code class="small">${q.query}</code>
        ${q.alerts_raised ? html`<div class="muted small">${q.alerts_raised} alert${q.alerts_raised === 1 ? "" : "s"} raised · last ${timeAgo(q.last_alert_at)}</div>` : ""}</div>
      <div class="saved-actions">
        <button class="btn sm" data-saved-run="${q.id}" title="Run on this investigation">Run</button>
        <button class="btn sm" data-saved-hunt="${q.id}" title="Run on every investigation">Hunt</button>
        <button class="btn sm" data-saved-alert="${q.id}" title="${q.alert ? "Stop alerting" : "Alert when a scan finds new matches"}">${q.alert ? "Mute" : "Alert"}</button>
        <button class="btn sm" data-saved-delete="${q.id}" title="Delete">✕</button></div></div>`)}</div>`;
}

async function saveQuery(form) {
  const data = new FormData(form);
  try {
    await api.post("/api/saved-queries", { name: String(data.get("name") || "").trim(), query: query.text, alert: data.get("alert") === "on", severity: data.get("severity") });
    saving = false;
    toast("Query saved", "success");
    await loadSaved();
  } catch (err) { toast(err.message, "error"); }
}

async function toggleSavedAlert(id) {
  const sq = savedQueries?.find((q) => q.id === id);
  if (!sq) return;
  try { await api.patch(`/api/saved-queries/${enc(id)}`, { alert: !sq.alert }); await loadSaved(); } catch (err) { toast(err.message, "error"); }
}

async function deleteSaved(id) {
  const sq = savedQueries?.find((q) => q.id === id);
  if (!sq || !confirm(`Delete the saved query “${sq.name}”?`)) return;
  try { await api.del(`/api/saved-queries/${enc(id)}`); await loadSaved(); } catch (err) { toast(err.message, "error"); }
}

// ------------------------------------------------------------------ hunts across investigations
async function runHunt(text) {
  if (!text) return;
  hunt = { text, busy: true, result: null, error: null };
  showPane("query");
  renderQuery();
  try {
    const result = await api.post("/api/hunt", { query: text, investigations: 50 });
    if (hunt?.text === text) hunt = { text, busy: false, result, error: null };
  } catch (err) {
    if (hunt?.text === text) hunt = { text, busy: false, result: null, error: err.message };
  }
  renderQuery();
}

function renderHunt() {
  const { text, busy, result, error } = hunt;
  const head = html`<div class="query-meta"><span><b>Hunt</b> <code class="small">${text}</code></span><button class="btn sm" data-hunt-close>Back</button></div>`;
  if (busy) return html`${head}<p class="muted small">Searching your investigations…</p>`;
  if (error) return html`${head}<div class="query-error">${error}</div>`;
  const r = result;
  return html`${head}
    <p class="small"><b>${r.investigations_matched}</b> of ${r.investigations_searched} investigations match · ${r.total_matches} matches · ${r.elapsed_ms} ms
      ${r.partial ? html`<br><span class="muted">Stopped at the time limit: the oldest investigations were not searched.</span>` : ""}</p>
    ${r.results.length ? r.results.map((hit) => html`<div class="list-row clickable" data-hunt-open="${hit.investigation_id}">
      <div class="list-main"><div class="list-title">${hit.target}</div>
        <div class="muted small">${timeAgo(hit.created_at)} · ${hit.rows.map((row) => row.label).join(", ")}${hit.count > hit.rows.length ? "…" : ""}</div></div>
      <span class="pill">${hit.count}</span></div>`)
      : html`<p class="muted small">No investigation matches.</p>`}`;
}

// ------------------------------------------------------------------ link analysis
async function loadLinks() {
  const id = state.investigation?.id;
  if (!id || isRunning()) return; // scores settle when the scan does
  try {
    const data = await api.get(`/api/investigation/${enc(id)}/links`);
    if (state.investigation?.id !== id) return;
    links = { for: id, data };
    if (communityColours) graph.colorByCommunity(data.community_of);
    renderIntel();
  } catch { /* link analysis is optional */ }
}

function toggleCommunityColours() {
  communityColours = !communityColours;
  graph.colorByCommunity(communityColours ? links?.data?.community_of : null);
  renderIntel();
}

function renderLinks() {
  const d = links?.data;
  if (!d) return html`<p class="muted small">${isRunning() ? "Calculated when the scan completes." : "Loading…"}</p>`;
  const row = (e, right) => html`<div class="list-row clickable" data-select="${e.id}">${entityIcon(e.type)}<div class="list-main"><div class="list-title">${e.label}</div></div><span class="muted small">${right}</span></div>`;
  return html`
    <p class="muted small">${d.communities.length} clusters · modularity ${d.modularity} · ${d.components} separate part${d.components === 1 ? "" : "s"}${d.betweenness_sampled ? " · brokerage estimated" : ""}</p>
    <div class="section-title">Key entities</div>
    ${d.key_entities.slice(0, 6).map((e) => row(e, `key ${e.key_score}`))}
    ${d.brokers.length ? html`<div class="section-title" style="margin-top:12px">Brokers ${tipText("Entities on the most shortest routes between others: they tie separate clusters together.")}</div>
      ${d.brokers.slice(0, 5).map((e) => row(e, `${Math.round(e.betweenness * 100)}%`))}` : ""}
    ${d.single_points_of_failure.length ? html`<div class="section-title" style="margin-top:12px">Single points of failure ${tipText("Removing one of these splits the graph apart.")}</div>
      ${d.single_points_of_failure.slice(0, 5).map((e) => row(e, `${e.degree} links`))}` : ""}
    <div class="section-title" style="margin-top:12px;display:flex;justify-content:space-between;align-items:center">Clusters
      <button class="btn sm" data-community-colours>${communityColours ? "Colour by type" : "Colour by cluster"}</button></div>
    ${d.communities.slice(0, 8).map((c) => html`<div class="list-row clickable" data-community="${c.id}">
      <span class="community-swatch" style="background:${graph.communityColor(c.id)}"></span>
      <div class="list-main"><div class="list-title">${c.anchor.label}</div><div class="muted small">${Object.entries(c.types).slice(0, 3).map(([t, n]) => `${n} ${t.replaceAll("_", " ")}`).join(" · ")}</div></div>
      <span class="pill">${c.size}</span></div>`)}`;
}

const tipText = (text) => html`<span class="muted small" title="${text}">ⓘ</span>`;

function togglePanel() {
  $("#workspace").classList.toggle("panel-collapsed");
  setTimeout(graph.resizeCanvas, 240);
}

function showPane(name) {
  $$(".panel-tab").forEach((t) => t.classList.toggle("active", t.dataset.pane === name));
  $$(".panel-pane").forEach((p) => { p.hidden = p.id !== `pane-${name}`; });
  $("#workspace").classList.remove("panel-collapsed");
}

function renderLegend() {
  const counts = graph.typeCounts();
  const types = Object.keys(ENTITY_TYPES).filter((t) => counts[t]);
  setHTML($("#legend"), html`${types.map((t) => html`
    <button class="legend-chip${graph.isTypeVisible(t) ? "" : " off"}" data-type="${t}" title="Show / hide ${typeInfo(t).label}">
      <span class="dot" style="background:${typeInfo(t).color}"></span>${typeInfo(t).label} <b>${counts[t]}</b>
    </button>`)}`);
}

function renderEmpty() {
  const el = $("#graph-empty");
  const { nodes } = graph.counts();
  if (!state.investigation) {
    el.hidden = false;
    setHTML(el, html`<div class="card" style="max-width:420px">${empty("graph", "No investigation open", "Start an investigation or open one from History to explore its intelligence graph.",
      html`<div class="hero-actions" style="justify-content:center"><button class="btn primary" data-action="newInvestigation">${ico("plus")}New investigation</button><button class="btn" data-action="loadDemo">Try the demo</button></div>`)}</div>`);
  } else if (!nodes) {
    el.hidden = false;
    setHTML(el, html`<div class="card" style="max-width:380px">${empty("search", isRunning() ? "Discovering…" : "Loading…", "Findings appear here live as Argus discovers them.")}</div>`);
  } else {
    el.hidden = true;
  }
}

// ------------------------------------------------------------------ details
function formatValue(v) {
  if (v === null || v === undefined || v === "") return "—";
  if (typeof v === "boolean") return v ? "Yes" : "No";
  if (Array.isArray(v)) return v.length ? v.map((x) => (typeof x === "object" ? JSON.stringify(x) : x)).join(", ") : "—";
  if (typeof v === "object") return Object.entries(v).map(([k, x]) => `${k}: ${x}`).join(" · ");
  return String(v);
}

function humanKey(k) {
  return k.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase());
}

async function loadPivots(entity) {
  pivotsFor = entity.id;
  pivots = [];
  if (String(entity.value).length < 2) return;
  try {
    const hits = await api.get(`/api/entities/search?q=${enc(entity.value)}&type=${enc(entity.type)}&limit=20`);
    if (pivotsFor !== entity.id) return;
    pivots = hits.filter((h) => h.investigation_id !== state.investigation?.id && h.entity.value === entity.value);
    renderDetails();
  } catch { /* optional */ }
}

function renderDetails() {
  const pane = $("#pane-details");
  const entity = selected && state.entities.get(selected);
  if (!entity) {
    setHTML(pane, html`${empty("info", "Select something on the graph", "Click any node to see what it is, how it connects to the rest of the investigation and which attack paths involve it.")}
      <div class="callout" style="margin-top:8px">${ico("info")}<span>Tip: hover a node to focus its connections, use the legend to hide types, and press <span class="kbd">/</span> to search.</span></div>`);
    return;
  }
  if (pivotsFor !== entity.id) loadPivots(entity);
  const info = typeInfo(entity.type);
  const meta = Object.entries(entity.metadata || {}).filter(([k, v]) => !HIDDEN_META.has(k) && v !== null && v !== "");
  const neighbours = graph.neighbors(entity.id).slice(0, 12);
  const involved = (state.paths?.paths || []).map((p, i) => ({ p, i })).filter(({ p }) => p.steps.some((s) => s.entity_id === entity.id));

  setHTML(pane, html`
    <div class="entity-head">
      ${entityIcon(entity.type, "entity-icon")}
      <div style="min-width:0"><div class="muted small">${info.label}</div><div class="entity-value">${entity.value}</div></div>
      ${["analyst", "admin"].includes(state.workspace?.role) ? html`<button class="btn sm ghost" data-to-case title="Add this to a case, with its details" style="margin-left:auto">${ico("plus")}Case</button>` : ""}
    </div>
    <dl class="kv">
      <dt>Confidence</dt><dd>${Math.round((entity.confidence ?? 1) * 100)}%</dd>
      <dt>Distance</dt><dd>${entity.depth === 0 ? "The target itself" : `${entity.depth} hop${entity.depth > 1 ? "s" : ""} from the target`}</dd>
      <dt>Found by</dt><dd>${(entity.metadata?.sources?.length > 1)
        ? html`${entity.metadata.sources.length} independent sources <span class="muted">(${entity.metadata.sources.map(humanSource).join(", ")})</span>`
        : humanSource(entity.source_module)}</dd>
      ${entity.metadata?.category ? html`<dt>Kind</dt><dd>${CATEGORY_LABEL[entity.metadata.category] || humanSource(entity.metadata.category)}</dd>` : ""}
    </dl>
    ${involved.length ? html`<div class="section"><div class="section-title">Part of ${involved.length} attack path${involved.length > 1 ? "s" : ""}</div>
      ${involved.map(({ p, i }) => html`<div class="list-row clickable" data-path="${i}">${severityPill(p.severity)}<div class="list-main"><div class="list-title">${p.title}</div></div></div>`)}</div>` : ""}
    ${intelBlocks(entity)}
    ${meta.length ? html`<div class="section"><div class="section-title">Details</div><dl class="kv">${meta.map(([k, v]) => html`<dt>${humanKey(k)}</dt><dd>${formatValue(v)}</dd>`)}</dl></div>` : ""}
    ${neighbours.length ? html`<div class="section"><div class="section-title">Connected to</div>
      ${neighbours.map((n) => html`<div class="list-row clickable" data-select="${n.id}">${entityIcon(n.type)}<div class="list-main"><div class="list-title">${n.label}</div><div class="list-sub">${typeInfo(n.type).label}</div></div></div>`)}</div>` : ""}
    <div class="section"><div class="section-title">Seen in other investigations</div>
      ${pivots.length ? pivots.map((h) => html`<div class="list-row clickable" data-open="${h.investigation_id}"><div class="list-main"><div class="list-title">${h.investigation_target}</div><div class="list-sub">${timeAgo(h.investigation_created_at)}</div></div>${ico("external")}</div>`)
        : html`<p class="muted small">Not seen in any other investigation.</p>`}</div>`);
}

/** Purpose-built panels for profile facts, software lifecycle and CVE threat intelligence. */
const CHAIN = { bitcoin: "Bitcoin", evm: "Ethereum-compatible", litecoin: "Litecoin", tron: "Tron", monero: "Monero" };
const amount = (n, asset) => `${Number(n).toLocaleString(undefined, { maximumFractionDigits: 8 })} ${asset}`;

/** Money in and out of a wallet, from the graph's SENT_FUNDS relations. */
function walletFlows(entity) {
  const rows = [];
  for (const r of state.relations.values()) {
    if (r.type !== "SENT_FUNDS" || (r.source_id !== entity.id && r.target_id !== entity.id)) continue;
    const out = r.source_id === entity.id;
    const other = state.entities.get(out ? r.target_id : r.source_id);
    if (other) rows.push({ out, other, md: r.metadata || {} });
  }
  return rows.sort((a, b) => (b.md.amount || 0) - (a.md.amount || 0));
}

function walletBlock(entity) {
  const md = entity.metadata || {};
  const chains = md.chains ? Object.entries(md.chains) : [];
  const flows = walletFlows(entity);
  const badges = [
    md.sanctions?.length ? html`<span class="pill critical">Sanctioned (OFAC)</span>` : "",
    md.sanctioned_counterparties?.length ? html`<span class="pill critical">Dealt with ${md.sanctioned_counterparties.length} sanctioned wallet${md.sanctioned_counterparties.length > 1 ? "s" : ""}</span>` : "",
    md.label ? html`<span class="pill accent">${md.label}</span>` : "",
    md.service ? html`<span class="pill warn" title="Exchanges, contracts and very busy wallets mix many people's money: Argus does not follow their counterparties">Service or exchange</span>` : "",
    md.coinjoins ? html`<span class="pill warn">Used CoinJoin ${md.coinjoins}×</span>` : "",
    md.ens ? html`<span class="pill">${md.ens}</span>` : "",
  ];
  const rows = md.chain === "bitcoin" ? [["Balance", md.balance != null && amount(md.balance, "BTC")], ["Received in total", md.total_received != null && amount(md.total_received, "BTC")],
    ["Sent in total", md.total_sent != null && amount(md.total_sent, "BTC")], ["Transactions", md.transactions], ["Address type", md.address_kind],
    ["Active", md.first_seen ? `${formatDay(md.first_seen)} – ${formatDay(md.last_seen)}${md.transactions_examined && md.transactions > md.transactions_examined ? ` (latest ${md.transactions_examined} examined)` : ""}` : null]] : [];
  return html`<div class="section"><div class="section-title">${CHAIN[md.chain] || "Crypto"} wallet</div>
    <div class="intel-badges">${badges}</div>
    ${md.sanctions?.length ? html`<div class="callout warn" style="margin:8px 0">${ico("alert")}<span>On the US Treasury sanctions list (OFAC SDN): <b>${md.sanctions.map((s) => s.name).join("; ")}</b> · ${[...new Set(md.sanctions.flatMap((s) => s.programs))].join(", ")}</span></div>` : ""}
    ${md.sanctioned_counterparties?.length ? html`<div class="callout warn" style="margin:8px 0">${ico("alert")}<span>Money moved between this wallet and sanctioned addresses: ${md.sanctioned_counterparties.map((s) => `${s.name} (${s.address.slice(0, 12)}…)`).join("; ")}</span></div>` : ""}
    <dl class="kv">${rows.filter(([, v]) => v !== null && v !== undefined && v !== false && v !== "").map(([k, v]) => html`<dt>${k}</dt><dd>${v}</dd>`)}
      ${chains.map(([name, c]) => html`<dt>${name[0].toUpperCase() + name.slice(1)}</dt><dd>${amount(c.balance, c.asset)} · ${c.transactions} transactions${c.token_transfers ? ` · ${c.token_transfers} token transfers` : ""}${c.contract ? " · smart contract" : ""}${c.first_seen ? ` · ${formatDay(c.first_seen)} – ${formatDay(c.last_seen)}` : ""}</dd>`)}
      ${md.checksum ? html`<dt>Checksum</dt><dd>${md.checksum === "verified" ? "Verified: a real, correctly typed address" : md.checksum}</dd>` : ""}</dl>
    ${flows.length ? html`<div class="section-title" style="margin-top:12px">Money in and out</div>
      ${flows.slice(0, 12).map((f) => html`<div class="list-row clickable" data-select="${f.other.id}"><span class="pill ${f.out ? "warn" : "ok"}">${f.out ? "Sent" : "Received"}</span>
        <div class="list-main"><div class="list-title">${amount(f.md.amount, f.md.asset)}</div><div class="list-sub">${f.out ? "to" : "from"} ${f.other.metadata?.label || f.other.value.slice(0, 16) + "…"} · ${f.md.transactions} tx${f.md.last ? ` · last ${formatDay(f.md.last)}` : ""}${f.md.chain && f.md.chain !== "bitcoin" ? ` · ${f.md.chain}` : ""}</div></div></div>`)}` : ""}
    ${md.explorer_url || chains[0] ? html`<p class="small" style="margin-top:8px"><a href="${md.explorer_url || chains[0][1].explorer_url}" target="_blank" rel="noopener noreferrer nofollow" referrerpolicy="no-referrer">Open in a block explorer ↗</a> <span class="muted">(leaves Argus: the explorer sees your connection)</span></p>` : ""}
  </div>`;
}

const ext = (url, text) => html`<a href="${url}" target="_blank" rel="noopener noreferrer nofollow" referrerpolicy="no-referrer">${text} ↗</a>`;
const kvRows = (rows) => html`<dl class="kv">${rows.filter(([, v]) => v !== undefined && v !== null && v !== "" && !(Array.isArray(v) && !v.length)).map(([k, v]) => html`<dt>${k}</dt><dd>${Array.isArray(v) ? v.join(", ") : v}</dd>`)}</dl>`;

/** Sanctions name matches and Offshore Leaks hits: shown on people and companies alike. */
function screeningBlock(md) {
  const out = [];
  if (md.sanction_matches?.length) {
    out.push(html`<div class="section"><div class="section-title">Sanctions lists</div>
      <div class="callout warn" style="margin-bottom:8px">${ico("alert")}<span>A similar name appears on a sanctions list. A similar name is not the same person: compare the dates of birth, nationality and other details before relying on it.</span></div>
      ${md.sanction_matches.map((m) => html`<div class="list-row"><span class="pill ${m.score >= 0.97 ? "critical" : "warn"}">${Math.round(m.score * 100)}%</span>
        <div class="list-main"><div class="list-title">${m.matched_name}${m.matched_name !== m.name ? html` <span class="muted">(alias of ${m.name})</span>` : ""}</div>
        <div class="list-sub">${m.list}${m.programs?.length ? ` · ${m.programs.join(", ")}` : ""}${Object.entries(m.details || {}).map(([k, v]) => ` · ${k}: ${v}`).join("")}</div>
        ${m.conflicts?.length ? html`<div class="small" style="margin-top:4px;color:var(--ok)">${ico("check")} Probably a different person: ${m.conflicts.join("; ")}</div>` : ""}</div></div>`)}</div>`);
  }
  if (md.matched_person) {
    out.push(html`<div class="section"><div class="section-title">Why this was linked</div>
      <p class="small">${md.matched_person.name}${md.matched_person.born ? ` (born ${md.matched_person.born})` : ""} is an officer here: <b>${md.matched_person.how}</b>.</p></div>`);
  }
  if (md.insolvency_notices?.length) {
    out.push(html`<div class="section"><div class="section-title">Insolvency notices (The Gazette)</div>
      <div class="callout warn" style="margin-bottom:8px">${ico("alert")}<span>${md.insolvency_notices_total > md.insolvency_notices.length ? `${md.insolvency_notices_total} notices; the latest ${md.insolvency_notices.length} below. ` : ""}Matched by ${md.insolvency_notice_match}.</span></div>
      ${md.insolvency_notices.map((n) => html`<div class="list-row"><span class="pill warn">${n.date ? formatDay(n.date) : ""}</span>
        <div class="list-main"><div class="list-title">${n.type}</div><div class="list-sub">${n.about ? `${n.about} · ` : ""}${ext(n.url, "Read the notice")}</div></div></div>`)}</div>`);
  }
  if (md.court_cases?.length) {
    out.push(html`<div class="section"><div class="section-title">US court cases (CourtListener)</div>
      ${md.court_case_match ? html`<div class="callout warn" style="margin-bottom:8px">${ico("info")}<span>Found by ${md.court_case_match}.</span></div>` : ""}
      ${md.court_cases.map((c) => html`<div class="list-row"><span class="pill">${c.filed ? formatDay(c.filed) : ""}</span>
        <div class="list-main"><div class="list-title">${c.name}</div><div class="list-sub">${[c.court, c.docket && `docket ${c.docket}`, c.nature].filter(Boolean).join(" · ")}${c.url ? html` · ${ext(c.url, "Open")}` : ""}</div></div></div>`)}
      ${md.court_cases_total > md.court_cases.length ? html`<p class="muted small">${md.court_cases_total} cases in all; the latest are shown.</p>` : ""}</div>`);
  }
  if (md.offshore_leaks?.length) {
    out.push(html`<div class="section"><div class="section-title">Offshore Leaks</div>
      ${md.offshore_leaks.map((h) => html`<div class="list-row"><span class="pill accent">${Math.round(h.score * 100)}%</span><div class="list-main"><div class="list-title">${h.name}</div><div class="list-sub">${ext(h.url, "Open the record")}</div></div></div>`)}
      <p class="muted small" style="margin-top:6px">Named in the ICIJ Offshore Leaks Database (Panama, Paradise, Pandora Papers…). Many offshore structures are legal: this is a lead, not evidence of wrongdoing. Data: ICIJ, Open Database Licence.</p></div>`);
  }
  return out;
}

/** Who owns an address block, and every range a network announces. */
function networkBlock(entity) {
  const md = entity.metadata || {};
  const out = [];
  const n = md.network;
  if (n) {
    out.push(html`<div class="section"><div class="section-title">Address block</div>
      ${n.shared_provider ? html`<p class="muted small">${ico("info")} A cloud or hosting provider's address, shared with many unrelated customers: it says little about who runs the site.</p>` : ""}
      ${kvRows([["Block", n.block], ["Registered to", n.registered_to], ["Network name", n.name], ["Announced as", n.announced_as],
        ["Country", n.country], ["Registry", n.registry], ["Abuse contact", n.abuse_contact]])}</div>`);
  }
  const r = md.network_ranges;
  if (r) {
    out.push(html`<div class="section"><div class="section-title">Network ${entity.value}</div>
      ${md.matched_by ? html`<div class="callout warn" style="margin-bottom:8px">${ico("alert")}<span>Found by matching the company's name in the registry: confirm it is the same company.</span></div>` : ""}
      ${r.shared_provider ? html`<p class="muted small">${r.note || "A provider's network: its ranges belong to its customers, so they are not listed."}</p>`
        : html`${kvRows([["Holder", r.holder], ["Address ranges", r.range_count], ["IPv4 addresses", r.addresses_v4?.toLocaleString()]])}
          <p class="muted small">Listed from the public routing registry, never scanned.</p>
          ${r.ranges_v4?.length || r.ranges_v6?.length ? html`<details><summary class="small">Ranges (${(r.ranges_v4?.length || 0) + (r.ranges_v6?.length || 0)})</summary>
            <div class="small" style="font-family:var(--mono, monospace);column-width:160px">${[...(r.ranges_v4 || []), ...(r.ranges_v6 || [])].map((x) => html`<div>${x}</div>`)}</div></details>` : ""}`}
    </div>`);
  }
  return out;
}

/** What a phone number itself says, and where the web mentions it (phones and emails). */
function phoneBlock(entity) {
  const md = entity.metadata || {};
  const p = md.phone;
  const out = [];
  if (entity.type === "phone" && (p || md.phone_valid === false)) {
    out.push(html`<div class="section"><div class="section-title">Phone number</div>
      ${md.phone_valid === false ? html`<div class="callout warn" style="margin-bottom:8px">${ico("alert")}<span>Not a real, allocated number range: possibly mistyped, invented, or reserved for TV and film.</span></div>` : ""}
      ${p?.concealing_line ? html`<div class="callout warn" style="margin-bottom:8px">${ico("alert")}<span>A ${p.line_type} line: often used to hide who is behind a number or where they are.</span></div>` : ""}
      ${p ? kvRows([["Line type", p.line_type], ["Country", p.country], ["Area", p.area], ["Original carrier", p.carrier ? `${p.carrier} (numbers can move to another network)` : null],
        ["Time zone", p.time_zones], ["Written as", p.written_as]]) : ""}</div>`);
  }
  const m = md.web_mentions;
  if (m) {
    const pages = [...state.entities.values()].filter((e) => e.metadata?.category === "mention" && [...state.relations.values()].some((r) => r.source_id === entity.id && r.target_id === e.id));
    out.push(html`<div class="section"><div class="section-title">On the web</div>
      <p class="muted small">${m.confirmed} page${m.confirmed === 1 ? "" : "s"} confirmed to mention it (of ${m.results} search results; near misses dropped).</p>
      ${pages.map((e) => html`<div class="list-row clickable" data-select="${e.id}"><span class="pill ${["nuisance report", "paste site"].includes(e.metadata.mention_kind) ? "warn" : ""}">${e.metadata.mention_kind}</span>
        <div class="list-main"><div class="list-title">${e.label}</div><div class="list-sub">${e.metadata.snippet || ""}</div></div></div>`)}</div>`);
  }
  if (entity.metadata?.category === "mention") {
    out.push(html`<div class="section"><div class="section-title">Mention</div>
      <p class="small">${entity.metadata.snippet || ""}</p>
      <p class="small">${/^https?:\/\//.test(entity.value) ? ext(entity.value, "Open the page") : ""} <span class="muted">(leaves Argus: the site sees your connection)</span></p></div>`);
  }
  return out;
}

/** What reading the whole website found: its pages, analytics IDs, and the sites it links to. */
function crawlBlock(md) {
  const crawl = md.crawl;
  if (!crawl) return [];
  const safe = (u) => /^https?:\/\//.test(u || "");
  return [html`<div class="section"><div class="section-title">Website read</div>
    ${kvRows([["Pages read", `${crawl.pages}${crawl.limit_reached ? " (the page limit was reached)" : ""}`],
      ["Skipped (robots.txt)", crawl.blocked_by_robots || null]])}
    ${md.tracking_ids?.length ? html`<div class="section-title" style="margin-top:10px">Analytics and advertising IDs</div>
      <p class="muted small">Sites that share one of these IDs are usually run by the same people.</p>
      ${md.tracking_ids.map((t) => html`<div class="list-row"><span class="pill accent">${t.product}</span><div class="list-main"><div class="list-title">${t.id}</div></div></div>`)}` : ""}
    ${md.links_to_sites?.length ? html`<div class="section-title" style="margin-top:10px">Links to other sites</div>
      <p class="muted small">Named only: Argus did not visit or scan them.</p>
      <div class="small">${md.links_to_sites.slice(0, 15).map((l) => `${l.site} (${l.links})`).join(" · ")}</div>` : ""}
    ${crawl.page_list?.length ? html`<details style="margin-top:10px"><summary class="small">Pages read (${crawl.page_list.length})</summary>
      ${crawl.page_list.map((p) => html`<div class="small">${safe(p.url) ? ext(p.url, p.title || p.url) : p.url}</div>`)}</details>` : ""}
  </div>`];
}

function companyBlock(md) {
  const out = [];
  if (md.company_number) {
    out.push(html`<div class="section"><div class="section-title">${md.registry || "Company register"}</div>
      ${md.insolvency?.length ? html`<div class="callout warn" style="margin-bottom:8px">${ico("alert")}<span>The register shows: <b>${md.insolvency.join(", ")}</b></span></div>` : ""}
      ${kvRows([["Registered name", md.legal_name], ["Number", md.company_number], ["Status", md.company_status], ["Incorporated", md.incorporated && formatDay(md.incorporated)],
        ["Dissolved", md.dissolved && formatDay(md.dissolved)], ["Type", md.company_type], ["Business (SIC)", md.sic_codes], ["Activity", md.industry || md.activity_code],
        ["Employees", md.employees], ["Former names", md.former_names], ["Website", md.website], ["Registered office", md.registered_address]])}
      ${md.register_url ? html`<p class="small" style="margin-top:6px">${ext(md.register_url, "Open on the register")}${md.opencorporates_url && md.opencorporates_url !== md.register_url ? html` · ${ext(md.opencorporates_url, "OpenCorporates")}` : ""}</p>` : ""}
      ${md.same_name_elsewhere?.length ? html`<p class="muted small" style="margin-top:6px">${ico("info")} Companies with the same name are also registered in: ${md.same_name_elsewhere.map((c) => c.registry || c.jurisdiction).join(", ")}. Check this is the one you mean.</p>` : ""}</div>`);
  } else if (md.registry_candidates?.length) {
    out.push(html`<div class="section"><div class="section-title">Possible register matches</div>
      <p class="muted small">No exact match in the company register; the closest names are below. Investigate one by its exact name.</p>
      ${md.registry_candidates.map((c) => html`<div class="list-row"><span class="pill">${Math.round(c.score * 100)}%</span><div class="list-main"><div class="list-title">${c.name}</div><div class="list-sub">${c.number} · ${c.status || ""}</div></div></div>`)}</div>`);
  }
  if (md.lei) {
    out.push(html`<div class="section"><div class="section-title">Legal Entity Identifier (GLEIF)</div>
      ${kvRows([["LEI", md.lei], ["Legal name", md.legal_name], ["Jurisdiction", md.jurisdiction], ["Status", md.entity_status], ["Registered address", md.registered_address], ["Head office", md.head_office], ["Local register ID", md.registered_as]])}
      ${md.lei_url ? html`<p class="small" style="margin-top:6px">${ext(md.lei_url, "Open in the LEI search")}</p>` : ""}</div>`);
  }
  if (md.sec_cik) {
    out.push(html`<div class="section"><div class="section-title">SEC filings (United States)</div>
      ${kvRows([["Name", md.sec_name], ["Ticker", md.ticker], ["CIK", md.sec_cik], ["Industry", md.sic], ["Incorporated in", md.state_of_incorporation], ["Business address", md.business_address], ["Former names", md.former_names],
        ["Recent filings", (md.recent_filings || []).slice(0, 6).map((f) => `${f.form} (${f.date})`)]])}
      <p class="small" style="margin-top:6px">${ext(md.sec_url, "Open on EDGAR")}</p></div>`);
  }
  return out;
}

function officerBlock(md) {
  const out = [];
  if (md.source_registry || md.born || md.appointments_total) {
    out.push(html`<div class="section"><div class="section-title">${md.source_registry || "Register"}</div>
      ${kvRows([["Role", md.role && md.role.replace(/-/g, " ")], ["Appointed", md.appointed && formatDay(md.appointed)], ["Resigned", md.resigned && formatDay(md.resigned)],
        ["Born (month)", md.born], ["Nationality", md.nationality], ["Occupation", md.occupation], ["Lives in", md.country_of_residence], ["Companies (all time)", md.appointments_total]])}</div>`);
  }
  if (md.officer_matches?.length) {
    out.push(html`<div class="section"><div class="section-title">Directors with this name</div>
      <p class="muted small">People on the register with this name. Several people can share a name: the month and year of birth help tell them apart. Their companies are shown as possible links.</p>
      ${md.officer_matches.map((m) => html`<div class="list-row"><span class="pill">${Math.round(m.score * 100)}%</span><div class="list-main"><div class="list-title">${m.name}</div><div class="list-sub">born ${m.born || "?"} · ${m.appointments ?? "?"} appointment(s) · ${m.address || ""}</div></div></div>`)}</div>`);
  }
  if (md.via_possible_match) out.push(html`<p class="small muted" style="margin:8px 0">${ico("info")} Linked through a possible match: ${md.via_possible_match}</p>`);
  return out;
}

const SEARCH_ENGINES = { shodan: "Shodan", fofa: "FOFA", zoomeye: "ZoomEye", censys: "Censys" };

// Fingerprint hubs: what the hash is, what sharing it suggests, and its facts.
const FINGERPRINTS = {
  favicon: {
    title: "Favicon fingerprint", served: "Served by",
    meaning: "The same icon often means the same operator or product, but default icons are shared by unrelated sites: treat it as a lead.",
    facts: (md) => [["Shodan hash", md.mmh3], ["MD5", md.md5], ["Type", `${md.content_type} · ${md.size} bytes`]],
  },
  jarm: {
    title: "TLS fingerprint (JARM)", served: "Shared by",
    meaning: "Servers with the same JARM answer TLS the same way: the same software, version and configuration. Unusual JARMs cluster C2 servers and phishing kits; common ones (big CDNs, stock web servers) say little.",
    facts: (md) => [["JARM", md.jarm], ["Probes answered", `${md.probes_answered} of 10`]],
  },
  hassh: {
    title: "SSH fingerprint (HASSH)", served: "Shared by",
    meaning: "The SSH server's algorithm list, hashed: the same software build and configuration. A stock OpenSSH is shared by millions of servers; a customised one is a strong link.",
    facts: (md) => [["HASSH", md.hassh_server], ["Algorithms", md.hassh_server_algorithms]],
  },
};

/** A fingerprint hub, or a certificate: who here shares it, and searches to find who else does. */
function fingerprintBlock(entity) {
  const md = entity.metadata;
  const kind = FINGERPRINTS[md.category];
  const hosts = graph.neighbors(entity.id).length;
  const searches = Object.entries(md.search_queries || {});
  if (!kind && !searches.length) return "";
  return html`<div class="section">${kind ? html`<div class="section-title">${kind.title}</div>
    <p class="small">${hosts > 1 ? html`<b>${kind.served} ${hosts} hosts in this graph.</b> ` : ""}${kind.meaning}</p>
    <dl class="kv">${kind.facts(md).map(([k, v]) => html`<dt>${k}</dt><dd><code style="word-break:break-all">${v}</code></dd>`)}</dl>` : ""}
    ${searches.length ? html`<div class="section-title" style="margin-top:10px">${kind ? "Find it elsewhere" : "Other hosts with this certificate"}</div>
    ${searches.map(([engine, q]) => html`<div class="list-row"><span class="pill accent">${SEARCH_ENGINES[engine] || engine}</span>
      <div class="list-main"><code class="small" style="word-break:break-all">${q}</code></div>
      <button class="btn sm" data-copy="${q}" title="Copy">Copy</button></div>`)}
    <p class="muted small" style="margin-top:6px">Paste into the search engine yourself: it sees the query and your connection, not the target.</p>` : ""}</div>`;
}

function intelBlocks(entity) {
  const md = entity.metadata || {};
  const blocks = [];
  if (entity.type === "organization") blocks.push(...companyBlock(md));
  if (entity.type === "person") blocks.push(...officerBlock(md));
  if (entity.type === "organization" || entity.type === "person") blocks.push(...screeningBlock(md));
  if (entity.type === "crypto_wallet") blocks.push(walletBlock(entity));
  if (entity.type === "domain" || entity.type === "subdomain") blocks.push(...crawlBlock(md));
  blocks.push(...phoneBlock(entity));
  blocks.push(...networkBlock(entity));
  if (FINGERPRINTS[md.category] || md.search_queries) blocks.push(fingerprintBlock(entity));
  if (md.found_on) blocks.push(html`<div class="section"><div class="section-title">Where it was found</div><p class="small">${/^https?:\/\//.test(md.found_on) ? ext(md.found_on, md.found_on) : md.found_on}</p></div>`);
  if (md.profile && Object.keys(md.profile).length) {
    const p = md.profile;
    const rows = [
      ["Name", p.display_name], ["Bio", p.bio], ["Location", p.location], ["Works at", p.company],
      ["Website", p.website], ["Joined", p.created_at && formatDay(p.created_at)],
      ["Followers", p.followers], ["Repositories", p.public_repos], ["Public email", p.public_email],
    ].filter(([, v]) => v !== undefined && v !== null && v !== "");
    const picture = p.avatar_url || md.avatar_url;
    blocks.push(html`<div class="section"><div class="section-title">Public profile${md.verified ? html` <span class="pill ok">Verified link</span>` : ""}</div>
      <dl class="kv">${rows.map(([k, v]) => html`<dt>${k}</dt><dd>${v}</dd>`)}</dl>
      ${picture ? html`<div style="margin-top:8px">${imageSearchLinks(picture)}</div>` : ""}
      <p class="muted small" style="margin-top:8px">Self-declared by the account owner; treat as a lead, not a fact.</p></div>`);
  }
  if (md.secrets?.length) {
    blocks.push(html`<div class="section"><div class="section-title">Leaked credentials</div>
      <div class="intel-badges"><span class="pill critical">${md.secrets.length} secret${md.secrets.length > 1 ? "s" : ""} in public code</span></div>
      ${md.secrets.map((s) => html`<div class="flag"><span class="dot" style="background:var(--sev-critical)"></span><span><b>${s.type}</b> <span class="mono muted">${s.preview}</span></span></div>`)}
      <dl class="kv" style="margin-top:8px">${md.repository ? html`<dt>Repository</dt><dd>${md.repository}</dd>` : ""}${md.path ? html`<dt>File</dt><dd>${md.path}</dd>` : ""}
        ${md.hostnames?.length ? html`<dt>Internal hosts</dt><dd>${md.hostnames.join(", ")}</dd>` : ""}</dl>
      <p class="muted small" style="margin-top:8px">Only a short preview is stored — never the secret itself. Rotate it: deleting the file does not remove it from Git history.</p></div>`);
  }
  if (md.category === "exposed_file") {
    blocks.push(html`<div class="section"><div class="section-title">Exposed file</div>
      <div class="intel-badges"><span class="pill critical">Live — confirmed by content</span></div>
      <dl class="kv"><dt>What</dt><dd>${md.file}</dd><dt>Evidence</dt><dd>${md.evidence}</dd></dl></div>`);
  }
  if (md.archive_url) {
    blocks.push(html`<div class="section"><div class="section-title">Web archive</div>
      <div class="intel-badges"><span class="pill medium">Archived copy — not verified as live</span></div>
      <dl class="kv"><dt>Captured</dt><dd>${formatDay(md.archived_on)}</dd>${md.archived_status ? html`<dt>Status then</dt><dd>HTTP ${md.archived_status}</dd>` : ""}</dl>
      <p class="small" style="margin-top:8px"><a href="${md.archive_url}" target="_blank" rel="noopener noreferrer nofollow" referrerpolicy="no-referrer">Open the archived copy ↗</a></p></div>`);
  }
  if (md.document) {
    const d = md.document;
    blocks.push(html`<div class="section"><div class="section-title">Hidden document metadata</div><dl class="kv">
      ${d.authors?.length ? html`<dt>Authors</dt><dd>${d.authors.join(", ")}</dd>` : ""}
      ${d.software?.length ? html`<dt>Made with</dt><dd>${d.software.join(", ")}</dd>` : ""}
      ${d.company ? html`<dt>Company</dt><dd>${d.company}</dd>` : ""}
      ${d.title ? html`<dt>Title</dt><dd>${d.title}</dd>` : ""}
      ${d.created ? html`<dt>Created</dt><dd>${formatDay(d.created)}</dd>` : ""}</dl>
      <p class="muted small" style="margin-top:8px">Author fields often hold internal account names — the login format attackers need for password spraying.</p></div>`);
  }
  if (md.category === "cloud_storage") {
    blocks.push(html`<div class="section"><div class="section-title">Cloud storage</div>
      <div class="intel-badges">${md.public_listing ? html`<span class="pill critical">Anyone can list files</span>` : html`<span class="pill">Exists — private</span>`}<span class="pill">${md.ownership}</span></div>
      <dl class="kv"><dt>Provider</dt><dd>${md.provider}</dd><dt>Bucket</dt><dd>${md.bucket}</dd>
        ${md.sample_keys?.length ? html`<dt>Sample files</dt><dd>${md.sample_keys.join(", ")}</dd>` : ""}</dl></div>`);
  }
  const recon = [];
  if (md.wayback) recon.push(["Web archive", md.wayback.urls_archived ? `${md.wayback.urls_archived} URLs since ${md.wayback.first_archived || "?"}${md.wayback.interesting && Object.keys(md.wayback.interesting).length ? ` · ${Object.entries(md.wayback.interesting).map(([k, v]) => `${v} ${(CATEGORY_LABEL[k] || k).toLowerCase()}`).join(", ")}` : ""}` : "Never archived"]);
  if (md.passive_dns) recon.push(["Passive DNS", `${md.passive_dns.hosts} hosts from ${md.passive_dns.sources_answered.length} sources`]);
  if (md.passive_sources) recon.push(["Seen in", md.passive_sources.join(", ")]);
  if (md.public_code) recon.push(["Public code", `${md.public_code.files} file(s)${md.public_code.files_with_secrets ? `, ${md.public_code.files_with_secrets} with secrets` : ""}`]);
  if (md.security_txt) recon.push(["security.txt", md.security_txt.present ? (md.security_txt.contacts || []).join(", ") || "Present" : "Missing — researchers have no official way to report issues"]);
  if (md.exposed_files) recon.push(["Exposed files", md.exposed_files.length ? md.exposed_files.join(", ") : "None found"]);
  if (md.cloud_storage) recon.push(["Cloud storage", `${md.cloud_storage.found} of ${md.cloud_storage.names_checked} likely names exist`]);
  if (md.platforms_checked) recon.push(["Sites checked", `${md.platforms_checked}${md.platforms_unreliable?.length ? ` · ${md.platforms_unreliable.length} ignored as unreliable (${md.platforms_unreliable.join(", ")})` : ""}`]);
  if (md.pgp_keys?.length) recon.push(["PGP keys", md.pgp_keys.map((k) => `${k.key_id} (${k.created || "?"}${k.revoked ? ", revoked" : ""})`).join(", ")]);
  if (recon.length) {
    blocks.push(html`<div class="section"><div class="section-title">Deep recon</div><dl class="kv">${recon.map(([k, v]) => html`<dt>${k}</dt><dd>${v}</dd>`)}</dl></div>`);
  }
  if (md.lifecycle) {
    const l = md.lifecycle;
    blocks.push(html`<div class="section"><div class="section-title">Support status</div>
      <div class="intel-badges">${l.eol ? html`<span class="pill critical">End of life</span>` : html`<span class="pill ok">Supported</span>`}
        ${l.outdated ? html`<span class="pill medium">Update available</span>` : ""}</div>
      <dl class="kv"><dt>Release line</dt><dd>${l.product} ${l.cycle}</dd>
        ${l.eol_date ? html`<dt>${l.eol ? "Support ended" : "Support ends"}</dt><dd>${formatDay(l.eol_date)}</dd>` : ""}
        ${l.latest ? html`<dt>Latest patch</dt><dd>${l.latest}</dd>` : ""}</dl>
      ${l.eol ? html`<p class="muted small" style="margin-top:8px">The vendor no longer ships security fixes for this version.</p>` : ""}</div>`);
  }
  if (md.intel) {
    const i = md.intel;
    const kev = i.kev;
    blocks.push(html`<div class="section"><div class="section-title">Threat intelligence</div>
      <div class="intel-badges">
        ${kev ? html`<span class="pill critical" data-tip="Listed in CISA's Known Exploited Vulnerabilities catalog">Exploited in the wild</span>` : html`<span class="pill">Not in CISA KEV</span>`}
        ${kev?.ransomware ? html`<span class="pill critical">Used by ransomware</span>` : ""}
        ${i.cvss_score != null ? html`<span class="pill ${i.cvss_score >= 9 ? "critical" : i.cvss_score >= 7 ? "high" : i.cvss_score >= 4 ? "medium" : "low"}">CVSS ${i.cvss_score}</span>` : ""}
      </div>
      <dl class="kv">
        ${i.epss != null ? html`<dt>Exploit chance</dt><dd>${(i.epss * 100).toFixed(1)}% in the next 30 days${i.epss_percentile != null ? html` <span class="muted">(top ${Math.max(0.1, (1 - i.epss_percentile) * 100).toFixed(1)}%)</span>` : ""}</dd>` : ""}
        ${kev ? html`<dt>Affects</dt><dd>${kev.product}</dd><dt>Added to KEV</dt><dd>${formatDay(kev.date_added)}</dd><dt>Required action</dt><dd>${kev.action}</dd>` : ""}
      </dl>
      ${i.description ? html`<p class="muted small" style="margin-top:8px">${i.description}</p>` : ""}
      <p class="small" style="margin-top:8px"><a href="https://nvd.nist.gov/vuln/detail/${entity.value.toUpperCase()}" target="_blank" rel="noopener noreferrer">View on NVD ↗</a></p></div>`);
  }
  return html`${blocks}`;
}

// ------------------------------------------------------------------ intel
function renderIntel() {
  const pane = $("#pane-intel");
  const a = state.analytics;
  const attack = state.attack;
  if (!state.investigation) { setHTML(pane, html`${empty("shield", "Nothing to analyse yet", "Open an investigation to see its threat intelligence.")}`); return; }
  setHTML(pane, html`
    <div class="section-title">MITRE ATT&amp;CK exposure</div>
    ${attack ? attack.techniques.length ? attack.techniques.map((t) => html`
      <div class="flag" style="display:block">
        <div style="display:flex;justify-content:space-between;gap:8px"><a href="${t.url}" target="_blank" rel="noopener noreferrer"><b>${t.id}</b></a><span class="pill">${t.count}</span></div>
        <div>${t.parent === t.id ? t.name : `${t.parent_name}: ${t.name}`}</div>
        <div class="muted small" style="margin-top:4px">🛡 ${t.defence}</div>
      </div>`) : html`<p class="muted small">No exposure mapped.</p>`
      : html`<p class="muted small">${isRunning() ? "Mapped when the scan completes." : "Loading…"}</p>`}
    <div class="section"><div class="section-title">Link analysis</div>${renderLinks()}</div>
    <div class="section"><div class="section-title">Most connected (pivots)</div>
      ${a?.top_pivots?.length ? a.top_pivots.map((h) => html`<div class="list-row clickable" data-select="${h.id}">${entityIcon(h.type)}<div class="list-main"><div class="list-title">${h.label}</div></div><span class="muted small">${h.connections} links</span></div>`)
        : html`<p class="muted small">—</p>`}</div>`);
}

function renderActivity() {
  const pane = $("#pane-activity");
  setHTML(pane, state.feed.length ? html`<div class="feed">${state.feed.map((f) => html`
      <div class="feed-item ${f.level}"><time>${f.at.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</time><span>${f.text}</span></div>`)}</div>`
    : html`${empty("history", "No activity yet", "Live discoveries, warnings and errors appear here during a scan.")}`);
}

export function selectEntity(id) { return graph.selectNode(id); }
