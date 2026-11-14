// Graph workspace: canvas, toolbar, legend, and a side panel that connects the selected
// entity to everything else - its facts, neighbours, attack paths and other investigations.

import { api, enc } from "../api.js";
import { empty, entityIcon, ico, severityPill } from "../components.js";
import { $, $$, formatDay, html, on, setHTML, timeAgo } from "../dom.js";
import { ENTITY_TYPES, typeInfo } from "../icons.js";
import * as graph from "../graph.js";
import { isRunning, on as onState, state } from "../state.js";

let actions;
let selected = null;
let pivotsFor = null;
let pivots = [];

// Keys shown in their own panels (or not at all) rather than the generic details list.
const HIDDEN_META = new Set([
  "full_record", "profile", "lifecycle", "intel", "verified", "sources", "document", "secrets", "hostnames",
  "wayback", "passive_dns", "passive_sources", "security_txt", "public_code", "cloud_storage", "pgp_keys",
  "sample_keys", "archive_url", "exposed_files", "platforms_unreliable", "platforms_checked", "platforms_unreachable",
  "public_listing", "evidence", "file", "category", "live", "repository", "path", "repository_owner", "bucket",
  "provider", "ownership", "archived_on", "archived_status",
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
    if (e.key !== "Enter") return;
    const id = graph.findNode(e.target.value);
    if (!id || !graph.selectNode(id)) actions.toast("No match in this graph");
  });

  on($(".panel-tabs"), "click", ".panel-tab", (_e, tab) => showPane(tab.dataset.pane));
  on($("#legend"), "click", ".legend-chip", (_e, chip) => {
    const visible = !graph.isTypeVisible(chip.dataset.type);
    graph.setTypeVisible(chip.dataset.type, visible);
    chip.classList.toggle("off", !visible);
  });
  on($("#pane-details"), "click", "[data-select]", (_e, el) => graph.selectNode(el.dataset.select));
  on($("#pane-intel"), "click", "[data-select]", (_e, el) => graph.selectNode(el.dataset.select));
  on($("#pane-details"), "click", "[data-open]", (_e, el) => actions.open(el.dataset.open));
  on($("#pane-details"), "click", "[data-path]", (_e, el) => actions.showPath(state.paths.paths[Number(el.dataset.path)]));
  on($("#graph-empty"), "click", "[data-action]", (_e, el) => actions[el.dataset.action]?.());

  onState("graph", () => { renderLegend(); renderEmpty(); });
  onState("reset", () => { selected = null; pivotsFor = null; renderAll(); });
  onState("investigation", renderEmpty);
  ["analytics", "attack", "paths"].forEach((e) => onState(e, () => { renderIntel(); renderDetails(); }));
  onState("feed", renderActivity);
  document.addEventListener("argus:theme", graph.applyTheme);
  renderAll();
}

function renderAll() {
  renderLegend();
  renderEmpty();
  renderDetails();
  renderIntel();
  renderActivity();
}

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
function intelBlocks(entity) {
  const md = entity.metadata || {};
  const blocks = [];
  if (md.profile && Object.keys(md.profile).length) {
    const p = md.profile;
    const rows = [
      ["Name", p.display_name], ["Bio", p.bio], ["Location", p.location], ["Works at", p.company],
      ["Website", p.website], ["Joined", p.created_at && formatDay(p.created_at)],
      ["Followers", p.followers], ["Repositories", p.public_repos], ["Public email", p.public_email],
    ].filter(([, v]) => v !== undefined && v !== null && v !== "");
    blocks.push(html`<div class="section"><div class="section-title">Public profile${md.verified ? html` <span class="pill ok">Verified link</span>` : ""}</div>
      <dl class="kv">${rows.map(([k, v]) => html`<dt>${k}</dt><dd>${v}</dd>`)}</dl>
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
