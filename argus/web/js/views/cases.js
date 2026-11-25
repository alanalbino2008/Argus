// Cases: an investigation as a body of work. Notes, people and links, a timeline, linked scans,
// and evidence preserved with fingerprints and a chain of custody.

import { api, download, enc, request } from "../api.js";
import { initInspector, inspectable, openInspector } from "./inspector.js";
import { initCaseViews, renderMap, renderTimeline, teardownMap } from "./casemap.js";
import { initAnalyst, renderAnalyst } from "./analyst.js";
import { initPlaybooks, renderPlaybooks } from "./playbooks.js";
import { initChart, renderChart } from "./casechart.js";
import { openProfile } from "./profile.js";
import { openImageSearch, openPageHistory } from "./research.js";
import { empty, ico } from "../components.js";
import { $, closeModal, confirmDialog, formatDate, html, on, openModal, setHTML, timeAgo, toast } from "../dom.js";
import { on as onState, state } from "../state.js";
import { loadRoutes, routeOptions, routeWarning } from "../opsec.js";

let root;
let cases = null;
let current = null; // the open case (with items and captures)
let routes = []; // egress routes (names only), loaded with the case
let watches = []; // accounts this case watches
let caseTab = "overview"; // overview | timeline | map | playbooks | analyst
let watchable = null; // platforms that can be watched
let kinds = null; // relationship kinds, loaded once
let actionsRef = null;
let pendingEntity = null; // an entity sent from the graph, waiting for a case to be chosen
const thumbs = new Map(); // capture id -> object URL of its screenshot

const ENTITY_TYPES = ["person", "organisation", "username", "account", "email", "phone", "domain", "ip", "address",
  "location", "vehicle", "document", "wallet", "other"];
const FROM_GRAPH = { person: "person", email: "email", username: "username", phone: "phone", domain: "domain",
  subdomain: "domain", ip_address: "ip", organization: "organisation", location: "location", crypto_wallet: "wallet" };
const canEdit = () => ["analyst", "admin"].includes(state.workspace?.role);
const short = (digest) => `${digest.slice(0, 12)}…`;
const anonymous = (c) => c.opsec_mode === "anonymous";

function safetyPills(c) {
  return html`${anonymous(c) ? html`<span class="pill ok" title="Nothing in this case touches its subjects directly">${ico("shield")}Anonymous</span>` : ""}
    <span class="pill ${c.egress ? "" : "high"}" title="How captures and scans reach the internet">${c.egress ? `via ${c.egress}` : "Direct"}</span>`;
}

function showWarning(id, text) {
  const el = $(id);
  el.textContent = text;
  el.hidden = !text;
}

// ---------------------------------------------------------------------------- list
function renderList() {
  setHTML(root, html`<div class="page">
    <div class="page-head">
      <div><h1>Cases</h1><p>One place per story or inquiry: notes, people and how they connect, a timeline, scans, and web pages preserved as evidence with fingerprints and a chain of custody.</p></div>
      <div class="page-actions"><button class="btn" data-act="verify-report" title="Check that a case report is genuine and unaltered">${ico("check")}Verify a report</button>
      ${canEdit() ? html`<button class="btn primary" data-act="new-case">${ico("plus")}New case</button>` : ""}</div>
    </div>
    ${cases.some((c) => c.review_due) ? html`<div class="callout warn" style="margin-bottom:12px">${ico("history")}<span><b>${cases.filter((c) => c.review_due).length} case(s) haven't been touched in a long time.</b> Data protection law expects you to keep personal information only while you need it: close, export or delete the ones you've finished with.</span></div>` : ""}
    ${!cases.length ? html`<div class="card">${empty("report", "No cases yet", "Open a case for each investigation. Capture pages before they change or disappear, and export a bundle anyone can verify.")}</div>`
      : html`<div class="case-grid">${cases.map((c) => html`<button class="card card-pad case-card" data-open-case="${c.id}">
        <div style="display:flex;justify-content:space-between;gap:8px;align-items:center"><b>${c.title}</b>
          <span>${c.restricted ? html`<span class="pill" title="Only the owner and members can open it">${ico("shield")}Restricted</span>` : ""} ${anonymous(c) ? html`<span class="pill ok">Anonymous</span>` : ""} ${c.review_due ? html`<span class="pill warn" title="Untouched for a long time: keep it only if you still need it">Review</span>` : ""} <span class="pill ${c.status === "open" ? "accent" : ""}">${c.status}</span></span></div>
        <p class="muted small" style="margin:6px 0">${c.purpose}</p>
        <div class="muted small">${c.counts.entity || 0} people & entities · ${c.counts.evidence || 0} evidence · ${c.counts.note || 0} notes · updated ${timeAgo(c.updated_at)}</div>
      </button>`)}</div>`}
  </div>`);
}

// ---------------------------------------------------------------------------- one case
function timeline() {
  const events = [
    ...current.items.filter((i) => i.occurred_at).map((i) => ({ at: i.occurred_at, icon: "history", title: i.title, sub: i.body, kind: i.kind })),
    ...current.captures.map((c) => ({ at: c.captured_at, icon: "eye", title: `Captured: ${c.title || c.url || "evidence"}`, sub: c.url || c.note, kind: "capture" })),
  ].sort((a, b) => (a.at < b.at ? 1 : -1));
  return events.length ? html`<ol class="timeline">${events.map((e) => html`<li><b>${e.title}</b> <span class="muted small">${formatDate(e.at)}</span>${e.sub ? html`<div class="muted small" style="white-space:pre-line">${e.sub.slice(0, 600)}</div>` : ""}</li>`)}</ol>`
    : html`<p class="muted small">Events you add, and every capture, appear here in order.</p>`;
}

function evidenceCard(c) {
  const shot = c.files.find((f) => f.name === "screenshot.png" || /\.(png|jpe?g|gif|webp)$/i.test(f.name));
  return html`<div class="card card-pad evidence-card">
    ${shot ? html`<img class="evidence-thumb" data-thumb="${c.id}" data-file="${shot.name}" alt="Screenshot of ${c.title || c.url || "evidence"}">` : html`<div class="evidence-thumb none">${ico("report")}</div>`}
    <div style="min-width:0">
      <b>${c.title || c.url || "Evidence"}</b>
      ${c.url ? html`<div class="mono small" style="overflow-wrap:anywhere">${c.url}</div>` : ""}
      <div class="muted small">${c.kind === "web" ? "Captured" : "Added"} ${formatDate(c.captured_at)} by ${c.captured_by}${c.status ? ` · HTTP ${c.status}` : ""}${c.route ? ` · ${c.route.kind === "direct" ? "direct" : `via ${c.route.name}`}` : ""}</div>
      <div class="small" style="margin-top:4px"><span class="mono" title="SHA-256 of the capture manifest">${short(c.digest)}</span>
        ${c.timestamped ? html` <span class="pill ok" title="An RFC 3161 timestamp authority signed this digest">Timestamped</span>` : ""}</div>
      ${c.note ? html`<div class="small" style="margin-top:4px"><i>${c.note}</i></div>` : ""}
      ${c.warnings.length ? html`<div class="muted small" style="margin-top:4px">${ico("info")} ${c.warnings.join(" · ")}</div>` : ""}
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:8px">
        <button class="btn sm" data-act="verify" data-id="${c.id}">${ico("check")}Verify</button>
        ${c.files.filter(inspectable).map((f) => html`<button class="btn sm" data-act="inspect" data-id="${c.id}" data-file="${f.name}" title="Hidden details and signs of editing">${ico("search")}Inspect ${c.files.filter(inspectable).length > 1 ? f.name : ""}</button>`)}
        ${c.files.map((f) => html`<button class="btn sm ghost" data-act="file" data-id="${c.id}" data-file="${f.name}" title="${f.sha256}">${ico("download")}${f.name}</button>`)}
        ${c.timestamped ? html`<button class="btn sm ghost" data-act="tsr" data-id="${c.id}">${ico("download")}timestamp.tsr</button>` : ""}
      </div>
    </div>
  </div>`;
}

function entities() {
  const people = current.items.filter((i) => i.kind === "entity");
  const byId = Object.fromEntries(people.map((p) => [p.id, p]));
  const links = current.items.filter((i) => i.kind === "link" && byId[i.data.from] && byId[i.data.to]);
  if (!people.length) return html`<p class="muted small">Add people, accounts, addresses and other entities, or send them here from the graph.</p>`;
  return html`${people.map((p) => {
    const attrs = Object.entries(p.data.attributes || {});
    const mine = links.filter((l) => l.data.from === p.id);
    return html`<div class="entity-card">
      <div style="display:flex;justify-content:space-between;gap:8px"><div><span class="pill">${p.data.type}</span> <a href="#" data-act="profile" data-id="${p.id}" title="Open the full profile"><b>${p.data.value}</b></a>${p.data.protected ? html` <span class="pill warn" title="Not named on the link chart, left out of suggestions and profiling, never sent to the AI analyst">${ico("shield")}Protected</span>` : ""}</div>
        ${canEdit() ? html`<button class="btn sm ghost icon" data-act="del-item" data-id="${p.id}" aria-label="Remove ${p.data.value}">${ico("trash")}</button>` : ""}</div>
      ${attrs.length ? html`<dl class="kv small" style="margin-top:6px">${attrs.map(([k, v]) => html`<dt>${k}</dt><dd>${v}</dd>`)}</dl>` : ""}
      ${p.body ? html`<p class="small" style="margin:6px 0 0">${p.body}</p>` : ""}
      ${mine.map((l) => html`<div class="small" style="margin-top:4px">→ ${l.data.label || (kinds?.kinds.find((k) => k.kind === l.data.relation)?.label) || "linked to"} <b>${byId[l.data.to].data.value}</b> <span class="muted">(${l.data.confidence})</span></div>`)}
    </div>`;
  })}`;
}

const WATCH_STATUS = { active: ["ok", "Watching"], pending: ["", "First check due"], gone: ["critical", "Gone"], error: ["high", "Problem"] };
const EVERY = { 6: "every 6 hours", 24: "daily", 168: "weekly" };

function watchRow(w) {
  const [cls, label] = WATCH_STATUS[w.status] || ["", w.status];
  const s = w.snapshot || {};
  const sub = [w.last_checked_at ? `checked ${timeAgo(w.last_checked_at)}` : "not checked yet", EVERY[w.interval_hours],
    w.changes_count ? `${w.changes_count} change${w.changes_count === 1 ? "" : "s"}` : "no changes", w.capture_on_change ? "captures on change" : ""].filter(Boolean).join(" · ");
  return html`<div class="list-row" style="flex-wrap:wrap">
    <div class="list-main"><div class="list-title">${w.platform} <span class="muted">@${w.handle}</span></div>
      ${s.display_name || s.bio ? html`<div class="list-sub">${[s.display_name, s.bio].filter(Boolean).join(" — ")}</div>` : ""}
      <div class="list-sub">${sub}</div>
      ${w.message ? html`<div class="list-sub">${ico("info")} ${w.message}</div>` : ""}</div>
    <span class="pill ${cls}">${label}</span>
    <span style="display:flex;gap:4px">
      <button class="btn sm ghost" data-act="watch-history" data-id="${w.id}">History</button>
      ${canEdit() ? html`<button class="btn sm ghost" data-act="watch-check" data-id="${w.id}" title="Check now">${ico("check")}</button>
        <button class="btn sm ghost icon" data-act="watch-remove" data-id="${w.id}" aria-label="Stop watching">${ico("trash")}</button>` : ""}
    </span>
  </div>`;
}

function renderCase() {
  const c = current;
  const notes = c.items.filter((i) => i.kind === "note");
  const scans = c.items.filter((i) => i.kind === "scan");
  setHTML(root, html`<div class="page">
    <div class="page-head stacked">
      <div><a href="#" data-act="back" class="muted small">← All cases</a>
        <h1 style="margin-top:4px">${c.title} ${c.restricted ? html`<span class="pill" style="vertical-align:middle">${ico("shield")}Restricted</span>` : ""}
          ${c.legal_hold ? html`<span class="pill high" style="vertical-align:middle" title="${c.legal_hold_note || "On legal hold"}${c.legal_hold_by ? ` (by ${c.legal_hold_by})` : ""}">Legal hold</span>` : ""}</h1>
        <div style="display:flex;gap:6px;flex-wrap:wrap;margin:4px 0">${safetyPills(c)}</div>
        <p>${c.purpose}</p>
        <p class="muted small">Opened by ${c.created_by} ${timeAgo(c.created_at)}${c.restricted ? ` · visible to ${[c.created_by, ...c.members].join(", ")}` : ""}${c.tags.length ? ` · ${c.tags.join(", ")}` : ""}</p></div>
      <div class="page-actions">
        ${canEdit() ? html`<button class="btn sm primary" data-act="capture">${ico("eye")}Capture a page</button>
          <button class="btn sm" data-act="upload">${ico("plus")}Add evidence file</button>
          <button class="btn sm" data-act="page-history" title="Every version of a web page in the Internet Archive">${ico("history")}Page history</button>
          <button class="btn sm" data-act="image-search" title="Where else a picture appears on the web">${ico("search")}Reverse image search</button>
          <button class="btn sm" data-act="case-scan">${ico("search")}Scan for this case</button>
          <button class="btn sm" data-act="safety">${ico("shield")}Safety</button>
          <button class="btn sm" data-act="case-report" title="The whole case in one HTML file that opens offline in any browser">${ico("report")}Case report</button>
          <button class="btn sm" data-act="export">${ico("download")}Evidence bundle</button>
          ${state.workspace?.role === "admin" ? html`<button class="btn sm" data-act="legal-hold" title="${c.legal_hold ? "Allow this case to be deleted again" : "Protect this case from deletion, by hand or by retention"}">${ico("shield")}${c.legal_hold ? "Release hold" : "Legal hold"}</button>` : ""}
          <select class="select" data-act-select="status" aria-label="Case status" style="max-width:130px">${["open", "closed", "archived"].map((s) => html`<option value="${s}" ${c.status === s ? "selected" : ""}>${s}</option>`)}</select>` : ""}
      </div>
    </div>
    <div class="segmented" role="tablist" aria-label="Case views" style="margin-bottom:16px">${[["overview", "Overview"], ["timeline", "Timeline"], ["chart", "Link chart"], ["map", "Map"], ["playbooks", "Playbooks"], ["analyst", "AI analyst"]].map(([k, label]) => html`<button class="${caseTab === k ? "active" : ""}" role="tab" aria-selected="${caseTab === k}" data-case-tab="${k}">${label}</button>`)}</div>
    ${caseTab !== "overview" ? html`<div id="case-view"><p class="muted">Loading…</p></div>` : html`
    <div class="grid" style="grid-template-columns:minmax(0,1.4fr) minmax(0,1fr);gap:16px;align-items:start" id="case-layout">
      <div>
        <div class="card card-pad"><div class="card-head"><h2>Evidence</h2><span class="muted small">${c.captures.length}</span></div>
          ${c.captures.length ? c.captures.slice().reverse().map(evidenceCard) : html`<p class="muted small">Capture a page before it changes or disappears: Argus keeps the response, a full-page screenshot, the text and a fingerprint of each, and records who handled it.</p>`}</div>
        <div class="card card-pad" style="margin-top:16px"><div class="card-head"><h2>Notes</h2>${canEdit() ? html`<button class="btn sm ghost" data-act="note">${ico("plus")}Note</button>` : ""}</div>
          ${notes.length ? notes.slice().reverse().map((n) => html`<div class="note"><div style="display:flex;justify-content:space-between"><b>${n.title}</b>${canEdit() ? html`<button class="btn sm ghost icon" data-act="del-item" data-id="${n.id}" aria-label="Delete note">${ico("trash")}</button>` : ""}</div>
            <p style="white-space:pre-wrap;margin:4px 0">${n.body}</p><div class="muted small">${n.created_by} · ${timeAgo(n.created_at)}</div></div>`) : html`<p class="muted small">Leads, hypotheses, what was checked and what is still open.</p>`}</div>
      </div>
      <div>
        <div class="card card-pad"><div class="card-head"><h2>People & entities</h2>${canEdit() ? html`<span><button class="btn sm ghost" data-act="entity">${ico("plus")}Entity</button><button class="btn sm ghost" data-act="link">Link</button><button class="btn sm ghost" data-act="import-people" title="People and accounts found by this case's scans">From scans</button></span>` : ""}</div>${entities()}</div>
        <div class="card card-pad" style="margin-top:16px"><div class="card-head"><h2>Timeline</h2>${canEdit() ? html`<button class="btn sm ghost" data-act="event">${ico("plus")}Event</button>` : ""}</div>${timeline()}</div>
        <div class="card card-pad" style="margin-top:16px"><div class="card-head"><h2>Scans</h2>${canEdit() ? html`<button class="btn sm ghost" data-act="scan">${ico("plus")}Link a scan</button>` : ""}</div>
          ${scans.length ? scans.map((s) => html`<div class="list-row clickable" data-open-scan="${s.data.investigation_id}"><div class="list-main"><div class="list-title">${s.data.target}</div><div class="list-sub">linked ${timeAgo(s.created_at)}</div></div>${ico("external")}</div>`) : html`<p class="muted small">Link investigations that belong to this case.</p>`}</div>
        <div class="card card-pad" style="margin-top:16px" id="watch-card"><div class="card-head"><h2>Watched accounts</h2>${canEdit() ? html`<button class="btn sm ghost" data-act="watch">${ico("eye")}Watch</button>` : ""}</div>
          ${watches.length ? html`<div class="list">${watches.map(watchRow)}</div>` : html`<p class="muted small">Watch the subject's accounts: every change to their name, bio, links or picture lands on the timeline, and the profile can be captured as evidence each time.</p>`}</div>
      </div>
    </div>`}
  </div>`);
  if (caseTab === "overview") { teardownMap(); loadThumbs(); return; }
  const view = $("#case-view");
  if (caseTab !== "map") teardownMap();
  const render = { timeline: renderTimeline, map: renderMap, chart: renderChart, playbooks: renderPlaybooks, analyst: renderAnalyst }[caseTab];
  render(view, c).catch((err) => setHTML(view, html`<p class="error-text">${err.message}</p>`));
}

async function loadThumbs() {
  for (const img of root.querySelectorAll("img[data-thumb]")) {
    const key = `${img.dataset.thumb}/${img.dataset.file}`;
    if (!thumbs.has(key)) {
      try {
        const res = await request(`/api/evidence/${enc(img.dataset.thumb)}/files/${enc(img.dataset.file)}`, { raw: true });
        thumbs.set(key, URL.createObjectURL(await res.blob()));
      } catch { continue; }
    }
    img.src = thumbs.get(key);
  }
}

async function loadCase(id) {
  const [c, w] = await Promise.all([api.get(`/api/cases/${enc(id)}`), api.get(`/api/cases/${enc(id)}/watches`).catch(() => [])]);
  watches = w;
  return c;
}

/** Open a case from another page (e.g. a lookalike's case from Monitoring). */
export function showCase(id) {
  return openCase(id);
}

async function openCase(id) {
  caseTab = "overview";
  current = await loadCase(id);
  location.hash = `#/cases`;
  renderCase();
}

export async function refresh() {
  if (!root) return;
  try {
    if (current) {
      current = await loadCase(current.id);
      renderCase();
    } else {
      cases = await api.get("/api/cases");
      renderList();
    }
  } catch (err) {
    if (current) { current = null; return refresh(); }
    setHTML(root, html`<div class="page"><p class="error-text">${err.message}</p></div>`);
  }
}

/** From the graph: put an entity into a case (the dialog asks which). */
export async function addEntityToCase(entity, investigationId) {
  pendingEntity = {
    type: FROM_GRAPH[entity.type] || "other", value: entity.value,
    attributes: Object.fromEntries(Object.entries(entity.metadata || {}).filter(([, v]) => ["string", "number"].includes(typeof v)).slice(0, 20).map(([k, v]) => [k, String(v)])),
    source_investigation_id: investigationId, source_entity_id: entity.id,
  };
  const list = await api.get("/api/cases");
  const open = list.filter((c) => c.status === "open");
  if (!open.length) return toast("Open a case first (Cases → New case)", "error", 5000);
  setHTML($("#tocase-select"), html`${open.map((c) => html`<option value="${c.id}">${c.title}</option>`)}`);
  $("#tocase-value").textContent = `${pendingEntity.type}: ${pendingEntity.value}`;
  openModal("tocase-modal");
}

// ---------------------------------------------------------------------------- people from scans
let importOffer = null;
const TYPE_ORDER = ["person", "organisation", "account", "username", "email", "phone", "wallet", "location"];

async function loadImport() {
  const scanId = $("#import-scan").value;
  setHTML($("#import-list"), html`<p class="muted small">Loading…</p>`);
  importOffer = await api.get(`/api/cases/${enc(current.id)}/scan-people?investigation_id=${enc(scanId)}`);
  const fresh = importOffer.entities.filter((p) => !p.existing);
  if (!fresh.length) {
    setHTML($("#import-list"), html`<p class="muted small">Everything this scan found is already in the case.</p>`);
    return;
  }
  setHTML($("#import-list"), html`${TYPE_ORDER.filter((t) => fresh.some((p) => p.type === t)).map((t) => html`<h3 style="margin:10px 0 4px">${t}</h3>
    ${fresh.filter((p) => p.type === t).map((p) => html`<label class="list-row" style="cursor:pointer;align-items:flex-start"><input type="checkbox" value="${p.key}" data-import ${p.confidence >= 0.8 ? "checked" : ""}>
      <div class="list-main"><div class="list-title">${p.label}</div><div class="list-sub">${Math.round(p.confidence * 100)}% sure · found by ${p.found_by}${Object.keys(p.attributes).length ? ` · ${Object.entries(p.attributes).slice(0, 3).map(([k, v]) => `${k.replace(/_/g, " ")}: ${v}`).join(" · ")}` : ""}</div></div></label>`)}`)}`);
}

async function openImport() {
  const { scans } = await api.get(`/api/cases/${enc(current.id)}/scan-people`);
  if (!scans.length) return toast("Link or run a scan for this case first", "error");
  setHTML($("#import-scan"), html`${scans.map((s) => html`<option value="${s.investigation_id}">${s.target} (${s.status})</option>`)}`);
  openModal("import-modal");
  await loadImport();
}

// ---------------------------------------------------------------------------- dialogs
function item(kind, body) {
  return api.post(`/api/cases/${enc(current.id)}/items`, { kind, ...body });
}

function attributes(text) {
  return Object.fromEntries(text.split("\n").map((l) => l.split(/:(.*)/s)).filter(([k, v]) => k?.trim() && v?.trim()).map(([k, v]) => [k.trim(), v.trim()]));
}

const FORMS = {
  "case-form": async () => {
    if (!$("#case-confirmed").checked) throw new Error("Confirm there is a legitimate purpose for this investigation.");
    const created = await api.post("/api/cases", { title: $("#case-title").value.trim(), purpose: $("#case-purpose").value.trim(),
      restricted: $("#case-restricted").checked, members: $("#case-members").value.split(",").map((m) => m.trim()).filter(Boolean),
      tags: $("#case-tags").value.split(",").map((t) => t.trim()).filter(Boolean), egress: $("#case-egress").value,
      opsec_mode: $("#case-anonymous").checked ? "anonymous" : "standard", confirmed: true });
    closeModal("case-modal");
    await openCase(created.id);
  },
  "capture-form": async () => {
    const btn = $("#capture-form button[type=submit]");
    btn.disabled = true;
    btn.textContent = "Capturing…";
    try {
      const ev = await api.post(`/api/cases/${enc(current.id)}/captures`, { url: $("#capture-url").value.trim(), note: $("#capture-note").value.trim(), egress: $("#capture-egress").value || "direct" });
      closeModal("capture-modal");
      toast(`Captured: fingerprint ${short(ev.digest)}${ev.timestamped ? " (timestamped)" : ""}`, "success", 6000);
    } finally {
      btn.disabled = false;
      btn.textContent = "Capture now";
    }
  },
  "safety-form": async () => {
    await api.patch(`/api/cases/${enc(current.id)}`, { egress: $("#safety-egress").value, opsec_mode: $("#safety-anonymous").checked ? "anonymous" : "standard" });
    closeModal("safety-modal");
    toast("Safety settings saved (recorded in the audit log)", "success");
  },
  "upload-form": async () => {
    const file = $("#upload-file").files[0];
    if (!file) throw new Error("Choose a file.");
    const form = new FormData();
    form.append("file", file);
    form.append("note", $("#upload-note").value.trim());
    await request(`/api/cases/${enc(current.id)}/uploads`, { method: "POST", body: form });
    closeModal("upload-modal");
    toast("Evidence added with its fingerprint", "success");
  },
  "import-form": async () => {
    const keys = [...document.querySelectorAll("[data-import]:checked")].map((b) => b.value);
    if (!keys.length) throw new Error("Tick at least one to add.");
    const r = await api.post(`/api/cases/${enc(current.id)}/scan-people`, { investigation_id: $("#import-scan").value, keys, relationships: $("#import-rels").checked });
    closeModal("import-modal");
    toast(`Added ${r.entities} and ${r.relationships} relationship${r.relationships === 1 ? "" : "s"}`, "success");
  },
  "entity-form": async () => {
    await item("entity", { body: $("#entity-notes").value.trim(), data: { type: $("#entity-type").value, value: $("#entity-value").value.trim(), attributes: attributes($("#entity-attrs").value), ...($("#entity-protected").checked ? { protected: true } : {}) } });
    closeModal("entity-modal");
  },
  "link-form": async () => {
    await item("link", { data: { from: $("#link-from").value, to: $("#link-to").value, relation: $("#link-kind").value, label: $("#link-label").value.trim(),
      confidence: $("#link-confidence").value, ...($("#link-since").value.trim() ? { since: $("#link-since").value.trim() } : {}), ...($("#link-until").value.trim() ? { until: $("#link-until").value.trim() } : {}) } });
    closeModal("link-modal");
  },
  "event-form": async () => {
    const when = $("#event-at").value;
    if (!when) throw new Error("Give the event a date and time.");
    await item("event", { title: $("#event-title").value.trim(), body: $("#event-body").value.trim(), occurred_at: new Date(when).toISOString() });
    closeModal("event-modal");
  },
  "note-form": async () => {
    await item("note", { title: $("#note-title").value.trim() || "Note", body: $("#note-body").value.trim() });
    closeModal("note-modal");
  },
  "scan-form": async () => {
    await item("scan", { data: { investigation_id: $("#scan-select").value } });
    closeModal("scan-modal");
  },
  "watch-form": async () => {
    const handle = $("#watch-handle").value.trim();
    if (!handle) throw new Error("Enter the username to watch.");
    await api.post(`/api/cases/${enc(current.id)}/watches`, { platform: $("#watch-platform").value, handle,
      interval_hours: Number($("#watch-interval").value), capture_on_change: $("#watch-capture").checked });
    closeModal("watch-modal");
    toast("Watching: the first check runs within a minute", "success");
  },
  "tocase-form": async () => {
    const caseId = $("#tocase-select").value;
    await api.post(`/api/cases/${enc(caseId)}/items`, { kind: "entity", data: pendingEntity });
    closeModal("tocase-modal");
    toast("Added to the case", "success");
    pendingEntity = null;
  },
};

async function openDialog(act) {
  const ids = { watch: "watch-modal", safety: "safety-modal", capture: "capture-modal", upload: "upload-modal", entity: "entity-modal", link: "link-modal", event: "event-modal", note: "note-modal", scan: "scan-modal", "new-case": "case-modal" };
  const modal = ids[act];
  const form = $(`#${modal} form`);
  form.reset();
  form.querySelector(".error-text").textContent = "";
  if (act === "link") {
    const people = current.items.filter((i) => i.kind === "entity");
    if (people.length < 2) return toast("Add at least two entities to link", "error");
    const options = html`${people.map((p) => html`<option value="${p.id}">${p.data.type}: ${p.data.value}</option>`)}`;
    setHTML($("#link-from"), options);
    setHTML($("#link-to"), options);
    $("#link-to").selectedIndex = 1;
    kinds ??= await api.get("/api/relationship-kinds");
    const GROUP_NAMES = { family: "Family", work: "Work", business: "Business & money", social: "Social", shared: "Shared details", other: "Other" };
    setHTML($("#link-kind"), html`${kinds.groups.map((g) => html`<optgroup label="${GROUP_NAMES[g] || g}">${kinds.kinds.filter((k) => k.group === g).map((k) => html`<option value="${k.kind}" ${k.kind === "associate" ? "selected" : ""}>${k.label}</option>`)}</optgroup>`)}`);
  }
  if (["capture", "safety", "new-case"].includes(act)) routes = await loadRoutes();
  if (act === "watch") {
    watchable ||= await api.get("/api/watchable-platforms");
    setHTML($("#watch-platform"), html`<optgroup label="Full profile (name, bio, links, picture)">${watchable.detailed.map((p) => html`<option value="${p}">${p}</option>`)}</optgroup>
      <optgroup label="Whether the account exists">${watchable.presence.map((p) => html`<option value="${p}">${p}</option>`)}</optgroup>`);
    syncWatch();
  }
  if (act === "capture") {
    setHTML($("#capture-egress"), routeOptions(routes, current.egress, { anonymousOnly: anonymous(current) }));
    if (anonymous(current) && !routes.some((r) => r.anonymous)) return toast("This case is anonymous but no anonymous route is set up", "error");
    syncCapture();
  }
  if (act === "safety") {
    setHTML($("#safety-egress"), routeOptions(routes, current.egress));
    $("#safety-anonymous").checked = anonymous(current);
    syncSafety("safety");
  }
  if (act === "new-case") {
    setHTML($("#case-egress"), routeOptions(routes, routes.find((r) => r.anonymous)?.name || ""));
    syncSafety("case");
  }
  if (act === "entity") setHTML($("#entity-type"), html`${ENTITY_TYPES.map((t) => html`<option value="${t}">${t}</option>`)}`);
  if (act === "scan") {
    const recent = await api.get("/api/investigations?limit=50&status=completed");
    if (!recent.length) return toast("No completed scans yet", "error");
    setHTML($("#scan-select"), html`${recent.map((r) => html`<option value="${r.id}">${r.target} · ${formatDate(r.created_at)}</option>`)}`);
  }
  openModal(modal);
}

function syncWatch() {
  const full = watchable?.detailed.includes($("#watch-platform").value);
  $("#watch-detail").textContent = full ? "Read through the platform's official public API: every profile field is compared."
    : "On this site Argus can tell whether the account exists, deleted or not, but cannot read its profile.";
}

async function showHistory(id) {
  const w = watches.find((x) => x.id === id);
  const rows = await api.get(`/api/cases/${enc(current.id)}/watches/${enc(id)}/history`);
  $("#history-sub").textContent = w ? `${w.platform} @${w.handle} · ${w.profile_url}` : "";
  const fmt = (v) => (v == null || v === "" || (Array.isArray(v) && !v.length) ? "(none)" : Array.isArray(v) ? v.join(", ") : String(v));
  const change = (c) => c.field === "exists" ? html`<div>${c.after}</div>`
    : c.field === "avatar_hash" ? html`<div>Profile picture ${c.before && c.after ? "changed" : c.after ? "added" : "removed"}</div>`
    : html`<div><b>${c.label}:</b> <s class="muted">${fmt(c.before)}</s> → ${fmt(c.after)}</div>`;
  const facts = (r) => Object.entries(r.facts).filter(([k]) => !["exists", "avatar_hash"].includes(k)).map(([k, v]) => `${k.replace("_", " ")}: ${fmt(v)}`).join(" · ");
  setHTML($("#history-body"), rows.length ? html`${rows.map((r, i) => html`<div class="note" style="${i ? "border-top:1px solid var(--border);padding-top:12px;margin-top:12px" : ""}">
      <div style="display:flex;gap:8px;align-items:center"><b>${formatDate(r.taken_at)}</b>${r.changes.length ? "" : html`<span class="pill">first seen</span>`}${r.capture_id ? html`<span class="pill ok">${ico("report")}captured</span>` : ""}</div>
      <div class="small" style="margin-top:6px;display:grid;gap:4px">${r.changes.length ? r.changes.map(change) : html`<div class="muted">${facts(r) || (r.exists === false ? "not found" : "exists")}</div>`}</div>
    </div>`)}`
    : html`<p class="muted">Not checked yet.</p>`);
  openModal("history-modal");
}

function syncCapture() {
  showWarning("#capture-warning", routeWarning(routes, $("#capture-egress").value));
}

/** Anonymous needs an anonymous route: offer only those, and say why. */
function syncSafety(prefix) {
  const select = $(`#${prefix}-egress`);
  const anon = $(`#${prefix}-anonymous`).checked;
  const chosen = select.value;
  setHTML(select, routeOptions(routes, chosen, { anonymousOnly: anon }));
  if (anon && !routes.some((r) => r.anonymous)) {
    $(`#${prefix}-anonymous`).checked = false;
    setHTML(select, routeOptions(routes, chosen));
    toast("No anonymous route (such as Tor) is set up yet: ask your administrator", "error", 6000);
  }
  if (prefix === "safety") showWarning("#safety-warning", routeWarning(routes, select.value));
}

/** Open a scan on its graph and select one entity once the scan's graph has arrived. */
async function showEntity(actions, investigationId, entityId) {
  await actions.open(investigationId, { view: "graph" });
  const { selectEntity } = await import("./graphview.js");
  for (let waited = 0; waited < 20000; waited += 200) {
    if (state.investigation?.id === investigationId && state.entities.has(entityId)) {
      if (!selectEntity(entityId)) toast("That entity is no longer in this scan's graph");
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  toast("The scan is taking a while to open: find the entity with the search box");
}

/** Pick a case report file and check its signature (on this server, against this server's key). */
function verifyReport() {
  const input = document.createElement("input");
  input.type = "file";
  input.accept = ".html,text/html";
  input.addEventListener("change", async () => {
    const file = input.files?.[0];
    if (!file) return;
    const form = new FormData();
    form.append("file", file);
    try {
      const r = await api.post("/api/reports/verify", form);
      if (!r.valid) toast(`NOT genuine: ${r.problem}`, "error", 12000);
      else if (r.trusted) toast(`Genuine: signed by this Argus (key ${r.key_id}) and unaltered since`, "success", 10000);
      else toast(`Unaltered since it was signed, but by another key (${r.key_id}); this server's is ${r.this_server_key_id}`, "error", 12000);
    } catch (err) { toast(err.message, "error"); }
  });
  input.click();
}

export function initCases(el, actions) {
  root = el;
  actionsRef = actions;
  initInspector(() => refresh());
  initCaseViews(root);
  initAnalyst(root, () => refresh());
  initPlaybooks(root, () => refresh());
  initChart(root);
  on(root, "click", "[data-case-tab]", (_e, btn) => { caseTab = btn.dataset.caseTab; refresh(); });
  $("#capture-egress").addEventListener("change", syncCapture);
  $("#import-scan").addEventListener("change", () => loadImport().catch((err) => toast(err.message, "error")));
  $("#watch-platform").addEventListener("change", syncWatch);
  ["case", "safety"].forEach((prefix) => {
    $(`#${prefix}-anonymous`).addEventListener("change", () => syncSafety(prefix));
    $(`#${prefix}-egress`).addEventListener("change", () => prefix === "safety" && syncSafety(prefix));
  });
  onState("workspace", () => { cases = null; current = null; });
  on(root, "click", "[data-open-case]", (_e, btn) => openCase(btn.dataset.openCase).catch((err) => toast(err.message, "error")));
  on(root, "click", "[data-open-scan]", (e, row) => { e.preventDefault(); actions.open(row.dataset.openScan); });
  on(root, "click", "[data-open-entity]", (e, link) => { e.preventDefault(); showEntity(actions, link.dataset.inv, link.dataset.openEntity); });
  root.addEventListener("change", async (e) => {
    if (e.target.dataset?.actSelect !== "status") return;
    try { await api.patch(`/api/cases/${enc(current.id)}`, { status: e.target.value }); toast(`Case ${e.target.value}`, "success"); } catch (err) { toast(err.message, "error"); }
  });
  on(root, "click", "[data-act]", async (e, btn) => {
    e.preventDefault();
    const { act, id } = btn.dataset;
    try {
      if (act === "back") { current = null; return refresh(); }
      if (act === "watch-history") return showHistory(id);
      if (act === "inspect") return openInspector(current, id, btn.dataset.file);
      if (act === "profile") return openProfile(current, id);
      if (act === "import-people") return openImport();
      if (act === "page-history") return openPageHistory(current.id, () => refresh());
      if (act === "image-search") return openImageSearch(current.id);
      if (act === "watch-check") {
        btn.disabled = true;
        const r = await api.post(`/api/cases/${enc(current.id)}/watches/${enc(id)}/check`).finally(() => { btn.disabled = false; });
        const found = r.changes_count - (watches.find((w) => w.id === id)?.changes_count || 0);
        toast(r.status === "error" ? r.message : found > 0 ? `${found} change${found === 1 ? "" : "s"} recorded on the timeline` : r.message || "Checked: no changes",
          r.status === "error" ? "error" : "success", 6000);
        return refresh();
      }
      if (act === "watch-remove") {
        if (!(await confirmDialog({ title: "Stop watching this account?", message: "Its history is deleted; changes already on the timeline and evidence captured are kept.", confirm: "Stop watching", danger: true }))) return;
        await api.del(`/api/cases/${enc(current.id)}/watches/${enc(id)}`);
        return refresh();
      }
      if (act === "case-scan") return actionsRef.newInvestigation({ caseId: current.id, caseTitle: current.title, egress: current.egress, anonymous: anonymous(current) });
      if (act === "verify-report") return verifyReport();
      if (act === "case-report") return download(`/api/cases/${enc(current.id)}/report.html`, `argus-case-${current.id}-report.html`);
      if (act === "legal-hold") {
        const holding = !current.legal_hold;
        const ok = await confirmDialog(holding
          ? { title: "Put this case on legal hold?", message: "It can then not be deleted, by anyone or by the retention policy, until the hold is released.", confirm: "Hold" }
          : { title: "Release the legal hold?", message: "The case can then be deleted again, including by the retention policy.", confirm: "Release", danger: true });
        if (!ok) return;
        try {
          await api.put(`/api/cases/${enc(current.id)}/legal-hold`, { hold: holding });
          toast(holding ? "Case on legal hold" : "Legal hold released", "success");
        } catch (err) { toast(err.message, err.status === 202 ? "info" : "error", 6000); }
        return refresh();
      }
      if (act === "export") return download(`/api/cases/${enc(current.id)}/export`, `argus-case-${current.id}.zip`);
      if (act === "file") return download(`/api/evidence/${enc(id)}/files/${enc(btn.dataset.file)}?download=true`, btn.dataset.file);
      if (act === "tsr") return download(`/api/evidence/${enc(id)}/timestamp.tsr`, `${id}.tsr`);
      if (act === "verify") {
        const r = await api.post(`/api/evidence/${enc(id)}/verify`);
        return r.intact ? toast(`Intact: ${r.files} file(s) match their fingerprints and the custody chain is unbroken`, "success", 6000)
          : toast(`NOT intact: ${r.problems.join("; ")}`, "error", 10000);
      }
      if (act === "del-item") {
        if (!(await confirmDialog({ title: "Remove this item?", message: "Links to it are removed too. This is recorded in the audit log.", confirm: "Remove", danger: true }))) return;
        await api.del(`/api/cases/${enc(current.id)}/items/${enc(id)}`);
        return refresh();
      }
      return openDialog(act);
    } catch (err) {
      toast(err.message, "error");
    }
  });
  Object.entries(FORMS).forEach(([formId, submit]) => {
    $(`#${formId}`).addEventListener("submit", async (e) => {
      e.preventDefault();
      const error = e.target.querySelector(".error-text");
      error.textContent = "";
      try {
        await submit();
        if (formId !== "case-form" && formId !== "tocase-form") await refresh();
      } catch (err) {
        error.textContent = err.message;
      }
    });
  });
}
