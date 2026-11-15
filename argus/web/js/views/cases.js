// Cases: an investigation as a body of work. Notes, people and links, a timeline, linked scans,
// and evidence preserved with fingerprints and a chain of custody.

import { api, download, enc, request } from "../api.js";
import { empty, ico } from "../components.js";
import { $, closeModal, confirmDialog, formatDate, html, on, openModal, setHTML, timeAgo, toast } from "../dom.js";
import { on as onState, state } from "../state.js";

let root;
let cases = null;
let current = null; // the open case (with items and captures)
let pendingEntity = null; // an entity sent from the graph, waiting for a case to be chosen
const thumbs = new Map(); // capture id -> object URL of its screenshot

const ENTITY_TYPES = ["person", "organisation", "username", "account", "email", "phone", "domain", "ip", "address",
  "location", "vehicle", "document", "other"];
const FROM_GRAPH = { person: "person", email: "email", username: "username", phone: "phone", domain: "domain",
  subdomain: "domain", ip_address: "ip", organization: "organisation", location: "location" };
const canEdit = () => ["analyst", "admin"].includes(state.workspace?.role);
const short = (digest) => `${digest.slice(0, 12)}…`;

// ---------------------------------------------------------------------------- list
function renderList() {
  setHTML(root, html`<div class="page">
    <div class="page-head">
      <div><h1>Cases</h1><p>One place per story or inquiry: notes, people and how they connect, a timeline, scans, and web pages preserved as evidence with fingerprints and a chain of custody.</p></div>
      ${canEdit() ? html`<div class="page-actions"><button class="btn primary" data-act="new-case">${ico("plus")}New case</button></div>` : ""}
    </div>
    ${!cases.length ? html`<div class="card">${empty("report", "No cases yet", "Open a case for each investigation. Capture pages before they change or disappear, and export a bundle anyone can verify.")}</div>`
      : html`<div class="case-grid">${cases.map((c) => html`<button class="card card-pad case-card" data-open-case="${c.id}">
        <div style="display:flex;justify-content:space-between;gap:8px;align-items:center"><b>${c.title}</b>
          <span>${c.restricted ? html`<span class="pill" title="Only the owner and members can open it">${ico("shield")}Restricted</span>` : ""} <span class="pill ${c.status === "open" ? "accent" : ""}">${c.status}</span></span></div>
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
  return events.length ? html`<ol class="timeline">${events.map((e) => html`<li><b>${e.title}</b> <span class="muted small">${formatDate(e.at)}</span>${e.sub ? html`<div class="muted small">${e.sub.slice(0, 200)}</div>` : ""}</li>`)}</ol>`
    : html`<p class="muted small">Events you add, and every capture, appear here in order.</p>`;
}

function evidenceCard(c) {
  const shot = c.files.find((f) => f.name === "screenshot.png" || /\.(png|jpe?g|gif|webp)$/i.test(f.name));
  return html`<div class="card card-pad evidence-card">
    ${shot ? html`<img class="evidence-thumb" data-thumb="${c.id}" data-file="${shot.name}" alt="Screenshot of ${c.title || c.url || "evidence"}">` : html`<div class="evidence-thumb none">${ico("report")}</div>`}
    <div style="min-width:0">
      <b>${c.title || c.url || "Evidence"}</b>
      ${c.url ? html`<div class="mono small" style="overflow-wrap:anywhere">${c.url}</div>` : ""}
      <div class="muted small">${c.kind === "web" ? "Captured" : "Added"} ${formatDate(c.captured_at)} by ${c.captured_by}${c.status ? ` · HTTP ${c.status}` : ""}</div>
      <div class="small" style="margin-top:4px"><span class="mono" title="SHA-256 of the capture manifest">${short(c.digest)}</span>
        ${c.timestamped ? html` <span class="pill ok" title="An RFC 3161 timestamp authority signed this digest">Timestamped</span>` : ""}</div>
      ${c.note ? html`<div class="small" style="margin-top:4px"><i>${c.note}</i></div>` : ""}
      ${c.warnings.length ? html`<div class="muted small" style="margin-top:4px">${ico("info")} ${c.warnings.join(" · ")}</div>` : ""}
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:8px">
        <button class="btn sm" data-act="verify" data-id="${c.id}">${ico("check")}Verify</button>
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
      <div style="display:flex;justify-content:space-between;gap:8px"><div><span class="pill">${p.data.type}</span> <b>${p.data.value}</b></div>
        ${canEdit() ? html`<button class="btn sm ghost icon" data-act="del-item" data-id="${p.id}" aria-label="Remove ${p.data.value}">${ico("trash")}</button>` : ""}</div>
      ${attrs.length ? html`<dl class="kv small" style="margin-top:6px">${attrs.map(([k, v]) => html`<dt>${k}</dt><dd>${v}</dd>`)}</dl>` : ""}
      ${p.body ? html`<p class="small" style="margin:6px 0 0">${p.body}</p>` : ""}
      ${mine.map((l) => html`<div class="small" style="margin-top:4px">→ ${l.data.label || "linked to"} <b>${byId[l.data.to].data.value}</b> <span class="muted">(${l.data.confidence})</span></div>`)}
    </div>`;
  })}`;
}

function renderCase() {
  const c = current;
  const notes = c.items.filter((i) => i.kind === "note");
  const scans = c.items.filter((i) => i.kind === "scan");
  setHTML(root, html`<div class="page">
    <div class="page-head">
      <div><a href="#" data-act="back" class="muted small">← All cases</a>
        <h1 style="margin-top:4px">${c.title} ${c.restricted ? html`<span class="pill" style="vertical-align:middle">${ico("shield")}Restricted</span>` : ""}</h1>
        <p>${c.purpose}</p>
        <p class="muted small">Opened by ${c.created_by} ${timeAgo(c.created_at)}${c.restricted ? ` · visible to ${[c.created_by, ...c.members].join(", ")}` : ""}${c.tags.length ? ` · ${c.tags.join(", ")}` : ""}</p></div>
      <div class="page-actions">
        ${canEdit() ? html`<button class="btn sm primary" data-act="capture">${ico("eye")}Capture a page</button>
          <button class="btn sm" data-act="upload">${ico("plus")}Add evidence file</button>
          <button class="btn sm" data-act="export">${ico("download")}Evidence bundle</button>
          <select class="select" data-act-select="status" aria-label="Case status" style="max-width:130px">${["open", "closed", "archived"].map((s) => html`<option value="${s}" ${c.status === s ? "selected" : ""}>${s}</option>`)}</select>` : ""}
      </div>
    </div>
    <div class="grid" style="grid-template-columns:minmax(0,1.4fr) minmax(0,1fr);gap:16px;align-items:start" id="case-layout">
      <div>
        <div class="card card-pad"><div class="card-head"><h2>Evidence</h2><span class="muted small">${c.captures.length}</span></div>
          ${c.captures.length ? c.captures.slice().reverse().map(evidenceCard) : html`<p class="muted small">Capture a page before it changes or disappears: Argus keeps the response, a full-page screenshot, the text and a fingerprint of each, and records who handled it.</p>`}</div>
        <div class="card card-pad" style="margin-top:16px"><div class="card-head"><h2>Notes</h2>${canEdit() ? html`<button class="btn sm ghost" data-act="note">${ico("plus")}Note</button>` : ""}</div>
          ${notes.length ? notes.slice().reverse().map((n) => html`<div class="note"><div style="display:flex;justify-content:space-between"><b>${n.title}</b>${canEdit() ? html`<button class="btn sm ghost icon" data-act="del-item" data-id="${n.id}" aria-label="Delete note">${ico("trash")}</button>` : ""}</div>
            <p style="white-space:pre-wrap;margin:4px 0">${n.body}</p><div class="muted small">${n.created_by} · ${timeAgo(n.created_at)}</div></div>`) : html`<p class="muted small">Leads, hypotheses, what was checked and what is still open.</p>`}</div>
      </div>
      <div>
        <div class="card card-pad"><div class="card-head"><h2>People & entities</h2>${canEdit() ? html`<span><button class="btn sm ghost" data-act="entity">${ico("plus")}Entity</button><button class="btn sm ghost" data-act="link">Link</button></span>` : ""}</div>${entities()}</div>
        <div class="card card-pad" style="margin-top:16px"><div class="card-head"><h2>Timeline</h2>${canEdit() ? html`<button class="btn sm ghost" data-act="event">${ico("plus")}Event</button>` : ""}</div>${timeline()}</div>
        <div class="card card-pad" style="margin-top:16px"><div class="card-head"><h2>Scans</h2>${canEdit() ? html`<button class="btn sm ghost" data-act="scan">${ico("plus")}Link a scan</button>` : ""}</div>
          ${scans.length ? scans.map((s) => html`<div class="list-row clickable" data-open-scan="${s.data.investigation_id}"><div class="list-main"><div class="list-title">${s.data.target}</div><div class="list-sub">linked ${timeAgo(s.created_at)}</div></div>${ico("external")}</div>`) : html`<p class="muted small">Link investigations that belong to this case.</p>`}</div>
      </div>
    </div>
  </div>`);
  loadThumbs();
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

async function openCase(id) {
  current = await api.get(`/api/cases/${enc(id)}`);
  location.hash = `#/cases`;
  renderCase();
}

export async function refresh() {
  if (!root) return;
  try {
    if (current) {
      current = await api.get(`/api/cases/${enc(current.id)}`);
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
      tags: $("#case-tags").value.split(",").map((t) => t.trim()).filter(Boolean), confirmed: true });
    closeModal("case-modal");
    await openCase(created.id);
  },
  "capture-form": async () => {
    const btn = $("#capture-form button[type=submit]");
    btn.disabled = true;
    btn.textContent = "Capturing…";
    try {
      const ev = await api.post(`/api/cases/${enc(current.id)}/captures`, { url: $("#capture-url").value.trim(), note: $("#capture-note").value.trim() });
      closeModal("capture-modal");
      toast(`Captured: fingerprint ${short(ev.digest)}${ev.timestamped ? " (timestamped)" : ""}`, "success", 6000);
    } finally {
      btn.disabled = false;
      btn.textContent = "Capture now";
    }
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
  "entity-form": async () => {
    await item("entity", { body: $("#entity-notes").value.trim(), data: { type: $("#entity-type").value, value: $("#entity-value").value.trim(), attributes: attributes($("#entity-attrs").value) } });
    closeModal("entity-modal");
  },
  "link-form": async () => {
    await item("link", { data: { from: $("#link-from").value, to: $("#link-to").value, label: $("#link-label").value.trim(), confidence: $("#link-confidence").value } });
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
  "tocase-form": async () => {
    const caseId = $("#tocase-select").value;
    await api.post(`/api/cases/${enc(caseId)}/items`, { kind: "entity", data: pendingEntity });
    closeModal("tocase-modal");
    toast("Added to the case", "success");
    pendingEntity = null;
  },
};

async function openDialog(act) {
  const ids = { capture: "capture-modal", upload: "upload-modal", entity: "entity-modal", link: "link-modal", event: "event-modal", note: "note-modal", scan: "scan-modal", "new-case": "case-modal" };
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
  }
  if (act === "entity") setHTML($("#entity-type"), html`${ENTITY_TYPES.map((t) => html`<option value="${t}">${t}</option>`)}`);
  if (act === "scan") {
    const recent = await api.get("/api/investigations?limit=50&status=completed");
    if (!recent.length) return toast("No completed scans yet", "error");
    setHTML($("#scan-select"), html`${recent.map((r) => html`<option value="${r.id}">${r.target} · ${formatDate(r.created_at)}</option>`)}`);
  }
  openModal(modal);
}

export function initCases(el, actions) {
  root = el;
  onState("workspace", () => { cases = null; current = null; });
  on(root, "click", "[data-open-case]", (_e, btn) => openCase(btn.dataset.openCase).catch((err) => toast(err.message, "error")));
  on(root, "click", "[data-open-scan]", (_e, row) => actions.open(row.dataset.openScan));
  root.addEventListener("change", async (e) => {
    if (e.target.dataset?.actSelect !== "status") return;
    try { await api.patch(`/api/cases/${enc(current.id)}`, { status: e.target.value }); toast(`Case ${e.target.value}`, "success"); } catch (err) { toast(err.message, "error"); }
  });
  on(root, "click", "[data-act]", async (e, btn) => {
    e.preventDefault();
    const { act, id } = btn.dataset;
    try {
      if (act === "back") { current = null; return refresh(); }
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
