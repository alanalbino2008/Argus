// Inspecting an evidence file: hidden metadata, signs of editing, where and when a photo was taken.

import { api, download, enc, request } from "../api.js";
import { ico } from "../components.js";
import { $, formatDate, html, on, openModal, setHTML, toast } from "../dom.js";
import { state } from "../state.js";

const KINDS = /\.(jpe?g|png|gif|webp|tiff?|heic|pdf|docx|xlsx|pptx)$/i;
const OWN = new Set(["screenshot.png", "rendered.html", "page.html", "text.txt", "headers.json"]); // made by Argus
let ctx = null; // { caseObj, captureId, file, report }
let elaUrl = null;
let onChange = () => {};

/** Files worth inspecting: photos and documents, not the files Argus made itself. */
export const inspectable = (f) => !OWN.has(f.name) && (KINDS.test(f.name) || /^(image\/|application\/pdf)/.test(f.media_type || ""));
const canEdit = () => ["analyst", "admin"].includes(state.workspace?.role);
const LEVEL = { warning: "warn", notice: "", info: "" };

export function initInspector(changed) {
  onChange = changed;
  const body = $("#inspect-body");
  on(body, "click", "[data-tool]", async (e, btn) => {
    e.preventDefault();
    try { await TOOLS[btn.dataset.tool](btn); } catch (err) { toast(err.message, "error"); }
  });
  on(body, "submit", "#sun-form", async (e) => {
    e.preventDefault();
    try { await sunCheck(); } catch (err) { toast(err.message, "error"); }
  });
}

export async function openInspector(caseObj, captureId, file) {
  if (elaUrl) URL.revokeObjectURL(elaUrl);
  elaUrl = null;
  ctx = { caseObj, captureId, file, report: null };
  $("#inspect-modal-h").textContent = `Inspect ${file}`;
  setHTML($("#inspect-body"), html`<p class="muted">Reading the file…</p>`);
  openModal("inspect-modal");
  ctx.report = await api.get(`/api/evidence/${enc(captureId)}/files/${enc(file)}/inspect`);
  render();
}

const base = () => `/api/evidence/${enc(ctx.captureId)}/files/${enc(ctx.file)}`;

function render() {
  const r = ctx.report;
  const gps = r.gps;
  const taken = r.taken_at;
  setHTML($("#inspect-body"), html`
    ${r.findings.length ? html`<div style="display:grid;gap:8px">${r.findings.map((f) => html`<div class="callout ${LEVEL[f.level]}">${ico(f.level === "warning" ? "alert" : "info")}<span>${f.text}</span></div>`)}</div>`
      : html`<div class="callout">${ico("info")}<span>Nothing unusual found.</span></div>`}
    ${gps ? html`<div class="inspect-section"><h3>Where it was taken</h3>
      <dl class="kv"><dt>Position</dt><dd class="mono">${gps.latitude}, ${gps.longitude}</dd>
        ${gps.altitude_m != null ? html`<dt>Altitude</dt><dd>${gps.altitude_m} m</dd>` : ""}
        ${gps.camera_facing != null ? html`<dt>Camera facing</dt><dd>${gps.camera_facing}°</dd>` : ""}
        ${gps.time_utc ? html`<dt>GPS time</dt><dd>${formatDate(gps.time_utc)} (UTC ${gps.time_utc.slice(11, 16)})</dd>` : ""}</dl>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:8px">
        <a class="btn sm" href="${gps.map_url}" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer" title="Leaves Argus: OpenStreetMap sees your address and the position">${ico("external")}Open map</a>
        ${canEdit() ? html`<button class="btn sm" data-tool="place">${ico("plus")}Add place to case</button>` : ""}
      </div></div>` : ""}
    ${taken ? html`<div class="inspect-section"><h3>When it was taken</h3>
      <p class="small">${cameraTime(taken)}</p>
      ${canEdit() ? html`<button class="btn sm" data-tool="when">${ico("plus")}Add to the case timeline</button>` : ""}</div>` : ""}
    ${r.kind === "image" ? sunSection(r) : ""}
    ${r.kind === "image" ? html`<div class="inspect-section"><h3>Image tools</h3>
      <div style="display:flex;gap:6px;flex-wrap:wrap">
        ${r.error_level ? html`<button class="btn sm" data-tool="ela">${ico("eye")}Error level analysis</button>` : ""}
        ${r.cleanable ? html`<button class="btn sm" data-tool="clean">${ico("download")}Copy without metadata</button>` : ""}
      </div>
      <div id="ela-area"></div>
      ${r.reverse_search.length ? html`<p class="small" style="margin:12px 0 6px"><b>Reverse image search</b>: find where else it appears, and the earliest copy.</p>
        <div style="display:flex;gap:6px;flex-wrap:wrap">${r.reverse_search.map((e) => html`<a class="btn sm ghost" href="${e.url}" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer">${ico("external")}${e.engine}</a>`)}</div>
        <p class="muted small" style="margin-top:6px">${r.reverse_search[0].mode === "upload" ? "This image isn't public, so each search engine opens its upload page: upload the copy without metadata, never the original." : "Searches by the image's public address."} These sites leave Argus: they see the image and your own connection.</p>` : ""}
    </div>` : ""}
    <div class="inspect-section"><h3>Everything the file contains</h3>
      <div class="inspect-grid">${r.groups.map((g) => html`<div class="card card-pad"><div class="section-title">${g.group}</div>
        <dl class="kv">${g.fields.map((f) => html`<dt>${f.label}</dt><dd class="${/hash|SHA|MD5|ID/.test(f.label) ? "mono small" : ""}">${f.value}</dd>`)}</dl></div>`)}</div></div>`);
}

/** The time as the camera wrote it (its own clock and zone), not converted to the viewer's. */
function cameraTime(t) {
  const [day, time] = t.value.slice(0, 16).split("T");
  const when = new Date(`${day}T00:00:00Z`).toLocaleDateString(undefined, { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" });
  return `${when}, ${time} ${t.time_zone_known ? `(UTC${t.value.slice(19) || "+00:00"})` : "(camera clock; time zone unknown)"}`;
}

function sunSection(r) {
  const s = r.sun;
  const gps = r.gps || {};
  const when = r.gps?.time_utc || r.taken_at?.value || "";
  const local = when ? when.slice(0, 16) : "";
  const offset = when.length > 19 ? when.slice(19) || "+00:00" : "+00:00";
  return html`<div class="inspect-section"><h3>Check the shadows</h3>
    ${s ? html`<div class="callout safe">${ico("sun")}<span>${s.summary} Compare with the shadows in the photo: if they disagree, the time or the place is wrong.</span></div>`
      : html`<p class="muted small">Enter where and when the photo claims to be from, and compare the shadows in it.</p>`}
    <form id="sun-form" class="sun-form" style="margin-top:8px">
      <label class="small">Latitude<input class="input" id="sun-lat" type="number" step="any" min="-90" max="90" value="${gps.latitude ?? ""}" required></label>
      <label class="small">Longitude<input class="input" id="sun-lon" type="number" step="any" min="-180" max="180" value="${gps.longitude ?? ""}" required></label>
      <label class="small">Date and time<input class="input" id="sun-at" type="datetime-local" value="${local}" required></label>
      <label class="small">UTC offset<input class="input mono" id="sun-offset" value="${offset}" pattern="(\\+|-)\\d\\d:\\d\\d" required></label>
      <button class="btn sm" type="submit">${ico("search")}Where was the sun?</button>
    </form>
    <p class="small" id="sun-result" style="margin-top:6px"></p></div>`;
}

async function sunCheck() {
  const at = `${$("#sun-at").value}:00${$("#sun-offset").value}`;
  const params = new URLSearchParams({ lat: $("#sun-lat").value, lon: $("#sun-lon").value, at });
  const s = await api.get(`/api/tools/sun?${params}`);
  $("#sun-result").textContent = s.summary;
}

const TOOLS = {
  async ela(btn) {
    btn.disabled = true;
    try {
      const res = await request(`${base()}/error-level`, { raw: true });
      if (elaUrl) URL.revokeObjectURL(elaUrl);
      elaUrl = URL.createObjectURL(await res.blob());
      setHTML($("#ela-area"), html`<div style="margin-top:10px"><img class="ela-view" src="${elaUrl}" alt="Error level analysis">
        <p class="muted small" style="margin-top:6px">Bright areas re-compressed differently from the rest. Pasted or edited areas often stand out, but so do sharp edges, text and fine detail: use it to know where to look, never as proof.</p></div>`);
    } finally {
      btn.disabled = false;
    }
  },
  async clean() {
    const stem = ctx.file.replace(/\.[^.]+$/, "");
    await download(`${base()}/clean`, `${stem}-clean.${ctx.report.type === "image/png" ? "png" : ctx.report.type === "image/webp" ? "webp" : ctx.report.type === "image/jpeg" ? "jpg" : "png"}`);
    toast("Saved a copy without metadata: the evidence itself is unchanged", "success");
  },
  async place() {
    const g = ctx.report.gps;
    await api.post(`/api/cases/${enc(ctx.caseObj.id)}/items`, { kind: "entity", body: `From the location data in ${ctx.file}`,
      data: { type: "location", value: `${g.latitude}, ${g.longitude}`, attributes: { source: ctx.file, map: g.map_url, ...(g.time_utc ? { "GPS time (UTC)": g.time_utc } : {}) } } });
    toast("Place added to the case", "success");
    onChange();
  },
  async when() {
    const t = ctx.report.taken_at;
    const at = t.time_zone_known ? t.value : `${t.value}Z`;
    await api.post(`/api/cases/${enc(ctx.caseObj.id)}/items`, { kind: "event", title: `Photo taken: ${ctx.file}`,
      body: t.time_zone_known ? "From the camera's date" : "From the camera's date (its time zone is unknown: shown as UTC)", occurred_at: new Date(at).toISOString() });
    toast("Added to the timeline", "success");
    onChange();
  },
};
