// A case in time and space: the timeline (with an activity chart) and the map.
//
// The map is drawn here, without a mapping library: map images come from Argus's own server
// (/api/map/tiles), fetched with the investigator's credentials, so the browser never contacts a
// map provider and nothing from another site runs on the page.

import { api, download, enc, request } from "../api.js";
import { ico } from "../components.js";
import { $, formatDate, html, on, setHTML, toast } from "../dom.js";
import { state } from "../state.js";

const TILE = 256;
const KIND = {
  event: ["accent", "Event"], account: ["warn", "Account change"], capture: ["ok", "Capture"], upload: ["ok", "Evidence added"],
  scan: ["", "Scan"], photo: ["", "Photo taken"], fact: ["accent", "Found in a scan"], change: ["warn", "Change between scans"],
  person: ["accent", "Person (People tab)"],
};
// Facts keep the precision their source gave: a year is not "1 January at 00:00".
const PRECISION = { year: "year only", month: "month only", day: "date" };
const canEdit = () => ["analyst", "admin"].includes(state.workspace?.role);

// ---------------------------------------------------------------------------- timeline
let tl = { entries: [], hidden: new Set(), bucket: null };

export async function renderTimeline(el, caseObj) {
  tl = { entries: await api.get(`/api/cases/${enc(caseObj.id)}/timeline`), hidden: tl.hidden, bucket: null, caseObj };
  el.dataset.mode = "timeline";
  drawTimeline(el);
}

// Buckets cover the whole span, empty ones included, so the chart's spacing is true to time.
function scaleFor(spanDays) {
  return spanDays > 365 * 5 ? "year" : spanDays > 120 ? "month" : "day";
}

function bucketOf(iso, scale) {
  return scale === "year" ? iso.slice(0, 4) : scale === "month" ? iso.slice(0, 7) : iso.slice(0, 10);
}

function allBuckets(first, last, scale) {
  const keys = [];
  const d = new Date(`${bucketOf(first, "day")}T00:00:00Z`);
  const end = bucketOf(last, scale);
  for (let guard = 0; guard < 2000; guard++) {
    const key = bucketOf(d.toISOString(), scale);
    if (keys.at(-1) !== key) keys.push(key);
    if (key >= end) break;
    if (scale === "year") d.setUTCFullYear(d.getUTCFullYear() + 1, 0, 1);
    else if (scale === "month") d.setUTCMonth(d.getUTCMonth() + 1, 1);
    else d.setUTCDate(d.getUTCDate() + 1);
  }
  return keys;
}

function drawTimeline(el) {
  const all = tl.entries;
  if (!all.length) {
    setHTML(el, html`<div class="card card-pad"><p class="muted">Nothing dated yet. Events you add, captures, account changes, linked scans and the dates inside photos all appear here.</p></div>`);
    return;
  }
  const counts = Object.fromEntries(Object.keys(KIND).map((k) => [k, all.filter((e) => e.kind === k).length]));
  const span = (Date.parse(all.at(-1).at) - Date.parse(all[0].at)) / 86400000;
  const scale = scaleFor(span);
  const shown = all.filter((e) => !tl.hidden.has(e.kind));
  const buckets = new Map();
  for (const e of shown) buckets.set(bucketOf(e.at, scale), (buckets.get(bucketOf(e.at, scale)) || 0) + 1);
  const keys = allBuckets(all[0].at, all.at(-1).at, scale);
  const peak = Math.max(1, ...buckets.values());
  const visible = tl.bucket ? shown.filter((e) => bucketOf(e.at, scale) === tl.bucket) : shown;
  const groups = new Map();
  for (const e of [...visible].reverse()) {
    const day = e.at.slice(0, 10);
    if (!groups.has(day)) groups.set(day, []);
    groups.get(day).push(e);
  }
  setHTML(el, html`<div class="card card-pad">
    <div class="card-head wrap"><div><h2>Timeline</h2><p class="muted small">${all.length} dated entries, ${formatDate(all[0].at)} to ${formatDate(all.at(-1).at)}. Times are shown in your time zone.</p></div>
      <button class="btn sm" data-tl="csv">${ico("download")}Spreadsheet (CSV)</button></div>
    <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px">${Object.entries(KIND).filter(([k]) => counts[k]).map(([k, [cls, label]]) => html`<button class="pill ${tl.hidden.has(k) ? "" : cls}" data-tl-kind="${k}" aria-pressed="${!tl.hidden.has(k)}" style="cursor:pointer;${tl.hidden.has(k) ? "opacity:.45;text-decoration:line-through" : ""}">${label} · ${counts[k]}</button>`)}</div>
    <div class="tl-chart" role="img" aria-label="Activity over time">
      ${keys.map((k) => { const n = buckets.get(k) || 0; return n ? html`<button class="tl-bar ${tl.bucket === k ? "on" : ""}" data-tl-bucket="${k}" title="${k}: ${n} entr${n === 1 ? "y" : "ies"}" aria-label="${k}: ${n} entries" style="height:${Math.max(4, Math.round((n / peak) * 70))}px"></button>` : html`<span class="tl-gap" title="${k}: nothing"></span>`; })}
    </div>
    <div class="muted small" style="display:flex;justify-content:space-between;margin:4px 0 12px"><span>${keys[0] || ""}</span>${tl.bucket ? html`<a href="#" data-tl="all">Showing ${tl.bucket} only · show everything</a>` : html`<span>per ${scale}: click a bar to focus on it</span>`}<span>${keys.at(-1) || ""}</span></div>
    ${[...groups.entries()].map(([day, list]) => html`<div class="tl-day"><div class="section-title">${new Date(`${day}T12:00:00Z`).toLocaleDateString(undefined, { weekday: "short", day: "numeric", month: "long", year: "numeric" })}</div>
      ${list.map((e) => html`<div class="tl-entry"><span class="mono small muted">${PRECISION[e.precision] || `${e.approximate ? "~" : ""}${new Date(e.at).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}`}</span>
        <span class="pill ${KIND[e.kind]?.[0] || ""}">${KIND[e.kind]?.[1] || e.kind}</span>
        <div style="min-width:0"><b>${e.title}</b>${e.detail ? html`<div class="muted small" style="white-space:pre-line">${e.detail.slice(0, 600)}</div>` : ""}
          <div class="muted small">${e.by ? `by ${e.by}` : ""}${e.approximate ? " · approximate: the camera's time zone is unknown" : ""}
            ${e.ref?.type === "entity" ? html`<a href="#" data-open-entity="${e.ref.entity_id}" data-inv="${e.ref.investigation_id}">Show on graph</a>` : ""}
            ${e.kind === "change" ? html`<a href="#" data-open-scan="${e.ref.id}">Open the scan</a>` : ""}</div></div></div>`)}</div>`)}
  </div>`);
}

// ---------------------------------------------------------------------------- map
let mp = null; // { el, center: {x, y} world px at zoom z, z, places, tiles: Map(key -> objectURL), ... }

const project = (lat, lon, z) => {
  const s = TILE * 2 ** z;
  const sin = Math.sin((Math.max(-85.05, Math.min(85.05, lat)) * Math.PI) / 180);
  return { x: ((lon + 180) / 360) * s, y: (0.5 - Math.log((1 + sin) / (1 - sin)) / (4 * Math.PI)) * s };
};

export async function renderMap(el, caseObj) {
  const data = await api.get(`/api/cases/${enc(caseObj.id)}/places`);
  teardownMap();
  el.dataset.mode = "map";
  mp = { el, caseObj, data, z: 2, center: { x: 512, y: 512 }, tiles: new Map(), pending: new Set(), selected: null };
  setHTML(el, html`<div class="card card-pad">
    <div class="card-head wrap"><div><h2>Map</h2><p class="muted small">${data.places.length} place${data.places.length === 1 ? "" : "s"}: coordinates in the case, photos' GPS and addresses looked up. Map images are fetched by Argus, never by your browser.</p></div>
      <span style="display:flex;gap:6px">${data.places.length ? html`<button class="btn sm" data-map="fit">${ico("fit")}Show all</button><button class="btn sm" data-map="kml">${ico("download")}Google Earth (KML)</button>` : ""}</span></div>
    <div class="map" id="case-map" tabindex="0" aria-label="Map of the case's places (drag to move, scroll or +/- to zoom)">
      <div class="map-tiles"></div><div class="map-marks"></div>
      <div class="map-zoom"><button class="btn sm icon" data-map="in" aria-label="Zoom in">${ico("zoomin")}</button><button class="btn sm icon" data-map="out" aria-label="Zoom out">${ico("zoomout")}</button></div>
      <div class="map-credit">${data.tiles ? data.attribution : "Map images are off on this server"}</div>
      <div class="map-pop" hidden></div>
    </div>
    ${data.places.length ? html`<div class="list" style="margin-top:12px">${data.places.map((p, i) => html`<div class="list-row clickable" data-map-place="${i}"><span class="map-dot ${p.kind}"></span><div class="list-main"><div class="list-title">${p.label}</div><div class="list-sub">${p.type} · ${p.how} · ${p.lat}, ${p.lon}${p.detail ? ` · ${p.detail}` : ""}</div></div></div>`)}</div>`
      : html`<p class="muted small" style="margin-top:12px">No places yet. Give a location entity coordinates (e.g. <span class="mono">51.5007, -0.1246</span> or a map link), add photos with GPS, or look up an address below.</p>`}
    ${data.unplaced.length ? html`<div style="margin-top:16px"><div class="section-title">Not on the map yet</div>
      <p class="muted small">Looking up an address sends it to the address service (OpenStreetMap's Nominatim by default) through this case's route.</p>
      <div class="list">${data.unplaced.map((u) => html`<div class="list-row"><div class="list-main"><div class="list-title">${u.label}</div><div class="list-sub">${u.type}</div></div>
        ${canEdit() && data.geocoding ? html`<button class="btn sm" data-map-geocode="${u.id}">${ico("search")}Find on map</button>` : ""}</div>`)}</div></div>` : ""}
  </div>`);
  wireMap();
  fit();
}

function teardownMap() {
  if (!mp) return;
  for (const url of mp.tiles.values()) if (url) URL.revokeObjectURL(url);
  mp = null;
}

function fit() {
  const pts = mp.data.places;
  const box = $("#case-map").getBoundingClientRect();
  const w = box.width || 800;
  const h = box.height || 480;
  if (!pts.length) { mp.z = 1; mp.center = { x: TILE, y: TILE }; return draw(); }
  let z = 17;
  for (; z > 1; z--) {
    const ps = pts.map((p) => project(p.lat, p.lon, z));
    const xs = ps.map((p) => p.x);
    const ys = ps.map((p) => p.y);
    if (Math.max(...xs) - Math.min(...xs) < w - 80 && Math.max(...ys) - Math.min(...ys) < h - 80) break;
  }
  if (pts.length === 1) z = 15;
  const ps = pts.map((p) => project(p.lat, p.lon, z));
  mp.z = z;
  mp.center = { x: (Math.min(...ps.map((p) => p.x)) + Math.max(...ps.map((p) => p.x))) / 2, y: (Math.min(...ps.map((p) => p.y)) + Math.max(...ps.map((p) => p.y))) / 2 };
  draw();
}

function zoomTo(z, anchor) {
  z = Math.max(1, Math.min(18, z));
  if (z === mp.z) return;
  const k = 2 ** (z - mp.z);
  const box = $("#case-map").getBoundingClientRect();
  const ax = anchor ? anchor.x : box.width / 2;
  const ay = anchor ? anchor.y : box.height / 2;
  const wx = mp.center.x - box.width / 2 + ax;
  const wy = mp.center.y - box.height / 2 + ay;
  mp.center = { x: wx * k - ax + box.width / 2, y: wy * k - ay + box.height / 2 };
  mp.z = z;
  draw();
}

function draw() {
  if (!mp) return;
  const box = $("#case-map").getBoundingClientRect();
  const w = box.width;
  const h = box.height;
  const left = mp.center.x - w / 2;
  const top = mp.center.y - h / 2;
  const n = 2 ** mp.z;
  const tilesEl = $("#case-map .map-tiles");
  const frag = document.createDocumentFragment();
  if (mp.data.tiles) {
    for (let tx = Math.floor(left / TILE); tx <= Math.floor((left + w) / TILE); tx++) {
      for (let ty = Math.max(0, Math.floor(top / TILE)); ty <= Math.min(n - 1, Math.floor((top + h) / TILE)); ty++) {
        const wx = ((tx % n) + n) % n;
        const key = `${mp.z}/${wx}/${ty}`;
        const img = document.createElement("img");
        img.className = "map-tile";
        img.alt = "";
        img.style.transform = `translate(${Math.round(tx * TILE - left)}px, ${Math.round(ty * TILE - top)}px)`;
        const url = mp.tiles.get(key);
        if (url) img.src = url;
        else loadTile(key);
        frag.append(img);
        img.dataset.key = key;
      }
    }
  }
  tilesEl.replaceChildren(frag);
  const marks = $("#case-map .map-marks");
  marks.replaceChildren(...mp.data.places.map((p, i) => {
    const pt = project(p.lat, p.lon, mp.z);
    const m = document.createElement("button");
    m.className = `map-mark ${p.kind}${mp.selected === i ? " on" : ""}`;
    m.dataset.mapMark = String(i);
    m.title = p.label;
    m.setAttribute("aria-label", `${p.label} (${p.type})`);
    m.style.transform = `translate(${Math.round(pt.x - left)}px, ${Math.round(pt.y - top)}px)`;
    return m;
  }));
  showPopup();
}

async function loadTile(key) {
  if (!mp || mp.pending.has(key) || mp.tiles.has(key)) return;
  const owner = mp;
  owner.pending.add(key);
  try {
    const res = await request(`/api/map/tiles/${key}.png`, { raw: true });
    const url = URL.createObjectURL(await res.blob());
    if (mp !== owner) { URL.revokeObjectURL(url); return; }
    owner.tiles.set(key, url);
    document.querySelectorAll(`#case-map img[data-key="${key}"]`).forEach((img) => { img.src = url; });
  } catch {
    owner.tiles.set(key, ""); // don't retry a missing tile on every redraw
  } finally {
    owner.pending.delete(key);
  }
}

function showPopup() {
  const pop = $("#case-map .map-pop");
  if (mp.selected == null) { pop.hidden = true; return; }
  const p = mp.data.places[mp.selected];
  const box = $("#case-map").getBoundingClientRect();
  const pt = project(p.lat, p.lon, mp.z);
  const x = pt.x - (mp.center.x - box.width / 2);
  const y = pt.y - (mp.center.y - box.height / 2);
  setHTML(pop, html`<b>${p.label}</b><div class="small muted">${p.type} · ${p.how}</div><div class="small mono">${p.lat}, ${p.lon}</div>${p.detail ? html`<div class="small">${p.detail}</div>` : ""}`);
  pop.style.transform = `translate(${Math.round(Math.min(Math.max(x - 110, 8), box.width - 230))}px, ${Math.round(Math.max(y - 110, 8))}px)`;
  pop.hidden = false;
}

function wireMap() {
  const el = $("#case-map");
  let drag = null;
  el.addEventListener("pointerdown", (e) => {
    if (e.target.closest("button")) return;
    drag = { x: e.clientX, y: e.clientY, cx: mp.center.x, cy: mp.center.y };
    el.setPointerCapture(e.pointerId);
  });
  el.addEventListener("pointermove", (e) => {
    if (!drag) return;
    mp.center = { x: drag.cx - (e.clientX - drag.x), y: drag.cy - (e.clientY - drag.y) };
    draw();
  });
  el.addEventListener("pointerup", () => { drag = null; });
  el.addEventListener("wheel", (e) => {
    e.preventDefault();
    const box = el.getBoundingClientRect();
    zoomTo(mp.z + (e.deltaY < 0 ? 1 : -1), { x: e.clientX - box.left, y: e.clientY - box.top });
  }, { passive: false });
  el.addEventListener("dblclick", (e) => {
    const box = el.getBoundingClientRect();
    zoomTo(mp.z + 1, { x: e.clientX - box.left, y: e.clientY - box.top });
  });
  el.addEventListener("keydown", (e) => {
    const step = { ArrowLeft: [-80, 0], ArrowRight: [80, 0], ArrowUp: [0, -80], ArrowDown: [0, 80] }[e.key];
    if (step) { e.preventDefault(); mp.center = { x: mp.center.x + step[0], y: mp.center.y + step[1] }; draw(); }
    if (e.key === "+" || e.key === "=") zoomTo(mp.z + 1);
    if (e.key === "-") zoomTo(mp.z - 1);
  });
}

function select(i) {
  const p = mp.data.places[i];
  mp.selected = i;
  if (mp.z < 12) mp.z = 14;
  mp.center = project(p.lat, p.lon, mp.z);
  draw();
}

export function initCaseViews(root) {
  on(root, "click", "[data-tl-kind]", (_e, btn) => {
    const k = btn.dataset.tlKind;
    if (tl.hidden.has(k)) tl.hidden.delete(k); else tl.hidden.add(k);
    tl.bucket = null;
    drawTimeline(btn.closest("[data-mode=timeline]"));
  });
  on(root, "click", "[data-tl-bucket]", (_e, btn) => {
    tl.bucket = tl.bucket === btn.dataset.tlBucket ? null : btn.dataset.tlBucket;
    drawTimeline(btn.closest("[data-mode=timeline]"));
  });
  on(root, "click", "[data-tl]", (e, btn) => {
    e.preventDefault();
    if (btn.dataset.tl === "all") { tl.bucket = null; drawTimeline(btn.closest("[data-mode=timeline]")); }
    if (btn.dataset.tl === "csv") download(`/api/cases/${enc(tl.caseObj.id)}/timeline.csv`, `argus-${tl.caseObj.id}-timeline.csv`).catch((err) => toast(err.message, "error"));
  });
  on(root, "click", "[data-map]", (e, btn) => {
    e.preventDefault();
    const act = btn.dataset.map;
    if (act === "in") zoomTo(mp.z + 1);
    if (act === "out") zoomTo(mp.z - 1);
    if (act === "fit") { mp.selected = null; fit(); }
    if (act === "kml") download(`/api/cases/${enc(mp.caseObj.id)}/places.kml`, `argus-${mp.caseObj.id}-places.kml`).catch((err) => toast(err.message, "error"));
  });
  on(root, "click", "[data-map-mark]", (_e, btn) => { mp.selected = Number(btn.dataset.mapMark); draw(); });
  on(root, "click", "[data-map-place]", (_e, row) => select(Number(row.dataset.mapPlace)));
  on(root, "click", "[data-map-geocode]", async (_e, btn) => {
    btn.disabled = true;
    btn.textContent = "Looking up…";
    try {
      await api.post(`/api/cases/${enc(mp.caseObj.id)}/items/${enc(btn.dataset.mapGeocode)}/geocode`);
      toast("Found: added to the map", "success");
      await renderMap(mp.el, mp.caseObj);
    } catch (err) {
      toast(err.message, "error");
      btn.disabled = false;
      btn.textContent = "Find on map";
    }
  });
  window.addEventListener("resize", () => { if (mp && document.body.contains(mp.el)) draw(); });
}

export { teardownMap };
