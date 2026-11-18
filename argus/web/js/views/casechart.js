// The Link chart tab of a case: the people and organisations in the case, how they are related,
// and what the network's shape says. Relationships the material shows can be added from the
// suggestions; the chain between any two people can be traced.

import { api, enc } from "../api.js";
import { ico } from "../components.js";
import { $, html, on, setHTML, toast } from "../dom.js";
import { nodeGlyph, typeInfo } from "../icons.js";
import { state } from "../state.js";

/* global cytoscape */

const GROUP_COLOR = { family: "#e11d48", work: "#2563eb", business: "#d97706", social: "#7c3aed", shared: "#059669", other: "#6b7280" };
const GROUP_LABEL = { family: "Family", work: "Work", business: "Business & money", social: "Social", shared: "Shared details", other: "Other" };
const CLUSTER_COLORS = ["#4f5bd5", "#e54666", "#12a594", "#ef5f00", "#8e4ec6", "#ad7f00", "#0d8a7d", "#d6409f"];
const TYPE_MAP = { person: "person", organisation: "organization", username: "username", account: "social_profile", email: "email",
  phone: "phone", domain: "domain", ip: "ip_address", address: "location", location: "location", wallet: "crypto_wallet", document: "url" };
const canEdit = () => ["analyst", "admin"].includes(state.workspace?.role);

let el = null;
let caseRef = null;
let net = null;
let cy = null;
let selected = null;
let suggestions = null;
let routeResult = null;
const filters = { groups: new Set(Object.keys(GROUP_COLOR)), min: "possible", colour: "type" };

export async function renderChart(target, caseObj) {
  el = target;
  caseRef = caseObj;
  el.dataset.mode = "chart";
  net = await api.get(`/api/cases/${enc(caseObj.id)}/network`);
  selected = null;
  routeResult = null;
  draw();
}

const rank = { confirmed: 0, likely: 1, possible: 2 };
const nodeById = (id) => net.nodes.find((n) => n.id === id);

function elements() {
  const maxDegree = Math.max(1, ...net.nodes.map((n) => n.degree || 0));
  const nodes = net.nodes.map((n) => {
    const info = typeInfo(TYPE_MAP[n.type] || "generic");
    const color = n.protected ? "#9ca3af" : filters.colour === "group" && n.cluster != null ? CLUSTER_COLORS[n.cluster % CLUSTER_COLORS.length] : info.color;
    return { data: { id: n.id, label: n.label.length > 26 ? `${n.label.slice(0, 25)}…` : n.label, color,
      icon: nodeGlyph(n.protected ? "shield" : TYPE_MAP[n.type] || "generic"), size: 30 + 26 * ((n.degree || 0) / maxDegree) } };
  });
  const edges = net.edges.filter((e) => filters.groups.has(e.group) && rank[e.confidence] <= rank[filters.min]).map((e) => ({
    data: { id: e.id, source: e.from, target: e.to, label: e.text, color: GROUP_COLOR[e.group], width: e.confidence === "confirmed" ? 3 : e.confidence === "likely" ? 2 : 1.5,
      style: e.confidence === "possible" ? "dashed" : "solid", arrow: e.symmetric ? "none" : "triangle" },
  }));
  return [...nodes, ...edges];
}

function mountGraph() {
  const box = $("#chart-canvas");
  if (!box) return;
  cy?.destroy();
  cy = cytoscape({
    container: box, elements: elements(), minZoom: 0.2, maxZoom: 3, wheelSensitivity: 0.25,
    style: [
      { selector: "node", style: { width: "data(size)", height: "data(size)", "background-color": "data(color)", "background-image": "data(icon)",
        "background-width": "55%", "background-height": "55%", label: "data(label)", "font-size": 11, "text-valign": "bottom", "text-margin-y": 5,
        color: getComputedStyle(document.documentElement).getPropertyValue("--text").trim() || "#111" } },
      { selector: "node:selected", style: { "border-width": 4, "border-color": "#111827" } },
      { selector: "edge", style: { width: "data(width)", "line-color": "data(color)", "line-style": "data(style)", "target-arrow-shape": "data(arrow)",
        "target-arrow-color": "data(color)", "curve-style": "bezier", opacity: 0.85, label: "", "font-size": 9, "text-rotation": "autorotate" } },
      { selector: "edge.show", style: { label: "data(label)", opacity: 1 } },
      { selector: ".faded", style: { opacity: 0.15 } },
      { selector: "node.on-route", style: { opacity: 1, "border-width": 4, "border-color": "#dc2626" } },
      { selector: "edge.on-route", style: { opacity: 1, "line-color": "#dc2626", "target-arrow-color": "#dc2626", width: 4, label: "data(label)" } },
    ],
    layout: { name: "cose", animate: false, padding: 30, nodeRepulsion: 9000, idealEdgeLength: 110 },
  });
  cy.on("tap", "node", (e) => { selected = e.target.id(); routeResult = null; drawSide(); highlight(); });
  cy.on("tap", (e) => { if (e.target === cy) { selected = null; drawSide(); highlight(); } });
  cy.on("mouseover", "node", (e) => { if (!routeResult) e.target.connectedEdges().addClass("show"); });
  cy.on("mouseout", "node", () => { if (!routeResult) cy.edges().removeClass("show"); });
  highlight();
}

function highlight() {
  if (!cy) return;
  cy.elements().removeClass("faded on-route show");
  if (routeResult?.found) {
    const ids = new Set(routeResult.steps.flatMap((s) => [s.from, s.to, s.edge]));
    cy.elements().forEach((x) => (ids.has(x.id()) ? x.addClass("on-route") : x.addClass("faded")));
  } else if (selected) {
    const hood = cy.getElementById(selected).closedNeighborhood();
    cy.elements().not(hood).addClass("faded");
    hood.edges().addClass("show");
  }
}

function personLink(id) {
  const n = nodeById(id);
  return n ? html`<a href="#" data-chart="select" data-id="${id}">${n.label}</a>` : "?";
}

function overview() {
  const a = net.analysis;
  return html`
    ${a.key_people.length ? html`<h3>Most connected</h3>${a.key_people.map((p) => html`<div class="small">${personLink(p.id)} <span class="muted">· ${p.connections} links</span></div>`)}` : ""}
    ${a.bridges.length ? html`<h3 style="margin-top:12px">Go-betweens</h3><p class="muted small">They connect groups that are otherwise apart.</p>${a.bridges.map((p) => html`<div class="small">${personLink(p.id)} <span class="muted">· links groups ${p.groups.map((g) => g + 1).join(" and ")}</span></div>`)}` : ""}
    ${a.clusters.length ? html`<h3 style="margin-top:12px">Groups (${a.clusters.length})</h3>${a.clusters.map((c) => html`<div class="small"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:${CLUSTER_COLORS[c.id % CLUSTER_COLORS.length]}"></span> Group ${c.id + 1}: ${c.members.slice(0, 4).map((m) => nodeById(m)?.label).join(", ")}${c.size > 4 ? ` and ${c.size - 4} more` : ""}</div>`)}` : ""}
    ${a.isolated.length ? html`<h3 style="margin-top:12px">Not connected yet (${a.isolated.length})</h3><div class="small">${a.isolated.map((p, i) => html`${i ? ", " : ""}${personLink(p.id)}`)}</div>` : ""}
    ${!net.edges.length ? html`<p class="muted small">No links yet. Link people in the Overview tab, or look at the suggestions.</p>` : ""}`;
}

function details(id) {
  const n = nodeById(id);
  if (!n) return "";
  const mine = net.edges.filter((e) => e.from === id || e.to === id);
  return html`<h3>${n.label}</h3>
    <p class="muted small">${n.type}${n.protected ? " · protected: not named here, never profiled" : ""} · ${n.degree || 0} link${n.degree === 1 ? "" : "s"}${n.cluster != null ? ` · group ${n.cluster + 1}` : ""}</p>
    ${Object.keys(n.attributes || {}).length ? html`<dl class="kv">${Object.entries(n.attributes).map(([k, v]) => html`<dt>${k}</dt><dd>${v}</dd>`)}</dl>` : ""}
    ${mine.length ? html`<h3 style="margin-top:10px">Relationships</h3>${mine.map((e) => {
      const out = e.from === id;
      const other = out ? e.to : e.from;
      return html`<div class="small" style="margin-bottom:4px"><span style="color:${GROUP_COLOR[e.group]}">●</span> ${out || e.symmetric ? e.text : `${e.text} (from)`} ${personLink(other)} <span class="muted">· ${e.confidence}${e.since ? ` · since ${e.since}` : ""}${e.until ? ` · until ${e.until}` : ""}</span></div>`;
    })}` : ""}
    <h3 style="margin-top:12px">How are they connected to…</h3>
    <div style="display:flex;gap:6px"><select class="select" id="chart-route-to" aria-label="Connected to">${net.nodes.filter((x) => x.id !== id).map((x) => html`<option value="${x.id}">${x.label}</option>`)}</select>
      <button class="btn sm" data-chart="route">Trace</button></div>
    ${routeResult ? routeView() : ""}`;
}

function routeView() {
  if (!routeResult.found) {
    return html`<p class="small" style="margin-top:8px">No chain of links joins them yet.${routeResult.common.length ? "" : " They share no connections."}</p>`;
  }
  return html`<div class="note" style="margin-top:8px"><b>${routeResult.hops} step${routeResult.hops === 1 ? "" : "s"}</b>, as strong as its weakest link: <span class="pill ${routeResult.strength === "confirmed" ? "ok" : routeResult.strength === "likely" ? "accent" : "warn"}">${routeResult.strength}</span>
    <ol class="small" style="margin:6px 0 0 18px">${routeResult.steps.map((s) => html`<li>${s.reversed ? html`<b>${s.to_label}</b> ${s.relationship} <b>${s.from_label}</b>` : html`<b>${s.from_label}</b> ${s.relationship} <b>${s.to_label}</b>`} <span class="muted">(${s.confidence})</span></li>`)}</ol>
    ${routeResult.common.length ? html`<p class="small" style="margin-top:6px">Connections in common: ${routeResult.common.map((c) => c.label).join(", ")}</p>` : ""}</div>`;
}

function suggestionsView() {
  if (!suggestions) return html`<button class="btn sm" data-chart="suggest">${ico("sparkle")}Find relationships in the material</button>`;
  if (!suggestions.suggestions.length) return html`<p class="muted small">No new relationships found in ${suggestions.documents_read} notes and documents and ${suggestions.scans_read} linked scans.</p>`;
  return html`<p class="muted small">From ${suggestions.documents_read} notes and documents and ${suggestions.scans_read} linked scans. Nothing is added until you choose.</p>
    ${suggestions.suggestions.map((s, i) => html`<div class="note" style="margin-bottom:6px">
      <div class="small"><span style="color:${GROUP_COLOR[s.group]}">●</span> <b>${s.from_label}</b> ${s.text} <b>${s.to_label}</b> <span class="pill ${s.confidence === "confirmed" ? "ok" : s.confidence === "likely" ? "accent" : "warn"}">${s.confidence}</span></div>
      <div class="muted small">${s.why}</div>
      ${canEdit() ? html`<button class="btn sm ghost" data-chart="accept" data-i="${i}" style="margin-top:4px">${ico("plus")}Add</button>` : ""}</div>`)}`;
}

function drawSide() {
  const side = $("#chart-side");
  if (!side) return;
  setHTML(side, html`${selected ? details(selected) : overview()}
    <h3 style="margin-top:16px">${ico("sparkle")}Suggested relationships</h3>${suggestionsView()}`);
}

function draw() {
  if (!el) return;
  setHTML(el, html`<div class="card card-pad">
    <div class="card-head"><h2>${ico("graph")}Link chart</h2>
      <span style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">
        <select class="select sm" data-chart-filter="min" aria-label="How sure"><option value="possible" ${filters.min === "possible" ? "selected" : ""}>All links</option><option value="likely" ${filters.min === "likely" ? "selected" : ""}>Likely and confirmed</option><option value="confirmed" ${filters.min === "confirmed" ? "selected" : ""}>Confirmed only</option></select>
        <select class="select sm" data-chart-filter="colour" aria-label="Colour people by"><option value="type" ${filters.colour === "type" ? "selected" : ""}>Colour by type</option><option value="group" ${filters.colour === "group" ? "selected" : ""}>Colour by group</option></select>
        <button class="btn sm ghost" data-chart="fit">${ico("fit")}Fit</button></span></div>
    <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px" role="group" aria-label="Kinds of relationship">${Object.entries(GROUP_LABEL).map(([g, label]) => html`<label class="pill" style="cursor:pointer;border:1px solid ${GROUP_COLOR[g]}"><input type="checkbox" data-chart-group="${g}" ${filters.groups.has(g) ? "checked" : ""}> <span style="color:${GROUP_COLOR[g]}">●</span> ${label}</label>`)}
      <span class="muted small" style="align-self:center">Solid: confirmed · thinner: likely · dashed: possible. Bigger: more connected.</span></div>
    <div class="chart-layout">
      <div id="chart-canvas" style="height:560px;border:1px solid var(--border);border-radius:10px;background:var(--bg)" role="img" aria-label="Network of people and organisations in this case"></div>
      <div id="chart-side" style="max-height:560px;overflow:auto"></div>
    </div>
  </div>`);
  mountGraph();
  drawSide();
}

export function initChart(root) {
  root.addEventListener("change", (e) => {
    const t = e.target;
    if (!el || !el.contains(t)) return;
    if (t.dataset.chartGroup) {
      if (t.checked) filters.groups.add(t.dataset.chartGroup); else filters.groups.delete(t.dataset.chartGroup);
      mountGraph();
    } else if (t.dataset.chartFilter) {
      filters[t.dataset.chartFilter] = t.value;
      mountGraph();
    }
  });
  on(root, "click", "[data-chart]", async (e, btn) => {
    e.preventDefault();
    try {
      const act = btn.dataset.chart;
      if (act === "fit") return cy?.fit(undefined, 30);
      if (act === "select") { selected = btn.dataset.id; routeResult = null; cy?.$(":selected").unselect(); cy?.getElementById(selected).select(); drawSide(); return highlight(); }
      if (act === "route") {
        routeResult = await api.get(`/api/cases/${enc(caseRef.id)}/network/path?source=${enc(selected)}&target=${enc($("#chart-route-to").value)}`);
        drawSide();
        return highlight();
      }
      if (act === "suggest") {
        btn.disabled = true;
        suggestions = await api.get(`/api/cases/${enc(caseRef.id)}/network/suggestions`);
        return drawSide();
      }
      if (act === "accept") {
        const s = suggestions.suggestions[Number(btn.dataset.i)];
        await api.post(`/api/cases/${enc(caseRef.id)}/items`, { kind: "link", data: { from: s.from, to: s.to, relation: s.kind, confidence: s.confidence, label: s.text, why: s.why } });
        suggestions.suggestions.splice(Number(btn.dataset.i), 1);
        toast("Relationship added", "success");
        net = await api.get(`/api/cases/${enc(caseRef.id)}/network`);
        mountGraph();
        drawSide();
      }
    } catch (err) {
      toast(err.message, "error", 8000);
    }
  });
}
