// Ransomware intelligence hub: recent leak-site posts, group tracking, new-group detection, stats.
// Read-only, from the public research feed. Argus never visits leak sites.

import { api } from "../api.js";
import { empty, ico } from "../components.js";
import { $, formatDay, html, on, setHTML, timeAgo } from "../dom.js";

let root;
let data = null;
let filters = { group: "", country: "", sector: "", q: "" };

function query() {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(filters)) if (v) p.set(k, v);
  p.set("limit", "200");
  return p.toString();
}

const hasFilter = () => Object.values(filters).some(Boolean);

function sparkline(byDay) {
  const max = Math.max(1, ...byDay.map((d) => d.count));
  return html`<div class="rw-spark" style="display:flex;align-items:flex-end;gap:3px;height:48px">
    ${byDay.map((d) => html`<div title="${d.day}: ${d.count}" style="flex:1;min-width:6px;background:var(--accent, #6366f1);opacity:${d.count ? 0.4 + 0.6 * (d.count / max) : 0.12};height:${Math.max(4, Math.round((d.count / max) * 48))}px;border-radius:2px"></div>`)}
  </div>`;
}

function facetChips(title, items, key) {
  if (!items.length) return "";
  return html`<div style="margin-top:10px"><div class="muted small" style="margin-bottom:4px">${title}</div>
    <div style="display:flex;flex-wrap:wrap;gap:6px">
      ${items.map((it) => html`<button class="btn sm ${filters[key] === it.name ? "primary" : "ghost"}" data-facet="${key}" data-val="${it.name}">${it.name} <span class="muted">${it.count}</span></button>`)}
    </div></div>`;
}

function render() {
  const d = data;
  if (!d.capabilities.ransomware) {
    setHTML(root, html`<div class="page"><div class="page-head"><div><h1>Ransomware</h1><p>Track the ransomware ecosystem from a public leak-site research feed.</p></div></div>
      <div class="guide-warning info">${ico("info")}<div class="small">The ransomware feed is turned off. Set <code>ARGUS_RANSOMWARE_FEED_URL</code> (e.g. the ransomware.live API) to see recent leak-site posts, group activity and new-group detection. Argus reads only this research feed; it never visits leak sites.</div></div></div>`);
    return;
  }
  const s = d.stats;
  setHTML(root, html`<div class="page">
    <div class="page-head">
      <div><h1>Ransomware</h1><p>Recent leak-site posts, active groups and newly appeared groups, from a public research feed. Argus never visits leak sites — only metadata is shown.</p></div>
      <div class="page-actions">${hasFilter() ? html`<button class="btn sm" data-act="clear">${ico("x")}Clear filters</button>` : ""}
        <button class="btn sm" data-act="refresh">${ico("compare")}Refresh</button></div>
    </div>
    ${d.new_groups.length ? html`<div class="callout warn" style="margin-bottom:16px">${ico("alert")}<span><b>${d.new_groups.length} newly appeared group(s):</b> ${d.new_groups.map((g) => html`<button class="btn sm ghost" data-facet="group" data-val="${g}">${g}</button> `)} — a new group name often marks a new operation or a rebrand. Verify before acting.</span></div>` : ""}
    <div class="grid kpis" style="margin-bottom:16px">
      <div class="card card-pad"><b style="font-size:24px">${s.last_7_days}</b><div class="muted small">posts in the last 7 days</div></div>
      <div class="card card-pad"><b style="font-size:24px">${s.last_30_days}</b><div class="muted small">posts in the last 30 days</div></div>
      <div class="card card-pad"><b style="font-size:24px">${s.active_groups}</b><div class="muted small">active groups (recent window)</div></div>
      <div class="card card-pad"><b style="font-size:24px">${d.roster_count || "—"}</b><div class="muted small">groups tracked by the feed</div></div>
    </div>
    <div class="card card-pad" style="margin-bottom:16px">
      <div class="card-head"><div><h2>Activity</h2><p class="muted small">Leak-site posts per day, last 14 days.</p></div></div>
      ${sparkline(s.by_day)}
      ${facetChips("Busiest groups", d.facets.groups, "group")}
      ${facetChips("Sectors", d.facets.sectors, "sector")}
      ${facetChips("Countries", d.facets.countries, "country")}
    </div>
    <div class="card card-pad">
      <div class="card-head"><div><h2>Recent posts</h2><p class="muted small">${d.total_matched} post(s)${hasFilter() ? " matching your filter" : ""}, newest first.</p></div>
        <input class="input" id="rw-search" placeholder="Search victim or site…" value="${filters.q}" style="max-width:240px" aria-label="Search victim or site">
      </div>
      ${!d.posts.length ? empty("search", "No posts", hasFilter() ? "No leak-site posts match this filter." : "No recent posts from the feed.")
        : html`<div class="table-scroll"><table class="table"><thead><tr><th>Victim</th><th>Group</th><th>Date</th><th class="hide-sm">Sector</th><th class="hide-sm">Country</th></tr></thead><tbody>
        ${d.posts.map((p) => html`<tr>
          <td><b style="word-break:break-word">${p.victim}</b>${p.website ? html`<div class="muted small mono">${p.website}</div>` : ""}</td>
          <td><button class="btn sm ghost" data-facet="group" data-val="${p.group}">${p.group}</button></td>
          <td>${p.published ? formatDay(p.published) : "—"}</td>
          <td class="hide-sm">${p.sector || "—"}</td>
          <td class="hide-sm">${p.country || "—"}</td>
        </tr>`)}</tbody></table></div>`}
    </div>
  </div>`);
}

export async function refresh() {
  if (!root) return;
  try {
    data = await api.get(`/api/ransomware?${query()}`);
  } catch (err) {
    setHTML(root, html`<div class="page"><p class="error-text">${err.message}</p></div>`);
    return;
  }
  render();
}

export function initRansomware(el) {
  root = el;
  on(root, "click", "[data-facet]", (_e, btn) => {
    const { facet, val } = btn.dataset;
    filters[facet] = filters[facet] === val ? "" : val; // toggle
    refresh();
  });
  on(root, "click", "[data-act]", (_e, btn) => {
    if (btn.dataset.act === "clear") { filters = { group: "", country: "", sector: "", q: "" }; return refresh(); }
    if (btn.dataset.act === "refresh") return refresh();
  });
  on(root, "keydown", "#rw-search", (e) => {
    if (e.key === "Enter") { filters.q = e.target.value.trim(); refresh(); }
  });
}
