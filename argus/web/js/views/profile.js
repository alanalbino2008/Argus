// A person's (or organisation's) profile in a case: everything the case knows about them, in one
// place. Opened from the case's list of people or from the link chart.

import { api, enc } from "../api.js";
import { ico } from "../components.js";
import { $, formatDate, html, openModal, setHTML } from "../dom.js";

const CONF = { confirmed: "ok", likely: "accent", possible: "warn", recorded: "" };
const safeUrl = (u) => /^https?:\/\//.test(u || "");

function section(title, body, empty) {
  return html`<div style="margin-bottom:18px"><h3 style="margin-bottom:6px">${title}</h3>${body || html`<p class="muted small">${empty}</p>`}</div>`;
}

function relRow(r) {
  return html`<div class="small" style="margin-bottom:4px"><span class="pill ${CONF[r.confidence] || ""}">${r.confidence}</span>
    ${r.outgoing === false && !r.symmetric ? html`<b>${r.other}</b> ${r.text} them` : html`${r.text} <b>${r.other}</b>`}
    <span class="muted">${r.since ? ` · since ${r.since}` : ""}${r.until ? ` · until ${r.until}` : ""}${r.why ? ` · ${r.why}` : ""}</span></div>`;
}

function render(p) {
  if (p.protected) return html`<div class="callout warn">${ico("shield")}<span>${p.message}</span></div>`;
  const kv = Object.entries(p.attributes || {});
  const n = p.network;
  const scans = p.scans || [];
  return html`
    <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px">
      <div>${section("Details", kv.length ? html`<dl class="kv">${kv.map(([k, v]) => html`<dt>${k}</dt><dd>${v}</dd>`)}</dl>` : "", "No details recorded yet.")}
        ${p.notes ? section("Notes", html`<p class="small" style="white-space:pre-wrap">${p.notes}</p>`) : ""}
        ${section("Place in the network", html`<p class="small">${n.connections} relationship${n.connections === 1 ? "" : "s"}${n.group ? ` · in group ${n.group} of ${n.group_size}` : ""}
          ${n.key_person ? html` · <span class="pill accent">Key person</span>` : ""}${n.go_between ? html` · <span class="pill warn">Go-between</span>` : ""}</p>`)}</div>
      <div>${section("Relationships", p.relationships.length ? html`${p.relationships.map(relRow)}` : "", "No relationships yet: link them in the case, or see the link chart's suggestions.")}
        ${section("Accounts and contacts", p.identifiers.length ? html`${p.identifiers.map(relRow)}` : "", "None linked yet.")}
        ${section("Places", p.places.length ? html`${p.places.map((r) => html`<div class="small">${ico("location")} ${r.other} <span class="muted">· ${r.text}</span></div>`)}` : "", "None recorded.")}</div>
    </div>
    ${scans.length ? section("What scans found", html`${scans.map((s) => html`<div class="note" style="margin-bottom:8px">
      <div class="muted small">From the scan of ${s.scan}</div>
      ${Object.keys(s.facts).length ? html`<dl class="kv">${Object.entries(s.facts).map(([k, v]) => html`<dt>${k.replace(/_/g, " ")}</dt><dd>${v}</dd>`)}</dl>` : ""}
      ${s.sanctions.map((x) => html`<div class="small" style="margin-top:4px"><span class="pill ${x.conflicts.length ? "warn" : "critical"}">Sanctions</span> Similar name on ${x.list}: ${x.name}${x.score ? ` (${Math.round(x.score * 100)}%)` : ""}${x.conflicts.length ? html` <span style="color:var(--ok)">· probably a different person: ${x.conflicts.join("; ")}</span>` : ""}</div>`)}
      ${s.offshore_leaks.map((x) => html`<div class="small"><span class="pill warn">Offshore Leaks</span> ${x.name} ${safeUrl(x.url) ? html`<a href="${x.url}" target="_blank" rel="noopener noreferrer nofollow">Open ↗</a>` : ""}</div>`)}
      ${s.appointments.length ? html`<div class="small" style="margin-top:6px"><b>Directorships and control</b>${s.appointments.map((a) => html`<div>${a.role} of ${a.company} <span class="muted">${a.from ? `· ${a.from}` : ""}${a.to ? ` – ${a.to}` : ""}</span></div>`)}</div>` : ""}
      ${s.profiles.map((x) => html`<div class="small" style="margin-top:4px">${ico("persona")} ${x.account}: ${[x.display_name, x.location, x.bio].filter(Boolean).join(" · ")}</div>`)}
    </div>`)}`) : ""}
    ${section("Timeline", p.timeline.length ? html`${p.timeline.map((t) => html`<div class="small"><span class="mono">${t.date}</span> · ${t.text} <span class="muted">(${t.source})</span></div>`)}` : "", "Nothing dated yet.")}
    ${section(`Mentioned in (${p.mentions.length})`, p.mentions.length ? html`${p.mentions.map((m) => html`<div class="note" style="margin-bottom:6px">
      <div class="small"><span class="pill">${m.kind}</span> <b>${m.title || ""}</b> <span class="muted">${m.when ? formatDate(m.when) : ""}</span></div>
      ${m.passages.map((x) => html`<div class="small muted" style="margin-top:3px">“${x}”</div>`)}</div>`)}` : "", "No notes, events or evidence name them yet.")}`;
}

export async function openProfile(caseObj, itemId) {
  setHTML($("#profile-title"), html`Profile`);
  setHTML($("#profile-body"), html`<p class="muted">Loading…</p>`);
  openModal("profile-modal");
  try {
    const p = await api.get(`/api/cases/${enc(caseObj.id)}/entities/${enc(itemId)}/profile`);
    setHTML($("#profile-title"), html`${ico(p.type === "organisation" ? "organization" : "person")} ${p.name}`);
    $("#profile-sub").textContent = p.protected ? "" : `${p.type}${p.added_by ? ` · added by ${p.added_by}` : ""}${p.from_scan ? " · from a scan" : ""}`;
    setHTML($("#profile-body"), render(p));
  } catch (err) {
    setHTML($("#profile-body"), html`<p class="error-text">${err.message}</p>`);
  }
}
