// The People tab of a case: everything already known about a person, one search from all of it,
// and the accounts, addresses and records found, scored against what is known, to confirm or reject.

/* global cytoscape */
import { api, enc, request } from "../api.js";
import { ico } from "../components.js";
import { $, formatDate, html, on, setHTML, timeAgo, toast } from "../dom.js";
import { state } from "../state.js";

const canEdit = () => ["analyst", "admin"].includes(state.workspace?.role);
const safeUrl = (u) => /^https?:\/\//.test(u || "");
const VERDICT = { likely: ["ok", "Likely theirs"], possible: ["accent", "Possible"], weak: ["", "Weak"], unlikely: ["warn", "Probably not"] };
const STEP = { pending: ["", "Waiting"], running: ["accent", "Searching"], done: ["ok", "Done"], skipped: ["", "Skipped"], failed: ["warn", "Failed"] };
const RUN = { running: "accent", completed: "ok", failed: "warn", cancelled: "", interrupted: "warn" };
const KIND = { name: "Name", username: "Username", email: "Email", phone: "Phone", website: "Website", profile: "Account", record: "Register record" };
const LISTS = [["names", "Full names", "Jane Doe, J. Doe"], ["usernames", "Usernames", "jdoe, jane_d"], ["emails", "Email addresses", "jane@example.org"],
  ["phones", "Phone numbers (with country code)", "+44 7700 900123"], ["profiles", "Links to their accounts", "https://github.com/jdoe"], ["websites", "Websites", "janedoe.dev"]];
let el = null;
let caseRef = null;
let people = [];
let current = null; // the subject shown in full
let editing = false;
let filter = "open";
let timer = null;
let onChanged = () => {};
let timelineOpen = false;

const base = () => `/api/cases/${enc(caseRef.id)}/subjects`;

export async function renderSubjects(target, caseObj) {
  el = target;
  caseRef = caseObj;
  el.dataset.mode = "subjects";
  people = await api.get(base());
  if (current && !people.some((p) => p.id === current.id)) current = null;
  if (!current && people.length) current = await api.get(`${base()}/${enc(people[0].id)}`);
  editing = !people.length;
  draw();
  poll();
}

function poll() {
  clearTimeout(timer);
  if (current?.status !== "running") return;
  timer = setTimeout(async () => {
    if (!el?.isConnected || el.dataset.mode !== "subjects") return;
    try {
      current = await api.get(`${base()}/${enc(current.id)}`);
      people = await api.get(base());
      draw();
      if (current.status !== "running") onChanged({ quiet: true });
    } catch { /* try again next time */ }
    poll();
  }, 2500);
}

function knownForm(s) {
  const k = s?.known || {};
  return html`<form id="sj-form" style="display:grid;gap:8px;max-width:640px">
    <label class="small" for="sj-name">How this person is referred to in the case</label>
    <input class="input" id="sj-name" required maxlength="300" value="${s?.name || ""}" placeholder="e.g. Jane Doe, or Suspect A" autocomplete="off">
    ${LISTS.map(([key, label, hint]) => html`<label class="small" for="sj-${key}">${label} <span class="muted">(one per line)</span></label>
      <textarea class="input" id="sj-${key}" rows="2" placeholder="${hint}" autocomplete="off">${(k[key] || []).join("\n")}</textarea>`)}
    <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px">
      <div><label class="small" for="sj-city">Town or city</label><input class="input" id="sj-city" maxlength="200" value="${k.city || ""}"></div>
      <div><label class="small" for="sj-employer">Employer</label><input class="input" id="sj-employer" maxlength="200" value="${k.employer || ""}"></div>
      <div><label class="small" for="sj-born">Year of birth</label><input class="input" id="sj-born" inputmode="numeric" maxlength="4" value="${k.birth_year || ""}" placeholder="Only used to rule matches out"></div>
      <div><label class="small" for="sj-tz">Usual time zone</label><input class="input" id="sj-tz" maxlength="6" value="${k.utc_offset || ""}" placeholder="UTC offset, e.g. +01:00"></div>
    </div>
    ${s ? "" : html`<label class="small"><input type="checkbox" id="sj-confirm" required> There is a legitimate purpose for researching this person (the case's: ${caseRef.purpose}). They are not a child.</label>`}
    <p class="error-text" id="sj-error"></p>
    <div><button class="btn primary" type="submit">${s ? "Save known details" : html`${ico("plus")}Add person`}</button>
      ${s ? html` <button class="btn ghost" type="button" data-sj="cancel-edit">Cancel</button>` : people.length ? html` <button class="btn ghost" type="button" data-sj="cancel-edit">Cancel</button>` : ""}</div>
  </form>`;
}

function readForm() {
  const lines = (id) => $(`#sj-${id}`).value.split(/[\n,]+/).map((v) => v.trim()).filter(Boolean);
  const born = $("#sj-born").value.trim();
  return { name: $("#sj-name").value.trim(),
    known: { ...Object.fromEntries(LISTS.map(([key]) => [key, lines(key)])), city: $("#sj-city").value.trim(),
      employer: $("#sj-employer").value.trim(), birth_year: born ? Number(born) : null,
      utc_offset: $("#sj-tz").value.trim() || null } };
}

function knownSummary(s) {
  const k = s.known;
  const chips = [...LISTS.flatMap(([key]) => (k[key] || []).map((v) => [key, v])),
    ...(k.city ? [["city", k.city]] : []), ...(k.employer ? [["employer", k.employer]] : []), ...(k.birth_year ? [["born", `born ${k.birth_year}`]] : []), ...(k.utc_offset ? [["time zone", `UTC${k.utc_offset}`]] : [])];
  return html`<div style="display:flex;flex-wrap:wrap;gap:6px;margin:8px 0">${chips.length ? chips.map(([key, v]) => html`<span class="pill" title="${key}" style="text-transform:none">${v}</span>`) : html`<span class="muted small">Nothing known yet.</span>`}
    ${k.photo_hash ? html`<span class="pill ok" title="Only a fingerprint of the photo is kept, to recognise the same picture on a profile">${ico("eye")}Photo</span>` : ""}</div>`;
}

function runView(run) {
  if (!run) return "";
  const done = run.steps.filter((s) => !["pending", "running"].includes(s.status)).length;
  return html`<details ${run.status === "running" ? "open" : ""} style="margin-top:12px"><summary class="small">
      <span class="pill ${RUN[run.status] || ""}">${run.status === "running" ? `Searching ${done}/${run.steps.length}…` : run.status}</span>
      ${run.reason === "watch" ? "Weekly watch" : "Search"} by ${run.by} ${timeAgo(run.started_at)} · route: ${run.route}${run.passive_only ? " · passive only (anonymous case)" : ""} · ${run.new} new</summary>
    ${run.status === "interrupted" ? html`<p class="error-text">The server stopped while this ran. Search again to finish.</p>` : ""}
    ${run.error ? html`<p class="error-text">${run.error}</p>` : ""}
    <div class="list">${run.steps.map((st) => { const [cls, label] = STEP[st.status] || ["", st.status];
      return html`<div class="list-row"><div class="list-main"><div class="list-title">${KIND[st.kind] || st.kind}: ${st.value}</div>
        <div class="list-sub">${st.round > 1 ? `Round ${st.round}, ` : ""}${st.origin}${st.detail ? ` · ${st.detail}` : ""}</div></div><span class="pill ${cls}">${label}</span></div>`; })}</div>
  </details>`;
}

function candidateRow(c) {
  const [cls, label] = VERDICT[c.verdict] || ["", c.verdict];
  const decided = c.status !== "open";
  return html`<tr>
    <td><span class="pill ${decided ? (c.status === "confirmed" ? "ok" : "") : cls}">${decided ? c.status : label}</span><div class="muted small">${c.score ?? ""}/100</div></td>
    <td><b>${c.label}</b>${c.platform ? html` <span class="muted small">${c.platform}</span>` : ""}<div class="muted small">${KIND[c.kind] || c.kind} · ${c.grade} · found from ${(c.found_from || []).map((f) => f.value).join(", ")}</div>
      ${c.agree?.length ? html`<div class="small" style="color:var(--ok-text)">${ico("check")}${c.agree.join("; ")}</div>` : ""}
      ${c.conflict?.length ? html`<div class="small error-text">${c.conflict.join("; ")}</div>` : ""}
      ${c.note ? html`<div class="muted small">Note: ${c.note}</div>` : ""}
      ${c.capture ? html`<div class="small ${c.capture.status === "failed" ? "error-text" : "muted"}">${ico("shield")}${{ capturing: "Preserving the page as evidence…", done: "Page preserved as evidence (fingerprinted, in the case)", failed: `Page not preserved: ${c.capture.detail || "error"}` }[c.capture.status] || ""}</div>` : ""}</td>
    <td style="white-space:nowrap">${safeUrl(c.url) ? html`<a href="${c.url}" target="_blank" rel="noopener noreferrer" class="small">${ico("external")}Open</a>` : ""}
      ${canEdit() && c.status === "open" ? html` <button class="btn sm" data-sj="confirm" data-id="${c.id}" title="It is theirs: add it to the known details and the case">${ico("check")}Theirs</button>
        <button class="btn sm ghost" data-sj="reject" data-id="${c.id}" title="Not theirs: never suggest it again">Not theirs</button>` : ""}
      ${canEdit() && c.status === "rejected" ? html` <button class="btn sm ghost" data-sj="reopen" data-id="${c.id}">Undo</button>` : ""}</td></tr>`;
}

function suggestionsView(s) {
  const list = (s.suggestions || []).filter((x) => x.status === "pending");
  if (!list.length) return "";
  return html`<div class="note" style="margin:12px 0" id="sj-suggestions">
    <b>${ico("sparkle")}Found on confirmed accounts (${list.length})</b>
    <p class="muted small" style="margin:4px 0 8px">Not added yet: a bio can mention a friend's account or an old job. Tick what is theirs; Argus adds it to the known details and searches from it.</p>
    ${list.map((x) => html`<label class="list-row" style="cursor:pointer;align-items:flex-start">
      ${canEdit() ? html`<input type="checkbox" value="${x.id}" data-sugg checked style="margin-top:3px">` : ""}
      <div class="list-main"><div class="list-title"><span class="muted">${x.label}:</span> <span style="word-break:break-all">${x.value}</span></div>
      <div class="list-sub">${x.why}, on ${x.from}</div></div></label>`)}
    ${canEdit() ? html`<div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">
      <button class="btn sm primary" data-sj="accept-sugg">${ico("check")}Add ticked and search</button>
      <button class="btn sm ghost" data-sj="dismiss-sugg">Dismiss ticked</button></div>` : ""}
  </div>`;
}

const DOSSIER_SECTIONS = [["established", "Established"], ["likely", "Likely, not confirmed"], ["conflicts", "Conflicts"]];

function deeperView(s) {
  return html`<details data-sj-load="graph" style="margin-top:12px"><summary class="small"><b>Graph</b></summary><div data-sj-panel="graph"><p class="muted small">Loading…</p></div></details>
    <details data-sj-load="groups" style="margin-top:8px"><summary class="small"><b>Groups: accounts that seem to share an owner</b></summary><div data-sj-panel="groups"><p class="muted small">Loading…</p></div></details>
    <details data-sj-load="timeline" style="margin-top:8px"><summary class="small"><b>Timeline of their online life</b></summary><div data-sj-panel="timeline"><p class="muted small">Loading…</p></div></details>
    <details data-sj-load="associates" style="margin-top:8px"><summary class="small"><b>Other people connected</b></summary><div data-sj-panel="associates"><p class="muted small">Loading…</p></div></details>
    <details data-sj-load="breaches" style="margin-top:8px"><summary class="small"><b>${ico("shield")}Breaches & reused passwords</b></summary><div data-sj-panel="breaches"><p class="muted small">Loading…</p></div></details>
    <details data-sj-load="dossier" style="margin-top:8px"><summary class="small"><b>${ico("sparkle")}AI dossier</b></summary><div data-sj-panel="dossier"><p class="muted small">Loading…</p></div></details>`;
}

function timelinePanel(t) {
  return html`${t.contradictions.length ? html`<div class="note" style="margin:8px 0"><b class="error-text">Contradictions</b>
      ${t.contradictions.map((c) => html`<div class="small"><b>${c.what}:</b> ${c.detail}</div>`)}
      <div class="muted small">Either one finding is wrong, or one of them is not this person.</div></div>` : ""}
    ${t.events.length ? html`<div class="list">${t.events.map((e) => html`<div class="list-row"><div class="list-main">
      <div class="list-title">${e.title}</div><div class="list-sub">${e.date}${e.status === "open" ? " · not confirmed" : ""}</div></div>
      ${safeUrl(e.url) ? html`<a href="${e.url}" target="_blank" rel="noopener noreferrer" class="small">${ico("external")}Open</a>` : ""}</div>`)}</div>`
      : html`<p class="muted small">Nothing dated yet. Dates come from confirmed accounts (when created, first and last archived, renamed), documents and records.</p>`}
    <label class="small"><input type="checkbox" data-sj-open ${timelineOpen ? "checked" : ""}> Include candidates not yet confirmed</label>
    ${activityPanel(t.activity)}`;
}

function activityPanel(a) {
  if (!a) return "";
  const max = Math.max(1, ...Object.values(a.hours_utc || {}));
  const bars = Array.from({ length: 24 }, (_, h) => (a.hours_utc || {})[String(h)] || 0);
  return html`<div style="margin-top:12px"><b class="small">When they are active</b>
    ${a.samples ? html`<div role="img" aria-label="Activity by hour (UTC)" style="display:flex;align-items:flex-end;gap:2px;height:60px;margin:6px 0">
        ${bars.map((n, h) => html`<div title="${String(h).padStart(2, "0")}:00 UTC: ${n}" style="flex:1;background:${a.busiest_utc.includes(h) ? "var(--accent)" : "var(--border)"};height:${Math.round((n / max) * 100)}%;min-height:2px"></div>`)}</div>
      <div class="muted small" style="display:flex;justify-content:space-between"><span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>23:00 UTC</span></div>
      <div class="small">Busiest: ${a.busiest_utc.map((h) => `${String(h).padStart(2, "0")}:00`).join(", ")} UTC, from ${a.samples} dated posts and account dates${a.utc_offset ? ` (their usual time zone: UTC${a.utc_offset})` : ""}.</div>`
      : html`<p class="muted small">Not enough dated posts yet (a public Telegram channel or account creation times give them).</p>`}
    ${a.gaps.length ? html`<b class="small">Gaps of a year or more with nothing found</b>${a.gaps.map((g) => html`<div class="small">${g.from} → ${g.to} (${Math.round(g.days / 365)} year${g.days >= 730 ? "s" : ""}): after “${g.after}”</div>`)}` : ""}
    <p class="muted small">${a.note}</p></div>`;
}

function associatesPanel(a) {
  return html`<p class="muted small">${a.note}</p>
    ${a.associates.length ? html`<div class="list">${a.associates.map((p) => html`<div class="list-row"><div class="list-main">
      <div class="list-title">${p.name}</div><div class="list-sub">${p.relations.join(", ")} · via ${p.via.join(", ")}</div></div></div>`)}</div>`
      : html`<p class="muted small">None yet. Co-authors, fellow company officers and accounts their Telegram channel mentions appear here once the accounts they come from are confirmed.</p>`}`;
}

function dossierPanel(d) {
  const r = d?.result;
  const findings = (list) => html`<ul class="small" style="margin:4px 0 8px">${list.map((f) => html`<li>${f.finding}
    <span class="pill ${f.confidence === "confirmed" ? "ok" : f.confidence === "likely" ? "accent" : ""}" style="text-transform:none">${f.confidence}${f.downgraded ? " (only open candidates behind it)" : ""}</span>
    ${f.unsupported ? html`<span class="error-text">no source given</span>` : html`<span class="muted">${f.sources.map((x) => `[${x.ref}] ${x.label}`).join("; ")}</span>`}</li>`)}</ul>`;
  return html`<p class="muted small">Written by the AI analyst from what is known and found about this person, each line citing its sources: known details [K], confirmed findings [C], open candidates [P] and the timeline [T]. It is a draft to check, not a finding.</p>
    ${canEdit() ? html`<label class="small"><input type="checkbox" id="sj-ai-ok"> Send this person's material to Anthropic, the company that makes Claude${caseRef.opsec_mode === "anonymous" ? html`, <b>including what you know about the subject of this anonymous case</b>` : ""}</label>
      <div style="margin:6px 0"><button class="btn sm" data-sj="dossier">${ico("sparkle")}${r ? "Write it again" : "Write the dossier"}</button></div>` : ""}
    ${r ? html`<div class="note"><p>${r.summary}</p>
      ${DOSSIER_SECTIONS.filter(([k]) => r[k]?.length).map(([k, label]) => html`<b class="small">${label}</b>${findings(r[k])}`)}
      ${r.gaps?.length ? html`<b class="small">Gaps</b><ul class="small">${r.gaps.map((g) => html`<li>${g}</li>`)}</ul>` : ""}
      ${r.next_steps?.length ? html`<b class="small">Next steps</b><ul class="small">${r.next_steps.map((x) => html`<li><b>${x.action}</b>: ${x.why} <span class="muted">(${x.how})</span></li>`)}</ul>` : ""}
      <div class="muted small">By ${d.by}, ${formatDate(d.generated_at)}${d.model ? ` · ${d.model}` : ""}</div></div>` : ""}`;
}

const NODE_COLOR = { subject: "#4f5bd5", known: "#0d74ce", confirmed: "#30a46c", open: "#ad7f00", rejected: "#9ca3af", shared: "#8e4ec6", associate: "#e54666", import: "#ef5f00" };
let personCy = null;

function drawGraph(target, g) {
  setHTML(target, html`<div class="muted small" style="display:flex;gap:12px;flex-wrap:wrap;margin:4px 0">${Object.entries({ subject: "The person", known: "Known", confirmed: "Theirs", open: "To review", shared: "Shared website", associate: "Other people", import: "In imported data" }).map(([k, label]) => html`<span><i style="display:inline-block;width:10px;height:10px;border-radius:50%;background:${NODE_COLOR[k]}"></i> ${label}</span>`)}</div>
    <div data-sj-cy style="height:460px;border:1px solid var(--border);border-radius:8px"></div>
    <p class="muted small">Dashed lines: what two accounts share (picture, links, website, name, bio). Click an account to open it.</p>`);
  if (typeof cytoscape === "undefined") return;
  personCy?.destroy();
  const box = target.querySelector("[data-sj-cy]");
  personCy = cytoscape({ container: box, wheelSensitivity: 0.2,
    elements: [...g.nodes.map((n) => ({ data: { ...n, color: NODE_COLOR[n.status] || "#6b7280" } })),
      ...g.edges.map((e, i) => ({ data: { id: `e${i}`, ...e } }))],
    style: [
      { selector: "node", style: { "background-color": "data(color)", label: "data(label)", "font-size": 9, color: "#555", "text-wrap": "ellipsis", "text-max-width": 120, width: 16, height: 16 } },
      { selector: 'node[status = "subject"]', style: { width: 30, height: 30, "font-size": 12, "font-weight": 700 } },
      { selector: "edge", style: { width: 1, "line-color": "#c7c7cf", "curve-style": "bezier" } },
      { selector: 'edge[label = "confirmed"]', style: { width: 2, "line-color": "#30a46c" } },
      { selector: 'edge[kind = "shared"]', style: { "line-style": "dashed", "line-color": "#8e4ec6" } },
      { selector: 'edge[kind = "associate"]', style: { "line-color": "#e54666" } },
    ],
    layout: { name: "cose", animate: false, nodeRepulsion: 9000, idealEdgeLength: 70 } });
  personCy.on("tap", "node", (ev) => { const url = ev.target.data("url"); if (url && /^https?:\/\//.test(url)) window.open(url, "_blank", "noopener,noreferrer"); });
}

function groupsPanel(g) {
  return g.groups.length ? html`${g.groups.map((grp) => html`<div class="note" style="margin:6px 0">
      <b class="small">${grp.includes_confirmed ? "Includes an account you confirmed" : "Accounts that seem to share an owner"} (${grp.members.length})</b>
      <div class="small">${grp.members.map((m) => html`<span class="pill ${m.status === "confirmed" ? "ok" : ""}" style="text-transform:none;margin:2px">${m.label}</span>`)}</div>
      ${grp.links.slice(0, 8).map((l) => html`<div class="muted small">${grp.members.find((m) => m.id === l.a)?.label} ↔ ${grp.members.find((m) => m.id === l.b)?.label}: ${l.reasons.join("; ")}</div>`)}</div>`)}
    <p class="muted small">A shared picture or a link between two accounts groups them; a shared website, name or similar bio alone is shown but not enough. Open candidates that share a picture or a link with an account you confirmed score higher.</p>`
    : html`<p class="muted small">No groups yet: no two accounts share a picture, links, a website, a name or bio wording.</p>`;
}

function breachesPanel(b) {
  const s = b.summary;
  return html`<p class="muted small">Where the person's email addresses, usernames and phone numbers appear in data breaches, and whether the same password was reused across them. Argus keeps a masked password and a one-way hash only — never the plaintext. Reused passwords are strong evidence two accounts are one person.</p>
    ${canEdit() ? html`<button class="btn sm" data-sj="run-breaches">${ico("search")}Look up breaches</button>` : ""}
    ${s.reuse?.length ? html`<h3 style="margin-top:12px">Reused passwords (${s.reuse.length})</h3>${s.reuse.map((g) => html`<div class="note"><b class="small">${g.masked || "same password"}</b>
      <div class="small">${g.identifiers.join(" ↔ ")}</div><div class="muted small">in ${g.breaches.join(", ")}</div></div>`)}` : ""}
    ${s.stealer?.infections ? html`<h3 style="margin-top:12px">${ico("alert")}Infostealer infections (${s.stealer.infections})</h3>
      <div class="guide-warning info" style="margin:6px 0"><div class="small">Malware captured this person's saved logins. The <b>sites below are accounts they hold</b> — often ones you did not know about (banks, email, work portals). Metadata only; no passwords are stored.${s.stealer.families?.length ? html` Stealer: ${s.stealer.families.join(", ")}.` : ""}${s.stealer.latest ? ` Most recent: ${s.stealer.latest}.` : ""}</div></div>
      <div style="display:flex;flex-wrap:wrap;gap:6px">${(s.stealer.sites || []).map((site) => html`<span class="pill mono">${site}</span>`)}</div>
      ${s.stealer.site_count > (s.stealer.sites || []).length ? html`<div class="muted small">and more</div>` : ""}` : ""}
    ${b.exposures.length ? html`<h3 style="margin-top:12px">Exposures (${b.exposures.length})</h3><div style="overflow-x:auto"><table class="table"><thead><tr><th>Identifier</th><th>Breach</th><th>When</th><th>Password</th><th></th></tr></thead><tbody>
      ${b.exposures.map((e) => html`<tr><td style="word-break:break-all">${e.identifier}</td><td>${e.breach}</td><td>${e.date || "—"}</td>
        <td>${e.password_masked || (e.has_password ? (e.hash_only ? "hashed" : "yes") : "—")}</td>
        <td>${canEdit() && e.password_sha256 && !e.hash_only ? html`<button class="btn sm ghost" data-sj="reveal" data-id="${e.identifier}|${e.breach}|${e.password_sha256}" title="Reveal the plaintext (records the reason, needs the case's legal authorisation and, where set, a second approver)">Reveal</button>` : ""}</td></tr>`)}</tbody></table></div>`
      : html`<p class="muted small">No exposures loaded. ${s.breaches?.length ? "" : "Run a look-up, with a breach provider configured."}</p>`}`;
}

async function loadPanel(kind, target) {
  const path = `${base()}/${enc(current.id)}`;
  try {
    if (kind === "graph") return drawGraph(target, await api.get(`${path}/graph`));
    if (kind === "breaches") return setHTML(target, breachesPanel(await api.get(`${path}/breaches`)));
    if (kind === "groups") setHTML(target, groupsPanel(await api.get(`${path}/clusters`)));
    if (kind === "timeline") setHTML(target, timelinePanel(await api.get(`${path}/timeline?include_open=${timelineOpen}`)));
    if (kind === "associates") setHTML(target, associatesPanel(await api.get(`${path}/associates`)));
    if (kind === "dossier") setHTML(target, dossierPanel(await api.get(`${path}/dossier`)));
  } catch (err) { setHTML(target, html`<p class="error-text">${err.message}</p>`); }
}

function subjectCard(s) {
  const running = s.status === "running";
  const shown = s.candidates.filter((c) => filter === "all" || c.status === filter);
  return html`<div class="card card-pad" style="margin-top:16px">
    <div class="card-head"><h2>${ico("persona")}${s.name}</h2>
      ${canEdit() ? html`<span style="display:flex;gap:6px;flex-wrap:wrap">
        ${running ? html`<button class="btn sm ghost" data-sj="stop">Stop</button>` : html`<button class="btn sm primary" data-sj="run">${ico("search")}Search from what is known</button>`}
        <button class="btn sm ghost" data-sj="edit">Edit known details</button>
        <label class="btn sm ghost" style="cursor:pointer">${ico("plus")}Photo<input type="file" accept="image/*" data-sj-photo hidden></label>
        <button class="btn sm ghost" data-sj="watch" title="Search again every week and raise an alert when new candidates turn up">${ico("eye")}${s.watch ? "Stop watching" : "Watch weekly"}</button>
        <button class="btn sm ghost icon" data-sj="delete" aria-label="Remove this person">${ico("trash")}</button></span>` : ""}</div>
    ${knownSummary(s)}
    ${canEdit() ? html`<label class="small" title="After each search, the pages of new likely candidates (up to 10) are preserved as evidence, before anyone confirms them"><input type="checkbox" data-sj-opt="capture_likely" ${s.options?.capture_likely ? "checked" : ""}> Preserve likely candidates' pages after each search</label>` : ""}
    ${s.watch ? html`<p class="muted small">${ico("eye")}Watched: next search ${formatDate(s.next_watch_at)}.${s.last_watch ? ` Last: ${s.last_watch.outcome}${s.last_watch.detail ? ` (${s.last_watch.detail})` : ""}.` : ""}</p>` : ""}
    ${canEdit() && !running ? html`<div class="small" style="display:flex;gap:12px;flex-wrap:wrap;align-items:center">
      <label><input type="checkbox" id="sj-run-confirm"> Legitimate purpose (${caseRef.purpose})</label>
      <label>Follow what is found <select class="select" id="sj-rounds" style="max-width:170px"><option value="1">known details only</option><option value="2" selected>one step further</option><option value="3">two steps further</option></select></label>
      <label><input type="checkbox" id="sj-fresh"> Search everything again</label></div>` : ""}
    ${suggestionsView(s)}
    ${runView(s.run)}
    ${deeperView(s)}
    <div class="card-head" style="margin-top:16px"><h3>Candidates</h3>
      <div class="segmented" role="group" aria-label="Candidates shown">${[["open", `To review (${s.counts.open})`], ["confirmed", `Theirs (${s.counts.confirmed})`], ["rejected", `Not theirs (${s.counts.rejected})`], ["all", "All"]].map(([k, label]) => html`<button class="${filter === k ? "active" : ""}" aria-pressed="${filter === k}" data-sj="filter" data-id="${k}">${label}</button>`)}</div></div>
    <p class="muted small">Each is scored against what is known: the same name, photo, town or employer, links to a known account, a known address shown on it. These are possibilities, never identifications: confirm only what you have checked.</p>
    ${shown.length ? html`<div style="overflow-x:auto"><table class="table"><tbody>${shown.map(candidateRow)}</tbody></table></div>`
      : html`<p class="muted small">${s.run ? "Nothing here." : "Search from what is known to find candidates."} Sources are incomplete, so this is not proof of absence.</p>`}
  </div>`;
}

function draw() {
  if (!el) return;
  setHTML(el, html`<div class="card card-pad">
    <div class="card-head"><h2>${ico("persona")}People</h2>${canEdit() && !editing ? html`<button class="btn sm ghost" data-sj="new">${ico("plus")}Person</button>` : ""}</div>
    <p class="muted small">Enter everything already known about a person (names, usernames, email addresses, phone numbers, account links, town, employer) and Argus searches from all of it at once, through this case's route${caseRef.opsec_mode === "anonymous" ? ", using passive sources only (anonymous case)" : ""}. What it finds is scored against what you know, for you to confirm or reject.</p>
    ${people.length > 1 ? html`<div class="segmented" role="group" aria-label="Person">${people.map((p) => html`<button class="${current?.id === p.id ? "active" : ""}" aria-pressed="${current?.id === p.id}" data-sj="pick" data-id="${p.id}">${p.name}${p.counts.open ? ` (${p.counts.open})` : ""}</button>`)}</div>` : ""}
    ${editing && canEdit() ? html`<div style="margin-top:12px">${knownForm(current && people.length && editing === "edit" ? current : null)}</div>` : ""}
  </div>${current && editing !== true ? subjectCard(current) : ""}`);
}

async function reload(id = current?.id) {
  people = await api.get(base());
  current = id ? await api.get(`${base()}/${enc(id)}`) : null;
  draw();
  poll();
}

export function initSubjects(root, changed) {
  onChanged = changed;
  on(root, "click", "[data-sj]", async (e, btn) => {
    e.preventDefault();
    const { sj, id } = btn.dataset;
    try {
      if (sj === "new") { editing = true; return draw(); }
      if (sj === "edit") { editing = "edit"; return draw(); }
      if (sj === "cancel-edit") { editing = false; return draw(); }
      if (sj === "filter") { filter = id; return draw(); }
      if (sj === "pick") return await reload(id);
      const path = `${base()}/${enc(current.id)}`;
      if (sj === "run") {
        if (!$("#sj-run-confirm")?.checked) return toast("Confirm there is a legitimate purpose first", "error");
        current = await api.post(`${path}/run`, { confirmed: true, rounds: Number($("#sj-rounds").value), fresh: $("#sj-fresh").checked });
        toast("Searching from everything known: candidates appear below as they are found", "success");
        draw();
        return poll();
      }
      if (sj === "stop") { current = await api.post(`${path}/run/cancel`); return draw(); }
      if (sj === "watch") { current = await api.put(`${path}/watch`, { on: !current.watch }); return draw(); }
      if (sj === "delete") {
        if (!window.confirm(`Remove ${current.name} and everything found for them from this case?`)) return;
        await api.del(path);
        current = null;
        return await renderSubjects(el, caseRef);
      }
      if (sj === "confirm") {
        current = await api.post(`${path}/candidates/${enc(id)}/confirm`, { search: true });
        const found = (current.suggestions || []).filter((x) => x.candidate === id && x.status === "pending").length;
        toast(`Added to the known details and the case.${current.search_refused ? ` ${current.search_refused}` : current.status === "running" ? " Searching from it." : ""}${found ? ` ${found} more detail${found === 1 ? "" : "s"} found on it to review.` : ""}`, "success", 7000);
        onChanged({ quiet: true });
        draw();
        return poll();
      }
      if (sj === "reject") { current = await api.post(`${path}/candidates/${enc(id)}/reject`, {}); return draw(); }
      if (sj === "accept-sugg" || sj === "dismiss-sugg") {
        const ids = [...el.querySelectorAll("[data-sugg]:checked")].map((b) => b.value);
        if (!ids.length) return toast("Tick the details first", "error");
        current = await api.post(`${path}/suggestions/${sj === "accept-sugg" ? "accept" : "dismiss"}`, { ids, search: true });
        if (sj === "accept-sugg") toast(current.search_refused || current.search_note || (current.status === "running" ? "Added to the known details; searching from them" : "Added to the known details"), current.search_refused ? "error" : "success", 6000);
        draw();
        return poll();
      }
      if (sj === "run-breaches") {
        const r = await api.post(`${path}/breaches`);
        const stealer = r.summary.stealer?.infections ? `, ${r.summary.stealer.site_count} site(s) from infostealer logs` : "";
        toast(`${r.summary.exposures} exposure(s), ${r.summary.reuse.length} reused password group(s)${stealer}${r.scored ? `, ${r.scored} candidate(s) scored up` : ""}`, "success", 7000);
        return loadPanel("breaches", el.querySelector('[data-sj-panel="breaches"]'));
      }
      if (sj === "reveal") {
        const [identifier, breach, hash] = id.split("|");
        const reason = window.prompt("This reveals a leaked password in clear. Why is it needed? (recorded in the audit log)");
        if (!reason) return;
        try {
          const r = await api.post(`${path}/breaches/reveal`, { identifier, breach, hash, reason });
          window.alert(`${identifier} — ${breach}\n\nPassword: ${r.password}\n\n${r.warning}`);
        } catch (err) {
          toast(err.detail?.summary ? "A second administrator must approve this reveal" : err.message, "error", 8000);
        }
        return;
      }
      if (sj === "dossier") {
        if (!$("#sj-ai-ok")?.checked) return toast("Confirm that the material may be sent to Anthropic first", "error");
        const label = btn.textContent;
        btn.disabled = true;
        btn.textContent = "Writing… (up to a minute)";
        try {
          const d = await api.post(`${path}/dossier`, { ai_acknowledged: true });
          const panel = el.querySelector('[data-sj-panel="dossier"]');
          if (panel) setHTML(panel, dossierPanel(d));
        } finally {
          if (btn.isConnected) { btn.disabled = false; btn.textContent = label; }
        }
        return;
      }
      if (sj === "reopen") { current = await api.post(`${path}/candidates/${enc(id)}/reopen`); return draw(); }
    } catch (err) { toast(err.message, "error", 8000); }
  });
  root.addEventListener("toggle", (e) => {
    const box = e.target;
    if (!(box instanceof HTMLDetailsElement) || !box.open || !box.dataset.sjLoad || !current) return;
    loadPanel(box.dataset.sjLoad, box.querySelector("[data-sj-panel]"));
  }, true);
  root.addEventListener("change", async (e) => {
    if (e.target.matches("[data-sj-opt]") && current) {
      try {
        current = await api.put(`${base()}/${enc(current.id)}/options`, { [e.target.dataset.sjOpt]: e.target.checked });
        toast(e.target.checked ? "Likely candidates' pages will be preserved after each search" : "Only confirmed accounts are preserved", "success");
      } catch (err) { toast(err.message, "error", 8000); }
      return;
    }
    if (e.target.matches("[data-sj-open]")) {
      timelineOpen = e.target.checked;
      return loadPanel("timeline", el.querySelector('[data-sj-panel="timeline"]'));
    }
    if (!e.target.matches("[data-sj-photo]") || !current) return;
    const file = e.target.files[0];
    if (!file) return;
    const form = new FormData();
    form.append("file", file);
    try {
      current = await request(`${base()}/${enc(current.id)}/photo`, { method: "POST", body: form });
      toast("Photo fingerprint kept (not the photo itself); candidates scored again", "success");
      draw();
    } catch (err) { toast(err.message, "error", 8000); }
  });
  root.addEventListener("submit", async (e) => {
    if (e.target.id !== "sj-form") return;
    e.preventDefault();
    const body = readForm();
    try {
      if (editing === "edit" && current) {
        current = await api.put(`${base()}/${enc(current.id)}`, body);
      } else {
        current = await api.post(base(), { ...body, confirmed: $("#sj-confirm").checked });
      }
      editing = false;
      await reload(current.id);
    } catch (err) { $("#sj-error").textContent = err.message; }
  });
}
