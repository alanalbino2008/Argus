// The People tab of a case: everything already known about a person, one search from all of it,
// and the accounts, addresses and records found, scored against what is known, to confirm or reject.

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
      employer: $("#sj-employer").value.trim(), birth_year: born ? Number(born) : null } };
}

function knownSummary(s) {
  const k = s.known;
  const chips = [...LISTS.flatMap(([key]) => (k[key] || []).map((v) => [key, v])),
    ...(k.city ? [["city", k.city]] : []), ...(k.employer ? [["employer", k.employer]] : []), ...(k.birth_year ? [["born", `born ${k.birth_year}`]] : [])];
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
      ${c.agree?.length ? html`<div class="small" style="color:var(--ok)">${ico("check")}${c.agree.join("; ")}</div>` : ""}
      ${c.conflict?.length ? html`<div class="small error-text">${c.conflict.join("; ")}</div>` : ""}
      ${c.note ? html`<div class="muted small">Note: ${c.note}</div>` : ""}</td>
    <td style="white-space:nowrap">${safeUrl(c.url) ? html`<a href="${c.url}" target="_blank" rel="noopener noreferrer" class="small">${ico("external")}Open</a>` : ""}
      ${canEdit() && c.status === "open" ? html` <button class="btn sm" data-sj="confirm" data-id="${c.id}" title="It is theirs: add it to the known details and the case">${ico("check")}Theirs</button>
        <button class="btn sm ghost" data-sj="reject" data-id="${c.id}" title="Not theirs: never suggest it again">Not theirs</button>` : ""}
      ${canEdit() && c.status === "rejected" ? html` <button class="btn sm ghost" data-sj="reopen" data-id="${c.id}">Undo</button>` : ""}</td></tr>`;
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
    ${s.watch ? html`<p class="muted small">${ico("eye")}Watched: next search ${formatDate(s.next_watch_at)}.${s.last_watch ? ` Last: ${s.last_watch.outcome}${s.last_watch.detail ? ` (${s.last_watch.detail})` : ""}.` : ""}</p>` : ""}
    ${canEdit() && !running ? html`<div class="small" style="display:flex;gap:12px;flex-wrap:wrap;align-items:center">
      <label><input type="checkbox" id="sj-run-confirm"> Legitimate purpose (${caseRef.purpose})</label>
      <label>Follow what is found <select class="select" id="sj-rounds" style="max-width:170px"><option value="1">known details only</option><option value="2" selected>one step further</option><option value="3">two steps further</option></select></label>
      <label><input type="checkbox" id="sj-fresh"> Search everything again</label></div>` : ""}
    ${runView(s.run)}
    <div class="card-head" style="margin-top:16px"><h3>Candidates</h3>
      <div class="segmented" role="tablist" aria-label="Candidates shown">${[["open", `To review (${s.counts.open})`], ["confirmed", `Theirs (${s.counts.confirmed})`], ["rejected", `Not theirs (${s.counts.rejected})`], ["all", "All"]].map(([k, label]) => html`<button class="${filter === k ? "active" : ""}" data-sj="filter" data-id="${k}">${label}</button>`)}</div></div>
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
    ${people.length > 1 ? html`<div class="segmented" role="tablist" aria-label="Person">${people.map((p) => html`<button class="${current?.id === p.id ? "active" : ""}" data-sj="pick" data-id="${p.id}">${p.name}${p.counts.open ? ` (${p.counts.open})` : ""}</button>`)}</div>` : ""}
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
        toast(current.search_refused ? `Added to the known details and the case. ${current.search_refused}` : "Added to the known details and the case; searching from it", "success", 6000);
        onChanged({ quiet: true });
        draw();
        return poll();
      }
      if (sj === "reject") { current = await api.post(`${path}/candidates/${enc(id)}/reject`, {}); return draw(); }
      if (sj === "reopen") { current = await api.post(`${path}/candidates/${enc(id)}/reopen`); return draw(); }
    } catch (err) { toast(err.message, "error", 8000); }
  });
  root.addEventListener("change", async (e) => {
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
