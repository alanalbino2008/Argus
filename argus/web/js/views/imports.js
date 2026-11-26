// The Data tab of a case: import lawfully obtained call records, statements, contact lists and phone
// extractions, and see who appears in them and which of them the case already holds.

import { api, enc, request } from "../api.js";
import { ico } from "../components.js";
import { $, formatDate, html, on, setHTML, toast } from "../dom.js";
import { state } from "../state.js";

const canEdit = () => ["analyst", "admin"].includes(state.workspace?.role);
const KINDS = [["auto", "Recognise it"], ["cdr", "Call records (CSV, XLSX)"], ["transactions", "Bank or payment statement (CSV, XLSX)"],
  ["contacts", "Contact list (CSV, XLSX; XRY exports)"], ["ufdr", "Cellebrite UFDR phone extraction"]];
let el = null;
let caseRef = null;
let imports = [];
let opened = null;

export async function renderImports(target, caseObj) {
  el = target;
  caseRef = caseObj;
  el.dataset.mode = "imports";
  imports = await api.get(`/api/cases/${enc(caseObj.id)}/imports`);
  draw();
}

function when(v) { return v ? formatDate(v) : "—"; }

function partyRow(e) {
  return html`<tr><td style="word-break:break-all"><b>${e.identifier}</b>${e.names?.length ? html`<div class="muted small">${e.names.join(", ")}</div>` : ""}</td>
    <td>${e.count}</td>${"paid_in" in e ? html`<td>${e.paid_in.toFixed(2)}</td><td>${e.paid_out.toFixed(2)}</td>` : ""}
    <td class="small">${when(e.first)}<br>${when(e.last)}</td>
    <td class="small">${(e.in_case || []).map((m) => html`<div>${ico("check")}${m.where}</div>`)}</td></tr>`;
}

function analysisView(a) {
  const money = a.import.kind === "transactions";
  const head = html`<tr><th>${money ? "Counterparty" : "Number, address or account"}</th><th>Records</th>${money ? html`<th>Paid in</th><th>Paid out</th>` : ""}<th>First / last</th><th>In the case</th></tr>`;
  const max = Math.max(1, ...Object.values(a.hours_utc || {}));
  return html`<div class="card card-pad" style="margin-top:16px">
    <div class="card-head"><h2>${a.import.label}: ${a.import.filename}</h2><span class="muted small">evidence ${a.evidence.id}</span></div>
    <p class="small">${a.records} records${a.from ? ` from ${when(a.from)} to ${when(a.to)}` : ""} · ${Object.entries(a.types).map(([k, n]) => `${n} ${k}`).join(", ")}</p>
    ${Object.keys(a.hours_utc || {}).length ? html`<div role="img" aria-label="Records by hour" style="display:flex;align-items:flex-end;gap:2px;height:50px">${Array.from({ length: 24 }, (_, h) => html`<div title="${h}:00: ${(a.hours_utc[String(h)] || 0)}" style="flex:1;background:var(--accent);opacity:.75;height:${Math.round(((a.hours_utc[String(h)] || 0) / max) * 100)}%;min-height:1px"></div>`)}</div><div class="muted small">Records by hour of the day, 00:00 to 23:00 (the time zone of the records)</div>` : ""}
    <h3 style="margin-top:12px">Already in the case (${a.in_case.length})</h3>
    ${a.in_case.length ? html`<div style="overflow-x:auto"><table class="table"><thead>${head}</thead><tbody>${a.in_case.map(partyRow)}</tbody></table></div>`
      : html`<p class="muted small">None of these numbers, addresses, accounts or names is in the case yet.</p>`}
    <h3 style="margin-top:12px">Most frequent</h3>
    <div style="overflow-x:auto"><table class="table"><thead>${head}</thead><tbody>${a.top.slice(0, 25).map(partyRow)}</tbody></table></div>
    <p class="muted small">Matching uses the last nine digits of phone numbers, exact addresses and usernames, and close names. Every reading of an import is recorded in the audit log.</p></div>`;
}

function draw() {
  if (!el) return;
  const authorised = Boolean((caseRef.authorization || "").trim());
  setHTML(el, html`<div class="card card-pad">
    <div class="card-head"><h2>${ico("download")}Data</h2></div>
    <p class="muted small">Import data obtained lawfully for this case: call detail records, bank or payment statements, contact lists and Cellebrite UFDR phone extractions. The file is kept as evidence with its fingerprint and chain of custody, its records beside it, and they are compared with the numbers, addresses, usernames and names already in the case.</p>
    ${!authorised ? html`<p class="error-text">Record the case's legal authorisation (warrant, court order or ticket) before importing: these files hold other people's communications and money.</p>
      ${canEdit() ? html`<form id="imp-auth" style="display:flex;gap:8px;flex-wrap:wrap;max-width:560px"><input id="imp-auth-value" class="input" style="flex:1" maxlength="300" required placeholder="e.g. Production order 2026/0412"><button class="btn" type="submit">${ico("shield")}Record it</button></form>` : ""}`
      : html`<p class="muted small">${ico("shield")}Authorisation: ${caseRef.authorization}</p>`}
    ${canEdit() && authorised && caseRef.status === "open" ? html`<form id="imp-form" style="display:grid;gap:8px;max-width:560px">
      <input type="file" id="imp-file" class="input" required accept=".csv,.tsv,.txt,.xlsx,.ufdr,.zip">
      <select id="imp-kind" class="select">${KINDS.map(([k, label]) => html`<option value="${k}">${label}</option>`)}</select>
      <input id="imp-note" class="input" maxlength="500" placeholder="Note (e.g. where it came from, the disclosure reference)">
      <p class="error-text" id="imp-error"></p>
      <div><button class="btn primary" type="submit">${ico("plus")}Import</button></div></form>` : ""}
    ${imports.length ? html`<div class="list" style="margin-top:12px">${imports.map((i) => html`<div class="list-row clickable" data-imp="${i.id}">
      <div class="list-main"><div class="list-title">${i.data_import.label}: ${i.data_import.filename}</div>
      <div class="list-sub">${i.data_import.records} records · ${i.captured_by} · ${formatDate(i.captured_at)}</div></div>${ico("external")}</div>`)}</div>`
      : html`<p class="muted small" style="margin-top:12px">Nothing imported yet.</p>`}
  </div>${opened ? analysisView(opened) : ""}`);
}

export function initImports(root) {
  on(root, "click", "[data-imp]", async (e, row) => {
    try {
      opened = await api.get(`/api/cases/${enc(caseRef.id)}/imports/${enc(row.dataset.imp)}`);
      draw();
    } catch (err) { toast(err.message, "error", 8000); }
  });
  root.addEventListener("submit", async (e) => {
    if (e.target.id === "imp-auth") {
      e.preventDefault();
      try {
        caseRef = { ...caseRef, ...(await api.patch(`/api/cases/${enc(caseRef.id)}`, { authorization: $("#imp-auth-value").value.trim() })) };
        toast("Legal authorisation recorded", "success");
        draw();
      } catch (err) { toast(err.message, "error", 8000); }
      return;
    }
    if (e.target.id !== "imp-form") return;
    e.preventDefault();
    const file = $("#imp-file").files[0];
    if (!file) return;
    const form = new FormData();
    form.append("file", file);
    form.append("kind", $("#imp-kind").value);
    form.append("note", $("#imp-note").value.trim());
    try {
      const made = await request(`/api/cases/${enc(caseRef.id)}/imports`, { method: "POST", body: form });
      toast(`${made.data_import.records} records imported as evidence`, "success");
      imports = await api.get(`/api/cases/${enc(caseRef.id)}/imports`);
      opened = await api.get(`/api/cases/${enc(caseRef.id)}/imports/${enc(made.id)}`);
      draw();
    } catch (err) { $("#imp-error").textContent = err.message; }
  });
}
