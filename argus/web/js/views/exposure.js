// Breach and dark-web exposure: watched domains, findings by urgency, triage and export.
// Staff addresses are masked unless an analyst reveals them (audited).

import { api, download, enc } from "../api.js";
import { empty, ico, severityPill } from "../components.js";
import { $, closeModal, confirmDialog, formatDay, html, on, openModal, setHTML, timeAgo, toast } from "../dom.js";
import { on as onState, state } from "../state.js";

let root;
let data = null;
let status = "open";
let reveal = false;
let triage = { ids: [], status: "resolved" };

const SECTIONS = [
  { kind: "stealer_log", title: "Infostealer infections", icon: "alert",
    advice: "Malware on someone's device captured their saved passwords and session cookies. Reset the password, revoke active sessions and MFA tokens for the sites listed, and clean or re-image the device: a new password alone does not help while the malware is still there." },
  { kind: "ransomware_post", title: "Ransomware leak sites", icon: "alert",
    advice: "A ransomware group claims to have attacked this organisation. For your own domain, start incident response now. For a supplier, contact them, find out what data of yours they held, and consider your notification duties." },
  { kind: "domain_breach", title: "Breaches of the organisation", icon: "breach",
    advice: "The organisation itself was breached. Check what data was taken and that the weakness behind the breach has been fixed. For a supplier, ask for their incident report." },
  { kind: "breach_account", title: "Staff accounts in breaches", icon: "email",
    advice: "Staff used work addresses on services that were breached. Where passwords were exposed, force a reset and check the password was not reused for work systems. Enforce MFA, and block known-breached passwords." },
];
const SOURCE_LABEL = { breach_catalogue: "Breach catalogue", domain_search: "Domain search", stealer_logs: "Stealer logs", ransomware: "Ransomware leak sites" };

const canEdit = () => ["analyst", "admin"].includes(state.workspace?.role);
const subjectLabel = (f) => (f.supplier_id ? html`<span class="pill">supplier</span> ${f.subject_name}` : f.subject_name);
const account = (f) => html`<span class="mono">${reveal && f.account ? f.account : f.account_masked}</span>`;

function sourcePills(w) {
  return Object.entries(w.sources || {}).map(([name, r]) => html`<span class="pill ${r.status === "ok" ? "ok" : r.status === "error" ? "critical" : ""}" title="${r.message || `${r.found || 0} result(s)`}">${SOURCE_LABEL[name] || name}</span>`);
}

function watchesCard() {
  const watches = data.watches;
  return html`<div class="card card-pad">
    <div class="card-head"><div><h2>Watched</h2><p class="muted small">Each domain is checked daily. Your supplier register is swept for breaches and ransomware posts automatically.</p></div></div>
    ${!watches.length ? empty("eye", "Nothing watched yet", "Add your organisation's domain to find breached staff accounts, infostealer infections and ransomware leak-site posts.")
      : html`<div class="table-scroll"><table class="table"><thead><tr><th>What</th><th>Last check</th><th class="hide-sm">Sources</th><th></th></tr></thead><tbody>
      ${watches.map((w) => html`<tr style="${w.enabled ? "" : "opacity:.6"}">
        <td><b>${w.scope === "suppliers" ? "Supplier register" : w.domain}</b>${w.demo ? html` <span class="pill">demo</span>` : ""}
          <div class="muted small">${w.scope === "suppliers" ? "Public breach and ransomware reports about every supplier" : w.organisation || ""}</div></td>
        <td>${w.last_checked_at ? html`${timeAgo(w.last_checked_at)}<div class="muted small">${w.last_status === "ok" ? "" : w.last_message || ""}</div>` : html`<span class="muted">pending</span>`}</td>
        <td class="hide-sm"><div style="display:flex;gap:4px;flex-wrap:wrap">${sourcePills(w)}</div></td>
        <td class="actions">${canEdit() && !w.demo ? html`<button class="btn sm ghost" data-act="check" data-id="${w.id}" title="Check now">${ico("compare")}</button>
          <button class="btn sm ghost" data-act="toggle" data-id="${w.id}" data-enabled="${w.enabled}">${w.enabled ? "Pause" : "Resume"}</button>` : ""}
          ${state.workspace?.role === "admin" && w.scope === "domain" ? html`<button class="btn sm ghost icon" data-act="remove" data-id="${w.id}" aria-label="Stop watching ${w.domain}" title="Stop watching">${ico("trash")}</button>` : ""}</td>
      </tr>`)}</tbody></table></div>`}
  </div>`;
}

function details(f) {
  const d = f.details || {};
  if (f.kind === "stealer_log") return html`Credentials for ${d.website_count} site${d.website_count === 1 ? "" : "s"}: <span class="mono">${(d.websites || []).slice(0, 6).join(", ")}</span>`;
  if (f.kind === "ransomware_post") return html`${d.group} · posted ${d.published ? formatDay(d.published) : "?"}${d.sector ? ` · ${d.sector}` : ""}${d.match === "name" ? html` · <b>matched by name only: verify</b>` : ""}`;
  return html`${d.breach_date ? `Breached ${formatDay(d.breach_date)}` : ""}${(d.data_classes || []).length ? ` · ${d.data_classes.slice(0, 5).join(", ")}` : ""}`;
}

function actions(ids, current) {
  if (!canEdit()) return "";
  const list = ids.join(",");
  return current === "open"
    ? html`<button class="btn sm" data-act="triage" data-ids="${list}" data-status="resolved">${ico("check")}Resolved</button>
           <button class="btn sm ghost" data-act="triage" data-ids="${list}" data-status="accepted">Accept risk</button>`
    : html`<button class="btn sm ghost" data-act="triage" data-ids="${list}" data-status="open">Reopen</button>`;
}

function accountRows(findings) {
  const byAccount = new Map();
  findings.forEach((f) => {
    const k = `${f.subject}|${f.account_masked}|${f.account || ""}|${f.status}`;
    if (!byAccount.has(k)) byAccount.set(k, []);
    byAccount.get(k).push(f);
  });
  const order = { critical: 4, high: 3, medium: 2, low: 1 };
  const groups = [...byAccount.values()].sort((a, b) => Math.max(...b.map((f) => order[f.severity])) - Math.max(...a.map((f) => order[f.severity])));
  return groups.map((fs) => {
    const top = fs.reduce((a, b) => (order[b.severity] > order[a.severity] ? b : a));
    return html`<div class="list-row">
      ${severityPill(top.severity)}
      <div class="list-main"><div class="list-title">${account(top)}</div>
        <div class="list-sub">${fs.map((f) => html`<span class="pill ${f.severity}" title="${(f.details.data_classes || []).join(", ")}">${f.details.breach_title}</span> `)}
          ${fs.some((f) => (f.details.data_classes || []).some((c) => /password/i.test(c))) ? html`<b>passwords exposed</b>` : html`<span class="muted">no passwords</span>`}</div></div>
      ${actions(fs.map((f) => f.id), top.status)}
    </div>`;
  });
}

function findingsCard() {
  const findings = data.findings;
  return html`<div class="card card-pad" style="margin-top:16px">
    <div class="card-head"><div><h2>Findings</h2><p class="muted small">Most urgent first. Mark a finding resolved when you have dealt with it, or accept the risk; either way it stays on record.</p></div>
      <div class="segmented" role="tablist">${["open", "resolved", "accepted", "all"].map((s) => html`<button class="${status === s ? "active" : ""}" data-status-filter="${s}">${s[0].toUpperCase() + s.slice(1)}</button>`)}</div></div>
    ${!findings.length ? empty("check", status === "open" ? "Nothing open" : "Nothing here", status === "open" ? "No open exposure. New findings appear here after each check, and alert your notification channels." : "")
      : SECTIONS.map((sec) => {
        const items = findings.filter((f) => f.kind === sec.kind);
        if (!items.length) return "";
        const count = sec.kind === "breach_account" ? new Set(items.map((f) => `${f.subject}|${f.account_masked}|${f.account || ""}`)).size : items.length;
        return html`<div class="section"><div class="section-title">${ico(sec.icon)} ${sec.title} <span class="muted">(${count})</span></div>
          <div class="guide-warning info" style="margin-bottom:8px">${ico("info")}<div class="small">${sec.advice}</div></div>
          <div class="list">${sec.kind === "breach_account" ? accountRows(items) : items.map((f) => html`<div class="list-row">
            ${severityPill(f.severity)}
            <div class="list-main"><div class="list-title" style="white-space:normal">${f.title}${f.account_masked ? html` · ${account(f)}` : ""}</div>
              <div class="list-sub">${subjectLabel(f)} · ${details(f)} · first seen ${timeAgo(f.first_seen_at)}${f.note ? html` · <i>${f.note}</i>` : ""}</div></div>
            ${actions([f.id], f.status)}
          </div>`)}</div></div>`;
      })}
  </div>`;
}

function render() {
  const s = data.summary;
  const caps = data.capabilities;
  setHTML(root, html`<div class="page">
    <div class="page-head">
      <div><h1>Exposure</h1><p>Breached staff accounts, infostealer infections and ransomware leak-site posts about your organisation and suppliers. Only metadata is collected: never passwords or stolen files.</p></div>
      <div class="page-actions">
        ${canEdit() ? html`<button class="btn sm" data-act="reveal" aria-pressed="${reveal}">${ico("eye")}${reveal ? "Mask addresses" : "Show addresses"}</button>
          <button class="btn sm" data-act="export">${ico("download")}Export for resets</button>
          <button class="btn sm primary" data-act="add">${ico("plus")}Watch a domain</button>` : ""}
      </div>
    </div>
    ${!caps.domain_search ? html`<div class="guide-warning info" style="margin-bottom:16px">${ico("info")}<div class="small">Breached staff accounts and infostealer infections need a <b>Have I Been Pwned</b> API key (<code>ARGUS_HIBP_API_KEY</code>), and HIBP only answers for domains you have verified you own. Breaches of organisations and ransomware leak-site posts work without one.</div></div>` : ""}
    <div class="grid kpis" style="margin-bottom:16px">
      <div class="card card-pad"><b style="font-size:24px;color:${s.by_kind.stealer_log ? "var(--sev-critical)" : "inherit"}">${s.by_kind.stealer_log}</b><div class="muted small">infostealer infections</div></div>
      <div class="card card-pad"><b style="font-size:24px;color:${s.by_kind.ransomware_post ? "var(--sev-critical)" : "inherit"}">${s.by_kind.ransomware_post}</b><div class="muted small">ransomware leak-site posts</div></div>
      <div class="card card-pad"><b style="font-size:24px">${s.accounts}</b><div class="muted small">staff accounts in breaches</div></div>
      <div class="card card-pad"><b style="font-size:24px">${s.by_kind.domain_breach}</b><div class="muted small">breaches of you or your suppliers</div></div>
    </div>
    ${watchesCard()}
    ${findingsCard()}
  </div>`);
}

export async function refresh() {
  if (!root) return;
  try {
    data = await api.get(`/api/exposure?status=${status}${reveal ? "&reveal=true" : ""}`);
  } catch (err) {
    setHTML(root, html`<div class="page"><p class="error-text">${err.message}</p></div>`);
    return;
  }
  render();
}

export function initExposure(el) {
  root = el;
  onState("workspace", () => { data = null; reveal = false; });
  on(root, "click", "[data-status-filter]", (_e, btn) => { status = btn.dataset.statusFilter; refresh(); });
  on(root, "click", "[data-act]", async (_e, btn) => {
    const { act, id } = btn.dataset;
    try {
      if (act === "add") { $("#exposure-form").reset(); $("#exp-error").textContent = ""; return openModal("exposure-modal"); }
      if (act === "reveal") { reveal = !reveal; if (reveal) toast("Full addresses shown. This is recorded in the audit log.", "info", 4000); return refresh(); }
      if (act === "export") return download("/api/exposure/export.csv", "exposure.csv");
      if (act === "triage") {
        triage = { ids: btn.dataset.ids.split(","), status: btn.dataset.status };
        if (triage.status === "open") { await api.post("/api/exposure/findings/status", { ids: triage.ids, status: "open" }); return refresh(); }
        $("#triage-title").textContent = triage.status === "resolved" ? "Mark as resolved" : "Accept the risk";
        $("#triage-note").value = "";
        $("#triage-note").placeholder = triage.status === "resolved" ? "e.g. Password reset, sessions revoked, device re-imaged" : "e.g. Shared mailbox with no login; no action needed";
        return openModal("triage-modal");
      }
      if (act === "check") { await api.post(`/api/exposure/watches/${enc(id)}/check`); toast("Checking now. Results appear in a minute or two.", "success"); }
      if (act === "toggle") await api.patch(`/api/exposure/watches/${enc(id)}`, { enabled: btn.dataset.enabled !== "true" });
      if (act === "remove") {
        if (!(await confirmDialog({ title: "Stop watching this domain?", message: "Its findings are deleted too.", confirm: "Stop watching", danger: true }))) return;
        await api.del(`/api/exposure/watches/${enc(id)}`);
        toast("No longer watched");
      }
      await refresh();
    } catch (err) {
      toast(err.message, "error");
    }
  });
  $("#triage-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const r = await api.post("/api/exposure/findings/status", { ids: triage.ids, status: triage.status, note: $("#triage-note").value.trim() });
      closeModal("triage-modal");
      toast(`${r.updated} finding${r.updated === 1 ? "" : "s"} updated`, "success");
      await refresh();
    } catch (err) {
      toast(err.message, "error");
    }
  });
  $("#exposure-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const error = $("#exp-error");
    if (!$("#exp-authorized").checked) return (error.textContent = "Confirm this is your organisation's domain, or one you are engaged to protect.");
    try {
      const w = await api.post("/api/exposure/watches", { domain: $("#exp-domain").value.trim(), organisation: $("#exp-org").value.trim(), basis: $("#exp-basis").value.trim(), authorized: true });
      closeModal("exposure-modal");
      toast(`${w.domain} is now watched; the first check is running`, "success", 5000);
      await refresh();
    } catch (err) {
      error.textContent = err.message;
    }
  });
}
