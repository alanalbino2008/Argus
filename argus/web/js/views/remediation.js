// Remediation: tasks with deadlines, owners and proof; triage, timeline, policy and metrics.

import { api, download, enc } from "../api.js";
import { empty, ico, severityPill } from "../components.js";
import { $, closeModal, confirmDialog, formatDay, html, on, openModal, setHTML, timeAgo, toast } from "../dom.js";
import { on as onState, state } from "../state.js";

let root;
let data = null;
let filters = { status: "active", assignee: "", severity: "", overdue: false };
let current = null; // the task open in the dialog
let pendingStatus = null;

const STATUS = {
  open: ["", "Open"], in_progress: ["accent", "In progress"], fixed: ["warn", "Fixed: awaiting verification"],
  verified: ["ok", "Verified fixed"], accepted: ["", "Risk accepted"],
};
const SOURCE = { attack_path: "Attack path", exposure: "Exposure", supplier: "Supplier", manual: "Manual" };
const NEXT = {
  open: ["in_progress", "fixed", "accepted"], in_progress: ["open", "fixed", "accepted"],
  fixed: ["in_progress", "verified", "accepted", "open"], verified: ["open"], accepted: ["open"],
};
const ACTION = { open: "Reopen", in_progress: "Start work", fixed: "Mark fixed", verified: "Confirm verified", accepted: "Accept risk" };

const canEdit = () => ["analyst", "admin"].includes(state.workspace?.role);
const isAdmin = () => state.workspace?.role === "admin";

function dueLabel(t) {
  if (!t.due_at) return "";
  const raw = (new Date(t.due_at) - Date.now()) / 86400000;
  const days = raw >= 0 ? Math.ceil(raw) : Math.floor(raw);
  if (["verified", "accepted"].includes(t.status)) return html`<span class="muted small">due ${formatDay(t.due_at)}</span>`;
  if (t.overdue) return html`<b style="color:var(--sev-critical-text)">${-days} day${days === -1 ? "" : "s"} overdue</b>`;
  return html`<span class="${days <= 7 ? "" : "muted"}">${days === 0 ? "due today" : `in ${days} day${days === 1 ? "" : "s"}`}</span>`;
}

const statusPill = (t) => html`<span class="pill ${STATUS[t.status][0]}" style="text-transform:none">${STATUS[t.status][1]}</span>`;

function kpis(m) {
  const mttr = m.mttr_days;
  return html`<div class="grid kpis" style="margin-bottom:16px">
    <div class="card card-pad"><b style="font-size:24px;color:${m.overdue ? "var(--sev-critical-text)" : "inherit"}">${m.overdue}</b><div class="muted small">overdue${m.overdue ? ` (${Object.entries(m.overdue_by_severity).filter(([, n]) => n).map(([s, n]) => `${n} ${s}`).join(", ")})` : ""}</div></div>
    <div class="card card-pad"><b style="font-size:24px">${m.active}</b><div class="muted small">active · ${m.due_within_7_days} due this week · ${m.awaiting_verification} awaiting verification</div></div>
    <div class="card card-pad"><b style="font-size:24px">${m.sla_compliance === null ? "—" : `${m.sla_compliance}%`}</b><div class="muted small">closed on time (last ${m.window_days} days, ${m.closed_in_window} closed)</div></div>
    <div class="card card-pad"><b style="font-size:24px">${mttr.critical ?? "—"}<span class="muted" style="font-size:14px"> / ${mttr.high ?? "—"} days</span></b><div class="muted small">median time to verified fix: critical / high</div></div>
  </div>`;
}

function filterBar() {
  const people = data.assignees;
  return html`<div class="filters" style="margin-bottom:12px;flex-wrap:wrap">
    <div class="segmented">${[["active", "Active"], ["closed", "Closed"], ["all", "All"]].map(([v, l]) => html`<button class="${filters.status === v ? "active" : ""}" data-filter-status="${v}">${l}</button>`)}</div>
    <select class="select" id="rem-assignee" style="max-width:220px" aria-label="Assignee">
      <option value="">Everyone</option><option value="me" ${filters.assignee === "me" ? "selected" : ""}>Assigned to me</option>
      <option value="unassigned" ${filters.assignee === "unassigned" ? "selected" : ""}>Unassigned</option>
      ${people.map((p) => html`<option value="${p}" ${filters.assignee === p ? "selected" : ""}>${p}</option>`)}
    </select>
    <select class="select" id="rem-severity" style="max-width:160px" aria-label="Severity"><option value="">Any severity</option>
      ${["critical", "high", "medium", "low"].map((s) => html`<option value="${s}" ${filters.severity === s ? "selected" : ""}>${s}</option>`)}</select>
    <label class="check small"><input type="checkbox" id="rem-overdue" ${filters.overdue ? "checked" : ""}> Overdue only</label>
  </div>`;
}

function table() {
  const tasks = data.tasks;
  if (!tasks.length) {
    return filters.status === "active" && !filters.assignee && !filters.severity && !filters.overdue
      ? empty("check", "Nothing to fix right now", "Track a fix from any attack path, exposure finding or supplier, or let the policy open tasks automatically for new critical findings.")
      : empty("search", "No tasks match", "Try other filters.");
  }
  return html`<div class="table-scroll"><table class="table"><thead><tr><th>Task</th><th>Owner</th><th>Due</th><th>Status</th></tr></thead><tbody>
    ${tasks.map((t) => html`<tr class="clickable" data-open="${t.id}" tabindex="0" style="cursor:pointer">
      <td>${severityPill(t.severity)} <b>${t.title}</b>
        <div class="muted small"><span class="pill">${SOURCE[t.source_type]}</span> ${t.target}${t.external_ref ? html` · <span class="mono">${t.external_ref}</span>` : ""}${t.reopen_count ? html` · <span style="color:var(--sev-high-text)">reopened ${t.reopen_count}×</span>` : ""}</div></td>
      <td>${t.assignee || html`<span class="muted">Unassigned</span>`}</td>
      <td>${dueLabel(t)}</td>
      <td>${statusPill(t)}</td>
    </tr>`)}</tbody></table></div>`;
}

function sidebar(m) {
  const owners = Object.entries(m.by_assignee);
  const opened = m.trend.reduce((a, w) => a + w.opened, 0);
  const closed = m.trend.reduce((a, w) => a + w.closed, 0);
  return html`<div class="card card-pad">
      <div class="card-head"><h2>By owner</h2></div>
      ${owners.length ? html`<table class="table"><tbody>${owners.map(([who, n]) => html`<tr><td>${who}</td><td>${n.open} open</td><td>${n.overdue ? html`<b style="color:var(--sev-critical-text)">${n.overdue} overdue</b>` : ""}</td></tr>`)}</tbody></table>` : html`<p class="muted small">No active tasks.</p>`}
      <p class="muted small" style="margin-top:12px">Last 12 weeks: <b>${opened}</b> opened, <b>${closed}</b> closed${m.regressions ? html`, <b>${m.regressions}</b> regression${m.regressions === 1 ? "" : "s"}` : ""}.</p>
    </div>
    <div class="card card-pad" style="margin-top:16px">
      <div class="card-head"><div><h2>Policy</h2><p class="muted small">Deadlines by severity${data.policy.auto_create !== "off" ? `; new ${data.policy.auto_create === "critical" ? "critical" : "critical and high"} findings open tasks automatically` : ""}.</p></div>
        ${isAdmin() ? html`<button class="btn sm ghost" data-act="policy">Edit</button>` : ""}</div>
      <table class="table"><tbody>${Object.entries(data.policy.sla_days).map(([s, d]) => html`<tr><td>${severityPill(s)}</td><td>${d} days</td></tr>`)}</tbody></table>
    </div>`;
}

function render() {
  const m = data.metrics;
  setHTML(root, html`<div class="page">
    <div class="page-head">
      <div><h1>Remediation</h1><p>Every fix with an owner, a deadline and proof. Attack-path fixes are verified by the next comparable scan, and reopen if the problem comes back.</p></div>
      <div class="page-actions"><button class="btn sm" data-act="export">${ico("download")}Export</button>
        ${canEdit() ? html`<button class="btn sm primary" data-act="new">${ico("plus")}New task</button>` : ""}</div>
    </div>
    ${kpis(m)}
    <div class="grid" style="grid-template-columns:minmax(0,1fr) 300px;gap:16px;align-items:start" id="rem-layout">
      <div class="card card-pad">${filterBar()}${table()}</div>
      <div>${sidebar(m)}</div>
    </div>
  </div>`);
}

export async function refresh() {
  if (!root) return;
  const q = new URLSearchParams({ status: filters.status });
  if (filters.assignee) q.set("assignee", filters.assignee);
  if (filters.severity) q.set("severity", filters.severity);
  if (filters.overdue) q.set("overdue", "true");
  try {
    data = await api.get(`/api/remediation?${q}`);
  } catch (err) {
    setHTML(root, html`<div class="page"><p class="error-text">${err.message}</p></div>`);
    return;
  }
  render();
}

// ---------------------------------------------------------------------------- the task dialog
function renderTask() {
  const t = current;
  const d = t.details || {};
  const nextSteps = canEdit() ? NEXT[t.status].filter((s) => !(s === "verified" && ["attack_path", "supplier"].includes(t.source_type))) : [];
  setHTML($("#task-body"), html`
    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:8px">${severityPill(t.severity)} ${statusPill(t)} <span class="pill">${SOURCE[t.source_type]}</span>
      ${t.target ? html`<span class="mono small">${t.target}</span>` : ""} <span class="muted small">· ${dueLabel(t)}</span></div>
    ${t.description ? html`<p style="white-space:pre-wrap">${t.description}</p>` : ""}
    ${(Array.isArray(d.remediation) && d.remediation.length) ? html`<div class="section-title">How to fix</div><ol>${d.remediation.map((r) => html`<li>${r}</li>`)}</ol>` : ""}
    ${(d.evidence || []).length ? html`<details class="more"><summary>Evidence when found</summary><ul>${d.evidence.map((e) => html`<li>${e}</li>`)}</ul></details>` : ""}
    ${t.source_type === "attack_path" ? html`<p class="muted small">${ico("info")} Verified automatically when a scan at least as thorough as the original (depth ${d.scope?.max_depth ?? "?"}${d.scope?.passive_only ? ", passive" : ""}) no longer finds this path.
      ${canEdit() && !["verified", "accepted"].includes(t.status) ? html`<button type="button" class="btn sm" data-task-act="rescan">${ico("compare")}Rescan to verify</button>` : ""}</p>` : ""}
    ${canEdit() ? html`<div class="grid two" style="gap:12px;margin-top:12px">
      <div class="field"><label class="label" for="task-assignee">Owner</label><input id="task-assignee" class="input" list="task-people" value="${t.assignee || ""}" placeholder="name or email" maxlength="128"><datalist id="task-people">${data.assignees.map((p) => html`<option value="${p}">`)}</datalist></div>
      <div class="field"><label class="label" for="task-due">Due</label><input id="task-due" class="input" type="date" value="${(t.due_at || "").slice(0, 10)}"></div>
      <div class="field"><label class="label" for="task-ref">Ticket</label><input id="task-ref" class="input mono" value="${t.external_ref || ""}" placeholder="e.g. SEC-142" maxlength="128"></div>
      <div class="field" id="task-until-field" hidden><label class="label" for="task-until">Accept until</label><input id="task-until" class="input" type="date"></div>
    </div>
    <div class="field"><label class="label" for="task-note">Note</label><textarea id="task-note" class="input" rows="2" maxlength="2000" placeholder="What was done, or why: recorded on the timeline"></textarea></div>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <button type="button" class="btn primary" data-task-act="save">Save changes</button>
      ${nextSteps.map((s) => html`<button type="button" class="btn ${s === "accepted" ? "ghost" : ""}" data-task-act="status" data-status="${s}">${ACTION[s]}</button>`)}
      <button type="button" class="btn ghost" data-task-act="comment">Comment</button>
      ${isAdmin() ? html`<button type="button" class="btn ghost icon" data-task-act="delete" aria-label="Delete task" title="Delete (created by mistake)">${ico("trash")}</button>` : ""}
    </div>` : ""}
    <div class="section-title" style="margin-top:16px">Timeline</div>
    <ol class="timeline">${(t.events || []).slice().reverse().map((e) => html`<li><b>${e.by}</b> <span class="muted small">${timeAgo(e.at)}</span><div>${e.text}</div></li>`)}</ol>`);
  $("#task-title").textContent = t.title;
}

async function openTask(id) {
  current = await api.get(`/api/remediation/${enc(id)}`);
  pendingStatus = null;
  renderTask();
  openModal("task-modal");
}

async function taskAction(act, btn) {
  const id = current.id;
  const note = $("#task-note")?.value.trim() || "";
  if (act === "status") {
    const status = btn.dataset.status;
    if (status === "accepted" && pendingStatus !== "accepted") {
      pendingStatus = "accepted";
      $("#task-until-field").hidden = false;
      const until = new Date(Date.now() + 90 * 86400000);
      $("#task-until").value = until.toISOString().slice(0, 10);
      $("#task-note").placeholder = "Why is this risk acceptable? (required)";
      $("#task-note").focus();
      return toast("Set an end date and say why, then press Accept risk again", "info", 4000);
    }
    const body = { status, note };
    if (status === "accepted") body.accepted_until = new Date(`${$("#task-until").value}T23:59:59Z`).toISOString();
    current = { ...(await api.patch(`/api/remediation/${enc(id)}`, body)) };
    toast(ACTION[status] === "Mark fixed" && current.source_type === "attack_path" ? "Marked fixed. The next comparable scan will verify it." : "Updated", "success", 4000);
  } else if (act === "save") {
    const due = $("#task-due").value;
    await api.patch(`/api/remediation/${enc(id)}`, {
      assignee: $("#task-assignee").value.trim(), external_ref: $("#task-ref").value.trim() || null,
      ...(due && due !== (current.due_at || "").slice(0, 10) ? { due_at: new Date(`${due}T23:59:59Z`).toISOString() } : {}), note,
    });
    toast("Saved", "success");
  } else if (act === "comment") {
    if (!note) return toast("Write a comment first", "error");
    await api.post(`/api/remediation/${enc(id)}/comments`, { text: note });
  } else if (act === "rescan") {
    const r = await api.post(`/api/remediation/${enc(id)}/rescan`);
    toast(`Verification scan ${r.investigation_id} started`, "success", 5000);
  } else if (act === "delete") {
    if (!(await confirmDialog({ title: "Delete this task?", message: "Only for tasks created by mistake. To stop tracking a real finding, accept its risk instead, so the decision is recorded.", confirm: "Delete", danger: true }))) return;
    await api.del(`/api/remediation/${enc(id)}`);
    closeModal("task-modal");
    return refresh();
  }
  current = await api.get(`/api/remediation/${enc(id)}`);
  pendingStatus = null;
  renderTask();
  refresh();
}

/** Open (or find) the task for a finding, from any page. */
export async function trackFinding(source) {
  try {
    const task = await api.post("/api/remediation", { source });
    toast(task.created ? "Task created: it now has a deadline and an owner can be assigned" : `Already tracked (${STATUS[task.status][1].toLowerCase()})`, "success", 5000);
    return task;
  } catch (err) {
    toast(err.message, "error");
    return null;
  }
}

export function initRemediation(el) {
  root = el;
  onState("workspace", () => { data = null; filters = { status: "active", assignee: "", severity: "", overdue: false }; });
  on(root, "click", "[data-filter-status]", (_e, btn) => { filters.status = btn.dataset.filterStatus; refresh(); });
  root.addEventListener("change", (e) => {
    if (e.target.id === "rem-assignee") filters.assignee = e.target.value;
    else if (e.target.id === "rem-severity") filters.severity = e.target.value;
    else if (e.target.id === "rem-overdue") filters.overdue = e.target.checked;
    else return;
    refresh();
  });
  on(root, "click", "[data-open]", (_e, row) => openTask(row.dataset.open).catch((err) => toast(err.message, "error")));
  root.addEventListener("keydown", (e) => { if (e.key === "Enter" && e.target.dataset?.open) openTask(e.target.dataset.open); });
  on(root, "click", "[data-act]", async (_e, btn) => {
    const act = btn.dataset.act;
    if (act === "export") return download("/api/remediation/export.csv", "remediation.csv");
    if (act === "new") { $("#newtask-form").reset(); $("#newtask-error").textContent = ""; return openModal("newtask-modal"); }
    if (act === "policy") {
      Object.entries(data.policy.sla_days).forEach(([s, d]) => { $(`#sla-${s}`).value = d; });
      $("#policy-auto").value = data.policy.auto_create;
      return openModal("policy-modal");
    }
  });
  on($("#task-modal"), "click", "[data-task-act]", (_e, btn) => taskAction(btn.dataset.taskAct, btn).catch((err) => toast(err.message, "error")));
  $("#newtask-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const error = $("#newtask-error");
    const title = $("#newtask-title").value.trim();
    if (!title) return (error.textContent = "Say what needs doing.");
    try {
      const due = $("#newtask-due").value;
      const task = await api.post("/api/remediation", {
        source: { type: "manual", title, severity: $("#newtask-severity").value, target: $("#newtask-target").value.trim(), description: $("#newtask-description").value.trim() },
        assignee: $("#newtask-assignee").value.trim() || null, ...(due ? { due_at: new Date(`${due}T23:59:59Z`).toISOString() } : {}),
      });
      closeModal("newtask-modal");
      toast(`Task created, due ${formatDay(task.due_at)}`, "success");
      await refresh();
    } catch (err) {
      error.textContent = err.message;
    }
  });
  $("#policy-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const sla = Object.fromEntries(["critical", "high", "medium", "low"].map((s) => [s, Number($(`#sla-${s}`).value)]));
      await api.put("/api/remediation/policy", { sla_days: sla, auto_create: $("#policy-auto").value });
      closeModal("policy-modal");
      toast("Policy saved. New deadlines apply to new tasks.", "success");
      await refresh();
    } catch (err) {
      $("#policy-error").textContent = err.message;
    }
  });
}
