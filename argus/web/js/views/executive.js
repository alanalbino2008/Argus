// The executive view: how exposed are we, and are we fixing it fast enough? (+ the board report)

import { api, request } from "../api.js";
import { empty, ico, severityPill } from "../components.js";
import { formatDay, html, on, setHTML, toast } from "../dom.js";
import { on as onState, state } from "../state.js";
import { gradeBadge, sparkline } from "./ratings.js";
import { trackFinding } from "./remediation.js";
import { openBoardSchedule } from "./schedules.js";

let root;
let data = null;
let days = 90;

const RAG = { red: "Red", amber: "Amber", green: "Green", grey: "Not measured" };
const LINK = { surface: "ratings", remediation: "remediation", exposure: "exposure", suppliers: "suppliers", threats: "monitoring" };
const canEdit = () => ["analyst", "admin"].includes(state.workspace?.role);

const rag = (status) => html`<span class="rag rag-${status}">${RAG[status]}</span>`;

function areaCard(a) {
  return html`<a class="card card-pad area-card area-${a.status}" href="#/${LINK[a.key]}">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:8px"><b>${a.title}</b>${rag(a.status)}</div>
    <p class="muted small" style="margin:6px 0 0">${a.reason}</p>
  </a>`;
}

function due(r) {
  if (r.status === "untracked") return html`<span class="muted">No owner yet</span>`;
  if (r.overdue) return html`<b style="color:var(--sev-critical)">Overdue</b> <span class="muted small">(${formatDay(r.due_at)})</span>`;
  return r.due_at ? html`Due ${formatDay(r.due_at)}` : "";
}

function render() {
  const d = data;
  setHTML(root, html`<div class="page">
    <div class="page-head">
      <div><h1>Executive overview</h1><p>How exposed are we, and are we fixing it fast enough? Everything Argus knows, summarised the way a board asks.</p></div>
      <div class="page-actions">
        <div class="segmented" role="tablist" aria-label="Period">${[30, 90, 180].map((n) => html`<button class="${days === n ? "active" : ""}" data-days="${n}">${n} days</button>`)}</div>
        ${canEdit() ? html`<button class="btn sm primary" data-act="board">${ico("report")}Board report (PDF)</button>` : ""}
        ${state.workspace?.role === "admin" ? html`<button class="btn sm" data-act="schedule">Send monthly…</button>` : ""}
      </div>
    </div>
    <div class="overall overall-${d.overall}" role="status">
      <div><span class="muted small">Overall · last ${d.period_days} days</span><div class="overall-label">${RAG[d.overall]}</div></div>
      <p>${d.verdict}</p>
    </div>
    <div class="grid" style="grid-template-columns:minmax(0,1.1fr) minmax(0,1fr);gap:16px;align-items:start;margin-top:16px" id="exec-layout">
      <div class="card card-pad">
        <div class="card-head"><h2>Key messages</h2></div>
        ${d.messages.length ? html`<ul class="messages">${d.messages.map((m) => html`<li>${m}</li>`)}</ul>` : html`<p class="muted">Nothing notable in this period.</p>`}
      </div>
      <div class="area-grid">${d.areas.map(areaCard)}</div>
    </div>
    <div class="grid two" style="align-items:start;margin-top:16px">
      <div class="card card-pad">
        <div class="card-head"><div><h2>Security ratings</h2><p class="muted small">Your own organisations (suppliers are under Supplier risk).</p></div></div>
        ${d.organisations.length ? html`<table class="table"><tbody>${d.organisations.map((o) => html`<tr>
          <td>${gradeBadge(o.grade)}</td><td><b>${o.target}</b><div class="muted small">score ${Math.round(o.score)}</div></td>
          <td>${sparkline(o.trend || [], 90, 26)}</td>
          <td>${o.change == null ? html`<span class="muted">—</span>` : html`<b style="color:${o.change >= 0 ? "var(--ok)" : "var(--sev-critical)"}">${o.change > 0 ? "+" : ""}${o.change}</b>`}</td>
        </tr>`)}</tbody></table>` : empty("rating", "Not rated yet", "Scan your organisation's domain to get an A–F security rating.")}
      </div>
      <div class="card card-pad">
        <div class="card-head"><div><h2>Risks to act on</h2><p class="muted small">Critical and overdue work first, then critical attack paths nobody owns.</p></div></div>
        ${d.top_risks.length ? html`<div class="list">${d.top_risks.map((r) => html`<div class="list-row">
          ${severityPill(r.severity)}
          <div class="list-main"><div class="list-title" style="white-space:normal">${r.title}</div>
            <div class="list-sub">${r.target} · ${r.owner || "Unassigned"} · ${due(r)}</div></div>
          ${r.status === "untracked" && canEdit() ? html`<button class="btn sm ghost" data-act="track" data-inv="${r.investigation_id}" data-path="${r.path_id}">Track fix</button>`
            : r.task_id ? html`<a class="btn sm ghost" href="#/remediation">Open</a>` : ""}
        </div>`)}</div>` : html`<p class="muted">No open critical or high risks.</p>`}
      </div>
    </div>
  </div>`);
}

export async function refresh() {
  if (!root) return;
  try {
    data = await api.get(`/api/executive?days=${days}`);
  } catch (err) {
    setHTML(root, html`<div class="page"><p class="error-text">${err.message}</p></div>`);
    return;
  }
  render();
}

async function boardReport(btn) {
  btn.disabled = true;
  try {
    const response = await request("/api/executive/report", { method: "POST", body: { days }, raw: true });
    const name = (response.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/)?.[1] || "argus-board-report.pdf";
    const url = URL.createObjectURL(await response.blob());
    const a = Object.assign(document.createElement("a"), { href: url, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
    toast(`Board report ${response.headers.get("X-Report-Id")} downloaded. Its fingerprint is registered for verification.`, "success", 6000);
  } catch (err) {
    toast(err.message, "error");
  } finally {
    btn.disabled = false;
  }
}

export function initExecutive(el) {
  root = el;
  onState("workspace", () => { data = null; });
  on(root, "click", "[data-days]", (_e, btn) => { days = Number(btn.dataset.days); refresh(); });
  on(root, "click", "[data-act]", async (_e, btn) => {
    const act = btn.dataset.act;
    if (act === "board") return boardReport(btn);
    if (act === "schedule") {
      if (!(await openBoardSchedule())) toast("Add a notification destination (e.g. email) in Monitoring first", "error", 5000);
      return;
    }
    if (act === "track") {
      if (await trackFinding({ type: "attack_path", investigation_id: btn.dataset.inv, path_id: btn.dataset.path })) refresh();
    }
  });
}

