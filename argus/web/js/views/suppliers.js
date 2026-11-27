// Supplier risk: the register, the risk matrix (criticality x grade), import/export and actions.

import { api, download, enc } from "../api.js";
import { empty, ico } from "../components.js";
import { $, closeModal, confirmDialog, formatDay, html, on, openModal, setHTML, toast } from "../dom.js";
import { on as onState, state } from "../state.js";
import { gradeBadge, sparkline } from "./ratings.js";
import { trackFinding } from "./remediation.js";

let root;
let actions;
let data = null;

const STATUS = {
  below_minimum: ["critical", "Below minimum"],
  within_tolerance: ["ok", "Within tolerance"],
  not_assessed: ["", "Assessing…"],
};
const RISK = { critical: "critical", high: "high", medium: "medium", low: "low", unknown: "" };
const DATA = { none: "None", internal: "Internal", personal: "Personal data", sensitive: "Sensitive data" };
const IMPACT = { 5: "Severe", 4: "Major", 3: "Moderate", 2: "Minor", 1: "Minimal" };

function exposurePills(exposure = {}) {
  const pills = [];
  if (exposure.ransomware_post) pills.push(html`<a class="pill critical" href="#/exposure" title="Named on a ransomware leak site">Ransomware post</a>`);
  if (exposure.domain_breach) pills.push(html`<a class="pill high" href="#/exposure" title="This supplier was breached">Breached</a>`);
  return pills.length ? html`<div style="margin-top:4px;display:flex;gap:4px;flex-wrap:wrap">${pills}</div>` : "";
}

function cellLevel(impact, grade) {
  const score = impact * { A: 1, B: 2, C: 3, D: 4, F: 5 }[grade];
  return score >= 15 ? "critical" : score >= 10 ? "high" : score >= 5 ? "medium" : "low";
}

function matrix() {
  return html`<div class="risk-matrix" role="table" aria-label="Supplier risk matrix: impact by security grade">
    <div class="rm-corner" role="columnheader">Impact ↓ · Grade →</div>
    ${["A", "B", "C", "D", "F"].map((g) => html`<div class="rm-head" role="columnheader">${gradeBadge(g, "sm")}</div>`)}
    ${[5, 4, 3, 2, 1].map((i) => html`
      <div class="rm-row" role="rowheader">${IMPACT[i]}</div>
      ${["A", "B", "C", "D", "F"].map((g) => {
        const n = data.matrix[String(i)][g];
        return html`<div class="rm-cell rm-${cellLevel(i, g)} ${n ? "has" : ""}" role="cell" title="${n} supplier(s): impact ${i}, grade ${g}">${n || ""}</div>`;
      })}`)}
  </div>`;
}

function render() {
  const sup = data.suppliers;
  const s = data.summary;
  const canEdit = ["analyst", "admin"].includes(state.workspace?.role);
  setHTML(root, html`<div class="page">
    <div class="page-head">
      <div><h1>Supplier risk</h1><p>Your third parties, rated from what an attacker can see and weighed by how much they matter to you. Assessments are passive and repeat automatically: weekly for critical suppliers, quarterly for low.</p></div>
      <div class="page-actions">
        <button class="btn sm" data-act="export">${ico("download")}Export register</button>
        ${canEdit ? html`<button class="btn sm" data-act="import">${ico("plus")}Import CSV</button><button class="btn sm primary" data-act="add">${ico("plus")}Add supplier</button>` : ""}
      </div>
    </div>
    ${!sup.length ? html`<div class="card">${empty("organization", "No suppliers yet", "Add the organisations you depend on — or import your register — and Argus will rate each one and tell you when one drops below what you accept.")}</div>` : html`
    <div class="grid kpis" style="margin-bottom:16px">
      <div class="card card-pad"><b style="font-size:24px">${s.total}</b><div class="muted small">suppliers</div></div>
      <div class="card card-pad"><b style="font-size:24px;color:${s.below_minimum ? "var(--sev-critical-text)" : "inherit"}">${s.below_minimum}</b><div class="muted small">below the minimum grade for their tier</div></div>
      <div class="card card-pad"><b style="font-size:24px">${s.by_risk.critical + s.by_risk.high}</b><div class="muted small">high or critical risk</div></div>
      <div class="card card-pad"><b style="font-size:24px">${s.not_assessed}</b><div class="muted small">first assessment in progress</div></div>
    </div>
    <div class="card card-pad">
        <div class="card-head"><div><h2>Register</h2><p class="muted small">Policy breaches and highest risk first.</p></div></div>
        <table class="table"><thead><tr><th>Supplier</th><th>Tier · data</th><th>Grade</th><th>Status</th><th>Risk</th><th></th></tr></thead><tbody>
        ${sup.map((x) => {
          const [cls, label] = STATUS[x.status];
          return html`<tr>
            <td><b>${x.name}</b><div class="muted small">${x.domain}${x.owner ? ` · ${x.owner}` : ""}</div></td>
            <td><span class="pill">${x.tier}</span><div class="muted small">${DATA[x.data_access]}</div></td>
            <td><div style="display:flex;gap:8px;align-items:center">${gradeBadge(x.grade)}${sparkline(x.trend, 60, 22)}</div>
              <div class="muted small">minimum ${x.min_grade || "none"}${x.last_assessed_at ? ` · ${formatDay(x.last_assessed_at)}` : ""}</div></td>
            <td><span class="pill ${cls}">${label}</span>${exposurePills(x.exposure)}</td>
            <td>${x.risk.level === "unknown" ? html`<span class="muted small">—</span>` : html`<span class="pill ${RISK[x.risk.level]}">${x.risk.level}</span><div class="muted small">${x.risk.score}/25</div>`}</td>
            <td class="actions">
              ${x.last_investigation_id ? html`<button class="btn sm ghost" data-act="open" data-id="${x.last_investigation_id}" title="Open the latest assessment">Open</button>` : ""}
              ${canEdit && x.status === "below_minimum" ? html`<button class="btn sm ghost" data-act="track" data-id="${x.id}" title="Track getting this supplier back to its minimum grade">Track fix</button>` : ""}
              ${canEdit ? html`<button class="btn sm ghost" data-act="assess" data-id="${x.id}" title="Re-assess now">${ico("compare")}</button>` : ""}
              ${state.workspace?.role === "admin" ? html`<button class="btn sm ghost icon" data-act="remove" data-id="${x.id}" title="Remove" aria-label="Remove ${x.name}">${ico("trash")}</button>` : ""}
            </td></tr>`;
        })}</tbody></table>
    </div>
    <div class="grid two" style="align-items:start;margin-top:16px">
      <div class="card card-pad">
        <div class="card-head"><div><h2>Risk matrix</h2><p class="muted small">Impact (criticality + data handled) against security grade.</p></div></div>
        ${matrix()}
      </div>
      <div class="card card-pad">
        <div class="card-head"><div><h2>Policy</h2><p class="muted small">The minimum acceptable grade and re-assessment frequency for each tier. A supplier can have its own minimum.</p></div></div>
        <table class="table"><tbody>${Object.entries(data.policy).map(([tier, p]) => html`<tr><td><span class="pill">${tier}</span></td><td>minimum ${p.min_grade ? gradeBadge(p.min_grade, "sm") : "none"}</td><td class="muted small">re-assessed every ${p.reassessed_every_days} days</td></tr>`)}</tbody></table>
      </div>
    </div>`}
  </div>`);
}

export async function refresh() {
  if (!root) return;
  try {
    data = await api.get("/api/suppliers");
  } catch (err) {
    setHTML(root, html`<div class="page"><p class="error-text">${err.message}</p></div>`);
    return;
  }
  render();
}

export function initSuppliers(el, appActions) {
  root = el;
  actions = appActions;
  onState("workspace", () => { data = null; });
  on(root, "click", "[data-act]", async (_e, btn) => {
    const { act, id } = btn.dataset;
    try {
      if (act === "add") { $("#supplier-form").reset(); $("#sup-error").textContent = ""; return openModal("supplier-modal"); }
      if (act === "import") { $("#supplier-import-form").reset(); setHTML($("#sup-import-result"), html``); return openModal("supplier-import-modal"); }
      if (act === "export") return download("/api/suppliers/export.csv", "supplier-register.csv");
      if (act === "open") return actions.open(id);
      if (act === "track") return trackFinding({ type: "supplier", supplier_id: id });
      if (act === "assess") { await api.post(`/api/suppliers/${enc(id)}/assess`); toast("Re-assessment started (passive)", "success"); }
      if (act === "remove") {
        if (!(await confirmDialog({ title: "Remove this supplier?", message: "Its monitoring stops. Past assessments stay in History.", confirm: "Remove", danger: true }))) return;
        await api.del(`/api/suppliers/${enc(id)}`);
        toast("Supplier removed");
      }
      await refresh();
    } catch (err) {
      toast(err.message, "error");
    }
  });
  $("#supplier-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const error = $("#sup-error");
    if (!$("#sup-authorized").checked) return (error.textContent = "Confirm you have a legitimate reason to assess this supplier.");
    try {
      const created = await api.post("/api/suppliers", {
        name: $("#sup-name").value.trim(), domain: $("#sup-domain").value.trim(), tier: $("#sup-tier").value,
        data_access: $("#sup-data").value, owner: $("#sup-owner").value.trim(), notes: $("#sup-notes").value.trim(),
        basis: $("#sup-basis").value.trim(), authorized: true,
      });
      closeModal("supplier-modal");
      toast(`${created.name} added — first passive assessment starting`, "success", 5000);
      await refresh();
    } catch (err) {
      error.textContent = err.message;
    }
  });
  $("#sup-file").addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (file) $("#sup-csv").value = await file.text();
  });
  $("#supplier-import-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const error = $("#sup-import-error");
    error.textContent = "";
    if (!$("#sup-import-authorized").checked) return (error.textContent = "Confirm you have a legitimate reason to assess these suppliers.");
    try {
      const r = await api.post("/api/suppliers/import", { csv: $("#sup-csv").value, basis: $("#sup-import-basis").value.trim(), authorized: true });
      setHTML($("#sup-import-result"), html`<div class="guide-warning ${r.errors.length ? "warning" : "info"}">${ico(r.errors.length ? "alert" : "check")}<div>
        <b>${r.created.length} supplier${r.created.length === 1 ? "" : "s"} added</b>${r.skipped.length ? html`, ${r.skipped.length} already in the register` : ""}.
        ${r.errors.length ? html`<ul style="margin:6px 0 0;padding-left:18px">${r.errors.slice(0, 8).map((x) => html`<li>${x.line ? `Line ${x.line}: ` : ""}${x.error}</li>`)}</ul>` : ""}</div></div>`);
      await refresh();
    } catch (err) {
      error.textContent = err.message;
    }
  });
}
