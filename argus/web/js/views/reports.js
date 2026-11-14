// Client PDF reports: options dialog, report history, and verifying a received report.

import { api, downloadPost, enc } from "../api.js";
import { $, copyText, formatDate, html, on, openModal, setHTML, toast } from "../dom.js";
import { state } from "../state.js";

const short = (sha) => `${sha.slice(0, 12)}…${sha.slice(-6)}`;

async function loadHistory(invId) {
  const box = $("#report-history");
  setHTML(box, html``);
  try {
    const reports = await api.get(`/api/reports?investigation_id=${enc(invId)}&limit=5`);
    if (!reports.length) return;
    setHTML(box, html`<div class="section-title" style="margin-top:6px">Issued for this investigation</div>
      <table class="table"><thead><tr><th>Reference</th><th>Issued</th><th>For</th><th>Fingerprint (SHA-256)</th></tr></thead><tbody>
      ${reports.map((r) => html`<tr><td class="mono">${r.id}</td><td>${formatDate(r.created_at)}<div class="muted small">${r.created_by}</div></td>
        <td>${r.prepared_for || "—"}<div class="muted small">TLP:${r.tlp}</div></td>
        <td><button type="button" class="btn sm ghost mono" data-copy="${r.sha256}" title="Copy the full fingerprint">${short(r.sha256)}</button></td></tr>`)}
      </tbody></table>`);
  } catch {
    /* viewers without history access still get the dialog */
  }
}

export async function openReport() {
  const inv = state.investigation;
  if (!inv) return;
  $("#report-error").textContent = "";
  $("#report-submit").disabled = false;
  openModal("report-modal");
  loadHistory(inv.id);
  try {
    const b = await api.get("/api/reports/branding");
    setHTML($("#report-branding-hint"), html`Branded as <b>${b.organisation}</b>${b.has_logo ? " with logo" : ""}`);
  } catch {
    $("#report-branding-hint").textContent = "";
  }
}

export function initReports() {
  on(document, "click", "[data-copy]", async (_e, btn) => {
    await copyText(btn.dataset.copy);
    toast("Fingerprint copied", "success", 1800);
  });
  $("#report-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const inv = state.investigation;
    if (!inv) return;
    const submit = $("#report-submit");
    submit.disabled = true;
    $("#report-error").textContent = "";
    const original = submit.innerHTML;
    submit.textContent = "Generating…";
    try {
      const headers = await downloadPost(`/api/investigation/${enc(inv.id)}/report`, {
        prepared_for: $("#report-for").value.trim(),
        tlp: $("#report-tlp").value,
        include_inventory: $("#report-inventory").checked,
        compare_previous: $("#report-compare").checked,
        include_personal_details: $("#report-personal").checked,
      });
      toast(`Report ${headers.get("X-Argus-Report-Id")} downloaded — its fingerprint is registered for verification`, "success", 5000);
      loadHistory(inv.id);
    } catch (err) {
      $("#report-error").textContent = err.message;
    } finally {
      submit.disabled = false;
      submit.innerHTML = original;
    }
  });
}

// ------------------------------------------------------------------ verify a received report
export async function verifyFile(file) {
  const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
  const sha = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  const res = await fetch(`/api/reports/verify/${sha}`);
  return { sha, ok: res.ok, body: await res.json().catch(() => ({})) };
}
