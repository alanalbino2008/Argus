// Dialogs: new investigation, what changed (drift), first-run tour.

import { api, enc } from "../api.js";
import { empty, ico, severityPill } from "../components.js";
import { $, closeModal, formatDate, html, openModal, setHTML, toast } from "../dom.js";
import { typeInfo } from "../icons.js";
import * as graph from "../graph.js";
import { emit, state } from "../state.js";
import { loadRoutes, routeOptions } from "../opsec.js";

// ------------------------------------------------------------------ type detection (mirrors the server)
export function detectType(value) {
  const t = value.trim();
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(t) || (t.includes(":") && /^[0-9a-f:]+$/i.test(t))) return "ip_address";
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(t)) return "email";
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(t)) return "domain";
  if (/^\+?[0-9\s().-]{7,20}$/.test(t) && (t.match(/\d/g) || []).length >= 7) return "phone";
  return t ? "username" : "";
}

// ------------------------------------------------------------------ new investigation
let actions;

export function initModals(appActions) {
  actions = appActions;
  const form = $("#new-form");
  const target = $("#new-target");
  const updateHint = () => {
    const detected = detectType(target.value);
    const chosen = $("#new-type").value;
    setHTML($("#new-type-hint"), detected
      ? html`Detected as <b>${typeInfo(chosen || detected).label}</b>${chosen ? " (set manually)" : ""}.`
      : html`Type is detected automatically.`);
    const isUsername = (chosen || detected) === "username";
    $("#new-variants-field").hidden = !isUsername;
    if (!isUsername) $("#new-variants").checked = false;
  };
  target.addEventListener("input", () => { updateHint(); $("#new-error").textContent = ""; });
  $("#new-type").addEventListener("change", updateHint);
  $("#new-depth").addEventListener("input", (e) => { $("#new-depth-value").textContent = e.target.value; });
  $("#new-watch").addEventListener("change", (e) => {
    $("#new-interval").hidden = !e.target.checked;
    $("#new-submit").textContent = e.target.checked ? "Start & keep watching" : "Start investigation";
  });
  ["#new-purpose", "#new-authorized"].forEach((s) => $(s).addEventListener("input", () => { $("#new-error").textContent = ""; }));
  form.addEventListener("submit", submitNew);
  $("#tour-next").addEventListener("click", nextTourStep);
  $("#tour-skip").addEventListener("click", endTour);
}

let forCase = null; // { caseId, anonymous } when started from a case

export async function openNewInvestigation({ target = "", type = "", watch = false, caseId = null, caseTitle = "", egress = "", anonymous = false } = {}) {
  forCase = caseId ? { caseId, anonymous } : null;
  const routes = await loadRoutes();
  $("#new-egress-field").hidden = !routes.length && !anonymous;
  setHTML($("#new-egress"), routeOptions(routes, egress, { anonymousOnly: anonymous }));
  $("#new-egress-note").textContent = caseId
    ? `For the case "${caseTitle}": the scan is linked to it${anonymous ? ". The case is anonymous, so the scan is passive and routed." : "."}`
    : "";
  $("#new-target").value = target;
  $("#new-type").value = ["domain", "ip_address", "email", "username", "phone"].includes(type) ? type : "";
  try { $("#new-purpose").value = sessionStorage.getItem("argus_last_purpose") || ""; } catch { /* ignore */ }
  $("#new-authorized").checked = false;
  $("#new-variants").checked = false;
  $("#new-passive").checked = anonymous;
  $("#new-passive").disabled = anonymous;
  $("#new-watch").checked = watch && !caseId;
  $("#new-watch").disabled = !!caseId;
  $("#new-watch").dispatchEvent(new Event("change"));
  $("#new-error").textContent = "";
  $("#new-target").dispatchEvent(new Event("input"));
  openModal("new-modal");
}

async function submitNew(e) {
  e.preventDefault();
  const target = $("#new-target").value.trim();
  const purpose = $("#new-purpose").value.trim();
  const error = $("#new-error");
  if (!target) { error.textContent = "Enter a target to investigate."; return $("#new-target").focus(); }
  if (purpose.length < 5) { error.textContent = "Describe the engagement (at least 5 characters)."; return $("#new-purpose").focus(); }
  if (!$("#new-authorized").checked) { error.textContent = "Please confirm you're authorised to investigate this target."; return; }
  try { sessionStorage.setItem("argus_last_purpose", purpose); } catch { /* ignore */ }

  const body = { target, target_type: $("#new-type").value || null, max_depth: Number($("#new-depth").value), passive_only: $("#new-passive").checked, purpose, authorized: true };
  if ($("#new-variants").checked) body.handle_variants = true;
  const egress = $("#new-egress-field").hidden ? "" : $("#new-egress").value;
  if (egress || forCase) {
    if ($("#new-watch").checked) { error.textContent = "Scheduled re-scans connect directly. Untick Keep watching, or choose Direct."; return; }
    Object.assign(body, { egress: egress || "direct" }, forCase ? { case_id: forCase.caseId } : {});
  }
  const submit = $("#new-submit");
  submit.disabled = true;
  try {
    if ($("#new-watch").checked) {
      const monitor = await api.post("/api/monitors", { ...body, interval_hours: Number($("#new-interval").value) });
      closeModal("new-modal");
      toast(`Watching ${target} — first scan started`, "success");
      emit("monitors-changed");
      if (monitor.last_investigation_id) await actions.open(monitor.last_investigation_id, { view: "graph" });
    } else {
      closeModal("new-modal");
      await actions.startScan(body);
    }
  } catch (err) {
    error.textContent = err.message;
    if (!$("#new-modal").classList.contains("open")) toast(err.message, "error");
  } finally {
    submit.disabled = false;
  }
}

// ------------------------------------------------------------------ what changed
export async function openDiff(invId, againstId) {
  setHTML($("#diff-body"), html`<p class="muted">Comparing…</p>`);
  setHTML($("#diff-subtitle"), html``);
  openModal("diff-modal");
  let d;
  try {
    d = await api.get(`/api/investigation/${enc(invId)}/diff${againstId ? `?against=${enc(againstId)}` : ""}`);
  } catch (err) {
    setHTML($("#diff-body"), html`${empty("compare", "Nothing to compare yet", err.status === 404 ? "This is the first completed scan of this target. Scan it again later — or watch it — to see what changes." : err.message)}`);
    return;
  }
  const s = d.summary;
  setHTML($("#diff-subtitle"), html`${d.headline.split(":")[0]} · compared with the scan of ${formatDate(d.previous_completed_at)}`);
  const trend = s.trend === "worse" ? "critical" : s.trend === "better" ? "ok" : "";
  const stat = (n, label) => html`<div class="card kpi" style="padding:14px"><div class="kpi-value" style="font-size:22px">${n}</div><div class="kpi-label">${label}</div></div>`;
  const paths = (items, extra = () => "") => items.length
    ? html`<div class="list">${items.map((p) => html`<div class="list-row">${severityPill(p.severity)}<div class="list-main"><div class="list-title" style="white-space:normal">${p.title}</div></div>${extra(p)}</div>`)}</div>`
    : html`<p class="muted small">None</p>`;
  const assets = (groups) => Object.keys(groups).length
    ? html`${Object.entries(groups).map(([type, items]) => html`<div style="margin-bottom:8px"><span class="muted small">${typeInfo(type).label}</span><div class="chain" style="margin-top:4px">${items.map((i) => html`<span class="chain-node"><span class="ico" style="background:${typeInfo(type).color}"></span><span class="txt">${i.value}</span></span>`)}</div></div>`)}`
    : html`<p class="muted small">None</p>`;
  setHTML($("#diff-body"), html`
    <div class="callout" style="margin-bottom:16px;align-items:center"><span class="pill ${trend}">${s.trend}</span>
      <span>Total attack-path risk went from <b>${s.risk_before}</b> to <b>${s.risk_after}</b> (${s.risk_delta >= 0 ? "+" : ""}${s.risk_delta}).</span></div>
    <div class="grid kpis" style="grid-template-columns:repeat(5,minmax(0,1fr));margin-bottom:8px">
      ${stat(s.new_paths, "new paths")}${stat(s.escalated_paths, "escalated")}${stat(s.resolved_paths, "resolved")}${stat(s.added, "new assets")}${stat(s.removed, "gone")}
    </div>
    <div class="grid two" style="margin-top:16px">
      <div>
        <div class="section-title">New attack paths</div>${paths(d.new_paths)}
        <div class="section"><div class="section-title">Got worse</div>${paths(d.escalated_paths, (p) => html`<span class="muted small">${p.score_before} → <b>${p.score}</b></span>`)}</div>
        <div class="section"><div class="section-title">Fixed ✓</div>${paths(d.resolved_paths)}</div>
      </div>
      <div>
        <div class="section-title">New assets</div>${assets(d.added)}
        <div class="section"><div class="section-title">No longer seen</div>${assets(d.removed)}</div>
        <div class="section"><div class="section-title">Security-relevant changes</div>
          ${d.changed.length ? html`<div class="list">${d.changed.map((c) => html`<div class="list-row"><div class="list-main"><div class="list-title">${c.value}</div>
            <div class="list-sub">${Object.entries(c.changes).map(([k, v]) => `${k.replace(/_/g, " ")}: ${JSON.stringify(v.before)} → ${JSON.stringify(v.after)}`).join(" · ")}</div></div></div>`)}</div>`
            : html`<p class="muted small">None</p>`}</div>
      </div>
    </div>`);
  if (state.investigation?.id === invId) graph.markNew(Object.values(d.added).flat().map((e) => e.id));
}

// ------------------------------------------------------------------ first-run tour
const TOUR = [
  { icon: "logo", title: "Welcome to Argus", text: "Argus maps what's publicly discoverable about a target and shows you how an attacker could use it. This 30-second tour shows you around." },
  { icon: "plus", title: "Start an investigation", text: "Enter a domain, IP, email or username. You'll state the purpose and confirm you're authorised — every scan is recorded in a tamper-evident audit log." },
  { icon: "paths", title: "Attack paths are the headline", text: "Findings are chained into realistic scenarios — leaked passwords, spoofable email, exposed services — ranked by risk, mapped to MITRE ATT&CK, with fixes. Click “Show on graph” to see the chain." },
  { icon: "bell", title: "Keep watching", text: "Tick “Keep watching” and Argus re-scans on a schedule, comparing each scan with the last and alerting you when something material changes. Press ? any time for shortcuts." },
  { icon: "sparkle", title: "Start with a guided scan", text: "Not sure where to begin? “Guided first scan” helps you pick a target you're allowed to assess, explains every option in plain English, and shows what it finds as it runs. Or explore the demo — nothing is scanned." },
];
let tourStep = 0;

function renderTour() {
  const step = TOUR[tourStep];
  setHTML($("#tour-body"), html`<div class="tour-illustration">${ico(step.icon)}</div><h2 id="tour-title" style="margin-bottom:8px">${step.title}</h2><p style="color:var(--text-2);line-height:1.6">${step.text}</p>`);
  setHTML($("#tour-progress"), html`${TOUR.map((_, i) => html`<span class="${i <= tourStep ? "on" : ""}"></span>`)}`);
  $("#tour-next").textContent = tourStep === TOUR.length - 1 ? "Get started" : "Next";
}

export function startTour(force = false) {
  try { if (!force && localStorage.getItem("argus_tour_done")) return; } catch { /* ignore */ }
  tourStep = 0;
  renderTour();
  openModal("tour-modal");
}

function nextTourStep() {
  if (tourStep < TOUR.length - 1) { tourStep += 1; renderTour(); } else endTour();
}

function endTour() {
  try { localStorage.setItem("argus_tour_done", "1"); } catch { /* ignore */ }
  closeModal("tour-modal");
}
