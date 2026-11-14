// Scheduled reports: list, create, run now, pause and delete. Shown on the Monitoring page
// to workspace administrators, next to the notification destinations it sends through.

import { api, enc } from "../api.js";
import { empty, ico } from "../components.js";
import { $, closeModal, confirmDialog, formatDate, html, openModal, setHTML, timeAgo, toast } from "../dom.js";
import { state } from "../state.js";

let schedules = null;
let channels = [];
let onChange = () => {};

const STATUS = {
  sent: ["ok", "Sent"],
  skipped_unchanged: ["", "Skipped — no new scan"],
  no_scan: ["warn", "No scan yet"],
  failed: ["critical", "Failed"],
};

export async function loadSchedules() {
  if (state.workspace?.role !== "admin") return (schedules = null);
  try {
    [schedules, channels] = await Promise.all([api.get("/api/reports/schedules"), api.get("/api/notifications/channels")]);
  } catch {
    schedules = null;
  }
  return schedules;
}

export function schedulesCard() {
  if (!schedules) return "";
  return html`<div class="card card-pad" style="margin-top:16px">
    <div class="card-head">
      <div><h2>Scheduled reports</h2><p class="muted small">Client-ready PDF reports sent automatically from the latest scan — e.g. every Monday at 08:00. Each one is registered and verifiable like any report.</p></div>
      <button class="btn" data-act="s-add" ${channels.length ? "" : html`disabled title="Add a notification destination first"`}>${ico("plus")}Schedule a report</button>
    </div>
    ${!channels.length ? html`<p class="muted small">${ico("info")} Add a destination under Notifications first — reports are sent through it.</p>` : ""}
    ${!schedules.length ? (channels.length ? empty("report", "No scheduled reports", "Send a weekly or monthly PDF to a client or your leadership, without anyone remembering to.") : "")
      : html`<table class="table"><thead><tr><th>Report</th><th>When</th><th>Last run</th><th>Next</th><th></th></tr></thead><tbody>
        ${schedules.map((s) => {
          const [cls, label] = STATUS[s.last_status] || ["", "Not run yet"];
          const to = s.channel_ids.map((id) => channels.find((c) => c.id === id)?.name || "removed destination").join(", ");
          return html`<tr style="${s.enabled ? "" : "opacity:.6"}">
            <td><b>${s.name}</b><div class="muted small">${s.target} → ${to}</div></td>
            <td>${s.description}</td>
            <td><span class="pill ${cls}" title="${s.last_message || ""}">${label}</span>${s.last_run_at ? html`<div class="muted small">${timeAgo(s.last_run_at)}</div>` : ""}</td>
            <td>${s.enabled ? formatDate(s.next_run_at) : "Paused"}</td>
            <td class="actions">
              <button class="btn sm" data-act="s-run" data-id="${s.id}" ${s.enabled ? "" : "disabled"}>Run now</button>
              <button class="btn sm ghost" data-act="s-toggle" data-id="${s.id}" data-enabled="${s.enabled}">${s.enabled ? "Pause" : "Resume"}</button>
              <button class="btn sm ghost icon" data-act="s-delete" data-id="${s.id}" title="Delete" aria-label="Delete ${s.name}">${ico("trash")}</button>
            </td></tr>`;
        })}</tbody></table>`}
  </div>`;
}

async function openCreate() {
  $("#schedule-form").reset();
  $("#schedule-error").textContent = "";
  const zones = typeof Intl.supportedValuesOf === "function" ? Intl.supportedValuesOf("timeZone") : ["UTC"];
  const local = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  setHTML($("#schedule-tz"), html`${["UTC", ...zones.filter((z) => z !== "UTC")].map((z) => html`<option value="${z}" ${z === local ? "selected" : ""}>${z.replaceAll("_", " ")}</option>`)}`);
  setHTML($("#schedule-day"), html`${Array.from({ length: 28 }, (_, i) => html`<option value="${i + 1}">${i + 1}</option>`)}`);
  setHTML($("#schedule-channels"), html`${channels.map((c) => html`<label class="check"><input type="checkbox" value="${c.id}" ${c.enabled ? "" : "disabled"}> ${c.name} <span class="muted small">${c.type}${c.enabled ? "" : " (paused)"}</span></label>`)}`);
  toggleFrequency();
  try {
    const [monitors, recent] = await Promise.all([api.get("/api/monitors"), api.get("/api/investigations?limit=50&status=completed")]);
    const targets = [...new Set([...monitors.map((m) => m.target), ...recent.map((r) => r.target)])];
    setHTML($("#schedule-targets"), html`${targets.map((t) => html`<option value="${t}">`)}`);
    if (state.investigation?.target) $("#schedule-target").value = state.investigation.target;
  } catch { /* suggestions are optional */ }
  openModal("schedule-modal");
}

function toggleFrequency() {
  const monthly = $("#schedule-frequency").value === "monthly";
  $("#schedule-weekday").hidden = monthly;
  $("#schedule-day").hidden = !monthly;
}

export async function handleScheduleAction(act, id, btn) {
  if (!act.startsWith("s-")) return false;
  if (act === "s-add") {
    await openCreate();
    return true;
  }
  try {
    if (act === "s-run") {
      await api.post(`/api/reports/schedules/${enc(id)}/run`);
      toast("Queued — the report is generated within a minute", "success");
      setTimeout(onChange, 65000);
    } else if (act === "s-toggle") {
      await api.patch(`/api/reports/schedules/${enc(id)}`, { enabled: btn.dataset.enabled !== "true" });
    } else if (act === "s-delete") {
      if (!(await confirmDialog({ title: "Delete this schedule?", message: "Reports already sent stay registered and verifiable.", confirm: "Delete", danger: true }))) return true;
      await api.del(`/api/reports/schedules/${enc(id)}`);
      toast("Schedule deleted");
    }
  } catch (err) {
    toast(err.message, "error");
  }
  await onChange();
  return true;
}

export function initSchedules(refresh) {
  onChange = refresh;
  $("#schedule-frequency").addEventListener("change", toggleFrequency);
  $("#schedule-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const error = $("#schedule-error");
    const channelIds = [...document.querySelectorAll("#schedule-channels input:checked")].map((i) => i.value);
    const [hour, minute] = ($("#schedule-time").value || "08:00").split(":").map(Number);
    const monthly = $("#schedule-frequency").value === "monthly";
    const body = {
      name: $("#schedule-name").value.trim(),
      target: $("#schedule-target").value.trim(),
      frequency: monthly ? "monthly" : "weekly",
      weekday: monthly ? null : Number($("#schedule-weekday").value),
      day_of_month: monthly ? Number($("#schedule-day").value) : null,
      hour, minute,
      timezone: $("#schedule-tz").value,
      channel_ids: channelIds,
      skip_unchanged: $("#schedule-skip").checked,
      options: { prepared_for: $("#schedule-for").value.trim(), tlp: $("#schedule-tlp").value, include_inventory: $("#schedule-inventory").checked, compare_previous: $("#schedule-compare").checked },
    };
    if (!body.name || !body.target) return (error.textContent = "Give the schedule a name and a target.");
    if (!channelIds.length) return (error.textContent = "Choose at least one destination.");
    try {
      const created = await api.post("/api/reports/schedules", body);
      closeModal("schedule-modal");
      toast(created.has_scan ? `Scheduled: ${created.description}` : `Scheduled: ${created.description}. There is no completed scan of ${created.target} yet — watch it so reports have something to send.`, "success", 6000);
      await onChange();
    } catch (err) {
      error.textContent = err.message;
    }
  });
}
