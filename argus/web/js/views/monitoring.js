// Monitoring: drift alerts first, then watched targets.

import { api, enc } from "../api.js";
import { empty, ico, severityPill } from "../components.js";
import { confirmDialog, html, on, setHTML, timeAgo, toast } from "../dom.js";
import { emit, state } from "../state.js";
import { handleNotificationAction, initNotifications, loadNotifications, notificationsCard } from "./notifications.js";
import { handleScheduleAction, initSchedules, loadSchedules, schedulesCard } from "./schedules.js";

let root;
let actions;
let alerts = null;
let monitors = null;
let fpWatches = []; // watched fingerprints (Shodan/Censys searches on a schedule)

export function initMonitoring(el, appActions) {
  root = el;
  actions = appActions;
  initNotifications(refresh);
  initSchedules(refresh);
  on(root, "click", "[data-act]", async (_e, btn) => {
    const { act, id } = btn.dataset;
    if (await handleNotificationAction(act, id, btn)) return;
    if (await handleScheduleAction(act, id, btn)) return;
    try {
      if (act === "ack") {
        await api.post(`/api/alerts/${enc(id)}/acknowledge`);
        toast("Alert acknowledged", "success");
      } else if (act === "changes") {
        actions.openDiff(btn.dataset.inv, btn.dataset.prev);
        return;
      } else if (act === "toggle") {
        await api.patch(`/api/monitors/${enc(id)}`, { enabled: btn.dataset.enabled !== "true" });
      } else if (act === "delete") {
        const ok = await confirmDialog({ title: "Stop watching this target?", message: "Past investigations and alerts are kept.", confirm: "Stop watching", danger: true });
        if (!ok) return;
        await api.del(`/api/monitors/${enc(id)}`);
        toast("Monitor removed");
      } else if (act === "fp-run") {
        await api.post(`/api/fingerprint-watches/${enc(id)}/run`);
        toast("Running now: the result shows here in a minute", "success");
      } else if (act === "fp-delete") {
        const ok = await confirmDialog({ title: "Stop watching this fingerprint?", message: "Alerts it raised are kept.", confirm: "Stop watching", danger: true });
        if (!ok) return;
        await api.del(`/api/fingerprint-watches/${enc(id)}`);
        toast("Fingerprint watch removed");
      } else if (act === "open") {
        actions.open(id);
        return;
      } else if (act === "new") {
        actions.newInvestigation();
        return;
      }
      refresh();
    } catch (err) {
      toast(err.message, "error");
    }
  });
}

export async function refresh() {
  try {
    [alerts, monitors, fpWatches] = await Promise.all([api.get("/api/alerts?limit=50"), api.get("/api/monitors"),
      api.get("/api/fingerprint-watches").catch(() => []), loadNotifications(), loadSchedules()]);
  } catch {
    return;
  }
  state.alertsOpen = alerts.filter((a) => !a.acknowledged_at).length;
  emit("alerts", state.alertsOpen);
  render();
}

function render() {
  if (!root) return;
  const open = (alerts || []).filter((a) => !a.acknowledged_at);
  const done = (alerts || []).filter((a) => a.acknowledged_at).slice(0, 10);
  setHTML(root, html`<div class="page" style="max-width:1040px">
    <div class="page-head">
      <div><h1>Monitoring</h1><p>Watched targets are re-scanned on a schedule. You're alerted when the attack surface changes in a way that matters.</p></div>
      <button class="btn primary" data-act="new">${ico("eye")}Watch a target</button>
    </div>

    <div class="card card-pad">
      <div class="card-head"><h2>Alerts</h2><span class="muted small">${open.length} open</span></div>
      ${alerts === null ? html`<p class="muted">Loading…</p>`
        : !alerts.length ? empty("bell", "No alerts", "When a watched target changes materially — a new attack path, a newly exposed service, a fresh breach — it shows up here.")
        : html`<div class="list">${[...open, ...done].map((a) => html`
          <div class="list-row" style="${a.acknowledged_at ? "opacity:.6" : ""}">
            ${severityPill(a.severity)}
            <div class="list-main"><div class="list-title" style="white-space:normal">${a.headline}</div>
              <div class="list-sub">${timeAgo(a.created_at)}${a.acknowledged_at ? html` · acknowledged by ${a.acknowledged_by}` : ""}</div></div>
            ${a.summary?.exposure ? html`<a class="btn sm" href="#/exposure">${ico("breach")}View exposure</a>`
              : a.summary?.fingerprint_watch ? html`<button class="btn sm" data-act="open" data-id="${a.investigation_id}" title="${(a.summary.fingerprint_watch.new_servers || []).map((h) => h.ip + (h.port ? ":" + h.port : "")).join(", ")}">${ico("eye")}Open investigation</button>`
              : html`<button class="btn sm" data-act="changes" data-inv="${a.investigation_id}" data-prev="${a.previous_investigation_id}">${ico("compare")}What changed</button>`}
            ${a.acknowledged_at ? "" : html`<button class="btn sm ghost" data-act="ack" data-id="${a.id}">${ico("check")}Acknowledge</button>`}
          </div>`)}</div>`}
    </div>

    <div class="card card-pad" style="margin-top:16px">
      <div class="card-head"><h2>Watched targets</h2><span class="muted small">${(monitors || []).length}</span></div>
      ${monitors === null ? html`<p class="muted">Loading…</p>`
        : !monitors.length ? empty("eye", "Nothing watched yet", "Tick “Keep watching” when starting an investigation, or use Watch on any investigation.")
        : html`<table class="table"><thead><tr><th>Target</th><th>Every</th><th>Last scan</th><th>Next scan</th><th>Status</th><th></th></tr></thead><tbody>
          ${monitors.map((m) => html`<tr>
            <td><b>${m.target}</b><div class="muted small">${m.purpose}</div></td>
            <td>${m.interval_hours >= 24 ? `${m.interval_hours / 24} day${m.interval_hours > 24 ? "s" : ""}` : `${m.interval_hours} h`}</td>
            <td>${m.last_investigation_id ? html`<button class="btn sm ghost" data-act="open" data-id="${m.last_investigation_id}" title="Open this scan">${timeAgo(m.last_run_at)}</button>` : "Pending"}</td>
            <td>${m.enabled ? timeAgo(m.next_run_at).replace(" ago", "").replace("just now", "now") : "—"}</td>
            <td>${m.enabled ? html`<span class="pill ok">Active</span>` : html`<span class="pill">Paused</span>`}</td>
            <td class="actions">
              <button class="btn sm ghost" data-act="toggle" data-id="${m.id}" data-enabled="${m.enabled}">${m.enabled ? "Pause" : "Resume"}</button>
              <button class="btn sm ghost icon" data-act="delete" data-id="${m.id}" title="Stop watching" aria-label="Stop watching">${ico("trash")}</button>
            </td></tr>`)}
        </tbody></table>`}
    </div>
    ${fingerprintCard()}
    ${notificationsCard()}
    ${schedulesCard()}
  </div>`);
}

const ENGINE = { shodan: "Shodan", censys: "Censys" };

/** Fingerprints whose Shodan/Censys search re-runs on a schedule (start one from a fingerprint in the graph). */
function fingerprintCard() {
  if (!fpWatches.length) return "";
  return html`<div class="card card-pad" style="margin-top:16px">
    <div class="card-head"><h2>Watched fingerprints</h2><span class="muted small">New servers sharing them raise an alert</span></div>
    <table class="table"><thead><tr><th>Fingerprint</th><th>Every</th><th>Servers known</th><th>Last check</th><th></th></tr></thead><tbody>
    ${fpWatches.map((w) => html`<tr>
      <td><b>${w.label}</b><div class="muted small mono">${ENGINE[w.engine] || w.engine}: ${w.query}</div></td>
      <td>${w.interval_hours === 24 ? "day" : "week"}</td>
      <td>${w.known}${w.last_total != null ? html` <span class="muted small">of ${Number(w.last_total).toLocaleString()}</span>` : ""}</td>
      <td>${w.last_run_at ? html`<span class="pill ${w.last_status === "ok" ? "ok" : "high"}" title="${w.last_message}">${timeAgo(w.last_run_at)}</span>` : "Pending"}
        ${w.last_status === "error" ? html`<div class="muted small">${w.last_message}</div>` : ""}</td>
      <td class="actions">
        <button class="btn sm ghost" data-act="open" data-id="${w.investigation_id}" title="Open the investigation it was watched from">${ico("eye")}</button>
        <button class="btn sm ghost" data-act="fp-run" data-id="${w.id}" title="Run the search now (spends a search credit)">Run now</button>
        <button class="btn sm ghost icon" data-act="fp-delete" data-id="${w.id}" title="Stop watching" aria-label="Stop watching">${ico("trash")}</button>
      </td></tr>`)}
    </tbody></table></div>`;
}
