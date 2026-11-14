// Monitoring: drift alerts first, then watched targets.

import { api, enc } from "../api.js";
import { empty, ico, severityPill } from "../components.js";
import { confirmDialog, html, on, setHTML, timeAgo, toast } from "../dom.js";
import { emit, state } from "../state.js";

let root;
let actions;
let alerts = null;
let monitors = null;

export function initMonitoring(el, appActions) {
  root = el;
  actions = appActions;
  on(root, "click", "[data-act]", async (_e, btn) => {
    const { act, id } = btn.dataset;
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
    [alerts, monitors] = await Promise.all([api.get("/api/alerts?limit=50"), api.get("/api/monitors")]);
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
            <button class="btn sm" data-act="changes" data-inv="${a.investigation_id}" data-prev="${a.previous_investigation_id}">${ico("compare")}What changed</button>
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
  </div>`);
}
