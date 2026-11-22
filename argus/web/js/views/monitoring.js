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
let brandWatches = []; // brands whose lookalike domains are looked for in Certificate Transparency
let brandForm = false;
let routes = []; // egress routes, for visiting lookalikes' websites without showing this server's address

export function initMonitoring(el, appActions) {
  root = el;
  actions = appActions;
  initNotifications(refresh);
  initSchedules(refresh);
  on(root, "change", "[data-act-change=brand-web]", async (_e, select) => {
    try {
      await api.patch(`/api/brand-watches/${enc(select.dataset.id)}`, { web_check: select.value });
      toast(select.value === "off" ? "Lookalikes' websites will not be visited" : "Lookalikes' websites will be checked at the next run", "success");
    } catch (err) { toast(err.message, "error"); refresh(); }
  });
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
      } else if (act === "brand-new") {
        brandForm = !brandForm;
        render();
        if (brandForm) root.querySelector("#brand-domain")?.focus();
        return;
      } else if (act === "brand-save") {
        const domain = root.querySelector("#brand-domain").value.trim();
        const allow = root.querySelector("#brand-allow").value.split(/[\s,]+/).filter(Boolean);
        const web_check = root.querySelector("#brand-web").value;
        if (!domain) { toast("Enter the brand's domain, e.g. acme.com"); return; }
        await api.post("/api/brand-watches", { domain, allow, web_check });
        brandForm = false;
        toast("Watching: existing lookalikes are recorded first; certificates from the last 14 days are reported", "success", 6000);
      } else if (act === "brand-run") {
        await api.post(`/api/brand-watches/${enc(id)}/run`);
        toast("Checking Certificate Transparency now: results show here in a minute", "success");
      } else if (act === "brand-delete") {
        const ok = await confirmDialog({ title: "Stop watching this brand?", message: "Alerts it raised are kept.", confirm: "Stop watching", danger: true });
        if (!ok) return;
        await api.del(`/api/brand-watches/${enc(id)}`);
        toast("Brand watch removed");
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
    brandWatches = await api.get("/api/brand-watches").catch(() => []);
    routes = (await api.get("/api/opsec/routes").catch(() => ({ routes: [] }))).routes || [];
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
              ${a.summary?.brand_watch ? html`<div class="list-sub mono">${a.summary.brand_watch.findings.slice(0, 6).map((f) => f.display).join(" · ")}</div>` : ""}
              <div class="list-sub">${timeAgo(a.created_at)}${a.acknowledged_at ? html` · acknowledged by ${a.acknowledged_by}` : ""}</div></div>
            ${a.summary?.brand_watch ? ""
              : a.summary?.exposure ? html`<a class="btn sm" href="#/exposure">${ico("breach")}View exposure</a>`
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
    ${brandCard()}
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

const SEV = { high: "high", medium: "medium", low: "low", critical: "critical" };

/** Brands whose lookalike domains are looked for in Certificate Transparency every day. */
function brandCard() {
  return html`<div class="card card-pad" style="margin-top:16px">
    <div class="card-head"><h2>Brand watch</h2>
      <button class="btn sm" data-act="brand-new">${ico("eye")}Watch a brand</button></div>
    <p class="muted small">Phishing sites need a certificate, and certificates are public. Argus checks Certificate Transparency every day for lookalikes of your domain (acme-login.com, acrne.com, look-alike letters) and alerts on new ones.</p>
    ${brandForm ? html`<div class="card-pad" style="border:1px solid var(--border);border-radius:8px;margin:10px 0">
      <label class="small">Your domain<input id="brand-domain" class="input" placeholder="acme.com" autocomplete="off"></label>
      <label class="small" style="display:block;margin-top:8px">Other domains you own (never reported)<input id="brand-allow" class="input" placeholder="acme.co.uk, acme-careers.com" autocomplete="off"></label>
      <label class="small" style="display:block;margin-top:8px">Visit lookalikes' websites (to spot cloned login pages)${webSelect("brand-web", "off")}</label>
      <p class="muted small">Visiting a phishing site tells whoever runs it that someone looked, and from which address. Use a route (Tor, a VPN) to hide this server. DNS checks are always on and passive.</p>
      <div style="margin-top:10px"><button class="btn primary sm" data-act="brand-save">Start watching</button></div></div>` : ""}
    ${!brandWatches.length ? (brandForm ? "" : html`<p class="muted small">No brand watched yet.</p>`)
      : brandWatches.map((w) => html`<div class="list-row" style="align-items:flex-start">
        <div class="list-main"><div class="list-title"><b>${w.domain}</b> <span class="muted small">every ${w.interval_hours === 24 ? "day" : "week"} · ${w.known} lookalike${w.known === 1 ? "" : "s"} known${w.allow.length ? ` · ${w.allow.length} own domain${w.allow.length === 1 ? "" : "s"} excluded` : ""}</span></div>
          <div class="list-sub">${w.last_run_at ? html`<span class="pill ${w.last_status === "ok" ? "ok" : w.last_status === "partial" ? "medium" : "high"}" title="${Object.entries(w.sources || {}).map(([k, v]) => `${k}: ${v.message || v.status}`).join("\n")}">${w.last_status}</span> ${timeAgo(w.last_run_at)} · ${w.last_message}` : "First check pending"}</div>
          ${w.recent.slice(0, 8).map((f) => html`<div class="list-sub"><span class="pill ${SEV[f.triage?.severity || f.severity] || ""}">${f.triage?.severity || f.severity}</span> ${f.triage ? html`<span class="pill ${f.triage.verdict === "phishing" ? "critical" : ""}" title="${(f.triage.reasons || []).join("\n")}">${f.triage.label}</span> ` : ""}<span class="mono" title="${(f.hosts || []).join("\n")}">${f.display}</span>${f.host_count > 1 ? html` <span class="muted">+${f.host_count - 1} host${f.host_count > 2 ? "s" : ""}</span>` : ""} <span class="muted">${f.technique}: ${f.detail} · ${f.issuer || "?"} · ${String(f.not_before).slice(0, 10)}</span></div>`)}</div>
        <div class="actions">
          <label class="small muted" title="Visit lookalikes' websites to spot cloned login pages">Websites ${webSelect("", w.web_check, w.id)}</label>
          <button class="btn sm ghost" data-act="brand-run" data-id="${w.id}" title="Check Certificate Transparency now">Run now</button>
          <button class="btn sm ghost icon" data-act="brand-delete" data-id="${w.id}" title="Stop watching" aria-label="Stop watching">${ico("trash")}</button>
        </div></div>`)}
  </div>`;
}

/** Off, direct, or one of the configured egress routes. */
function webSelect(id, value, watchId = "") {
  const options = [["off", "Don't visit"], ["direct", "Visit directly"], ...routes.map((r) => [r.name, `Through ${r.name}`])];
  return html`<select class="select" style="width:auto;margin-left:6px" ${id ? html`id="${id}"` : ""} ${watchId ? html`data-act-change="brand-web" data-id="${watchId}"` : ""}>
    ${options.map(([v, label]) => html`<option value="${v}" ${v === value ? "selected" : ""}>${label}</option>`)}</select>`;
}
