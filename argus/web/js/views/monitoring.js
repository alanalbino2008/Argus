// Monitoring: drift alerts first, then watched targets.

import { api, downloadPost, enc } from "../api.js";
import { empty, ico, severityPill } from "../components.js";
import { $, closeModal, confirmDialog, copyText, html, on, openModal, setHTML, timeAgo, toast } from "../dom.js";
import { emit, state } from "../state.js";
import { showCase } from "./cases.js";
import { handleNotificationAction, initNotifications, loadNotifications, notificationsCard } from "./notifications.js";
import { handleScheduleAction, initSchedules, loadSchedules, schedulesCard } from "./schedules.js";

let root;
let actions;
let alerts = null;
let alertFilter = "open"; // open | mine | unassigned | closed
let alertStats = null;
let assignees = { me: "", assignees: [] };
let monitors = null;
let fpWatches = []; // watched fingerprints (Shodan/Censys searches on a schedule)
let brandWatches = []; // brands whose lookalike domains are looked for in Certificate Transparency
let brandForm = false;
let brandSummary = null; // headline brand-protection numbers (90 days)
let campaigns = []; // lookalikes, watched servers and tagged indicators sharing infrastructure
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
        const login = root.querySelector("#brand-login").value.trim();
        if (!domain) { toast("Enter the brand's domain, e.g. acme.com"); return; }
        const home = `https://${domain.replace(/^https?:\/\//, "").split("/")[0]}/`;
        await api.post("/api/brand-watches", { domain, allow, web_check, reference_urls: login ? [home, login] : [] });
        brandForm = false;
        toast("Watching: existing lookalikes are recorded first; certificates from the last 14 days are reported", "success", 6000);
      } else if (act === "alert-filter") {
        alertFilter = id;
        refresh();
        return;
      } else if (act === "alert") {
        return openAlert(id);
      } else if (act === "brand-report") {
        toast("Preparing the brand-protection report…");
        await downloadPost("/api/brand-protection/report", { days: 90 });
        return;
      } else if (act === "campaign-takedown") {
        return openCampaignTakedown(id);
      } else if (act === "lookalike-case") {
        const ok = await confirmDialog({ title: `Open a case for ${btn.dataset.domain}?`, confirm: "Open case",
          message: "The case gets the domain, what it imitates, its timeline and the triage evidence, and a capture of its website (through the watch's route) as preserved evidence. Confirm this is for brand protection: a legitimate purpose." });
        if (!ok) return;
        toast("Opening the case and capturing the website…", "info", 6000);
        const r = await api.post(`/api/brand-watches/${enc(id)}/lookalikes/${enc(btn.dataset.domain)}/case`, { confirmed: true });
        if (r.warning) toast(r.warning, "error", 8000);
        await showCase(r.case.id);
        return;
      } else if (act === "show-case") {
        await showCase(btn.dataset.case);
        return;
      } else if (act === "takedown") {
        return openTakedown(id, btn.dataset.domain);
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
    const query = { open: "status=open,investigating", mine: "assignee=me&status=open,investigating",
      unassigned: "assignee=none&status=open,investigating", closed: "status=resolved,false_positive" }[alertFilter];
    [alerts, monitors, fpWatches] = await Promise.all([api.get(`/api/alerts?limit=100&${query}`), api.get("/api/monitors"),
      api.get("/api/fingerprint-watches").catch(() => []), loadNotifications(), loadSchedules()]);
    alertStats = await api.get("/api/alerts/stats?days=30").catch(() => null);
    brandWatches = await api.get("/api/brand-watches").catch(() => []);
    routes = (await api.get("/api/opsec/routes").catch(() => ({ routes: [] }))).routes || [];
    campaigns = (await api.get("/api/campaigns").catch(() => ({ campaigns: [] }))).campaigns || [];
    brandSummary = brandWatches.length ? await api.get("/api/brand-protection/summary?days=90").catch(() => null) : null;
  } catch {
    return;
  }
  state.alertsOpen = alertStats ? alertStats.open : alerts.filter((a) => !a.acknowledged_at).length;
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
      <div class="card-head wrap"><h2>Alerts</h2>
        <span class="muted small">${alertStats ? `${alertStats.open} open · ${alertStats.unassigned} unassigned${alertStats.median_hours_to_resolve != null ? ` · resolved in ${hoursText(alertStats.median_hours_to_resolve)} (median, 30 days)` : ""}` : ""}</span></div>
      <div class="segmented" style="margin:6px 0 10px">${[["open", "Open"], ["mine", "Mine"], ["unassigned", "Unassigned"], ["closed", "Closed"]].map(([k, label]) =>
        html`<button class="btn sm ${alertFilter === k ? "primary" : "ghost"}" data-act="alert-filter" data-id="${k}">${label}</button> `)}</div>
      ${alerts === null ? html`<p class="muted">Loading…</p>`
        : !alerts.length ? empty("bell", alertFilter === "closed" ? "Nothing closed yet" : "No open alerts", "When a watched target changes materially — a new attack path, a newly exposed service, a fresh breach — it shows up here.")
        : html`<div class="list">${alerts.map((a) => html`
          <div class="list-row" style="${["resolved", "false_positive"].includes(a.status) ? "opacity:.65" : ""}">
            ${severityPill(a.severity)}
            <div class="list-main"><div class="list-title" style="white-space:normal"><a data-act="alert" data-id="${a.id}" style="cursor:pointer">${a.headline}</a></div>
              ${a.summary?.brand_watch ? html`<div class="list-sub mono">${a.summary.brand_watch.findings.slice(0, 6).map((f) => f.display).join(" · ")}</div>` : ""}
              <div class="list-sub">${timeAgo(a.created_at)} · <span class="pill ${STATUS[a.status]?.[0] || ""}">${STATUS[a.status]?.[1] || a.status}</span> ${a.assignee ? html`· ${a.assignee}` : html`· <span class="muted">unassigned</span>`}${a.comments ? ` · ${a.comments} comment${a.comments === 1 ? "" : "s"}` : ""}</div></div>
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
    ${campaignCard()}
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
    ${brandStrip()}
    <p class="muted small">Phishing sites need a certificate, and certificates are public. Argus checks Certificate Transparency every day for lookalikes of your domain (acme-login.com, acrne.com, look-alike letters) and alerts on new ones.</p>
    ${brandForm ? html`<div class="card-pad" style="border:1px solid var(--border);border-radius:8px;margin:10px 0">
      <label class="small">Your domain<input id="brand-domain" class="input" placeholder="acme.com" autocomplete="off"></label>
      <label class="small" style="display:block;margin-top:8px">Other domains you own (never reported)<input id="brand-allow" class="input" placeholder="acme.co.uk, acme-careers.com" autocomplete="off"></label>
      <label class="small" style="display:block;margin-top:8px">Visit lookalikes' websites (to spot cloned login pages)${webSelect("brand-web", "off")}</label>
      <p class="muted small">Visiting a phishing site tells whoever runs it that someone looked, and from which address. Use a route (Tor, a VPN) to hide this server. DNS checks are always on and passive.</p>
      <label class="small" style="display:block;margin-top:8px">Your login page (optional: lookalikes that look like it are flagged, even with a different title and icon)<input id="brand-login" class="input" placeholder="https://login.acme.com/" autocomplete="off"></label>
      <div style="margin-top:10px"><button class="btn primary sm" data-act="brand-save">Start watching</button></div></div>` : ""}
    ${!brandWatches.length ? (brandForm ? "" : html`<p class="muted small">No brand watched yet.</p>`)
      : brandWatches.map((w) => html`<div class="list-row" style="align-items:flex-start">
        <div class="list-main"><div class="list-title"><b>${w.domain}</b> <span class="muted small">every ${w.interval_hours === 24 ? "day" : "week"} · ${w.known} lookalike${w.known === 1 ? "" : "s"} known${w.allow.length ? ` · ${w.allow.length} own domain${w.allow.length === 1 ? "" : "s"} excluded` : ""}${w.references?.length ? ` · compared with ${w.references.length} of your page${w.references.length === 1 ? "" : "s"}` : ""}</span></div>
          <div class="list-sub">${w.last_run_at ? html`<span class="pill ${w.last_status === "ok" ? "ok" : w.last_status === "partial" ? "medium" : "high"}" title="${Object.entries(w.sources || {}).map(([k, v]) => `${k}: ${v.message || v.status}`).join("\n")}">${w.last_status}</span> ${timeAgo(w.last_run_at)} · ${w.last_message}` : "First check pending"}</div>
          ${w.recent.slice(0, 8).map((f) => html`<div class="list-sub"><span class="pill ${SEV[f.triage?.severity || f.severity] || ""}">${f.triage?.severity || f.severity}</span> ${f.triage ? html`<span class="pill ${f.triage.verdict === "phishing" ? "critical" : ""}" title="${(f.triage.reasons || []).join("\n")}">${f.triage.label}</span> ` : ""}${takedownPill(w, f)}<span class="mono" title="${(f.hosts || []).join("\n")}">${f.display}</span>${f.host_count > 1 ? html` <span class="muted">+${f.host_count - 1} host${f.host_count > 2 ? "s" : ""}</span>` : ""} <span class="muted">${f.technique}: ${f.detail} · ${f.issuer || "?"} · ${String(f.not_before).slice(0, 10)}</span></div>`)}</div>
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

const TAKEDOWN = { drafted: ["", "Takedown drafted"], reported: ["medium", "Reported"], down: ["ok", "Taken down"], closed: ["", "Takedown closed"] };

/** A takedown's state, or a button to start one (for anything not defensive or already down). */
function takedownPill(w, f) {
  const t = (w.takedowns || {})[f.name];
  if (t) {
    const [cls, label] = TAKEDOWN[t.status] || ["", t.status];
    const when = t.status === "down" && t.reported_at ? ` after ${timeAgo(t.reported_at).replace(" ago", "")}` : "";
    return html`<button class="pill ${cls}" style="cursor:pointer;border:0" data-act="takedown" data-id="${w.id}" data-domain="${f.name}" title="Open the takedown request">${label}${when}</button> ${caseButton(w, f)}`;
  }
  if (!["analyst", "admin"].includes(state.workspace?.role) || ["yours", "dormant"].includes(f.triage?.verdict)) return caseButton(w, f);
  return html`<button class="btn sm ghost" style="padding:0 6px" data-act="takedown" data-id="${w.id}" data-domain="${f.name}">Report abuse</button> ${caseButton(w, f)}`;
}

async function openTakedown(watchId, domain) {
  let watch = brandWatches.find((w) => w.id === watchId);
  let record = watch?.takedowns?.[domain];
  if (!record) {
    toast(`Looking up ${domain}'s registrar and host…`);
    record = await api.post(`/api/brand-watches/${enc(watchId)}/takedowns`, { domain });
    await refresh();
    watch = brandWatches.find((w) => w.id === watchId);
  }
  const d = record.draft || { to: [], subject: "", body: "" };
  const reg = record.contacts?.registrar || {};
  const contacts = [reg.registrar && `Registrar: ${reg.registrar}${reg.abuse_email ? ` (${reg.abuse_email})` : ""}`,
    ...(record.contacts?.hosts || []).map((h) => `Host of ${h.ip}: ${h.network || "unknown"}${h.abuse_email ? ` (${h.abuse_email})` : ""}`)].filter(Boolean);
  setHTML($("#takedown-title"), html`Takedown request: <span class="mono">${domain}</span>`);
  setHTML($("#takedown-intro"), html`Argus drafted this abuse report for the domain's registrar and host. Send it from your own mailbox (abuse desks reply to the sender), then mark it reported: Argus keeps checking the domain and tells you when it goes down.`);
  setHTML($("#takedown-body"), html`
    <dl class="kv"><dt>Status</dt><dd>${(TAKEDOWN[record.status] || ["", record.status])[1]}${record.reported_at ? ` · reported ${timeAgo(record.reported_at)}` : ""}${record.down_at ? ` · down ${timeAgo(record.down_at)}` : ""}</dd>
      <dt>Send to</dt><dd class="mono">${d.to.length ? d.to.join(", ") : "No abuse address in RDAP: use the registrar's abuse form"}</dd>
      ${contacts.length ? html`<dt>Found in RDAP</dt><dd>${contacts.map((c) => html`<div class="small">${c}</div>`)}</dd>` : ""}
      <dt>Subject</dt><dd><input id="takedown-subject" class="input" value="${d.subject}"></dd></dl>
    <textarea id="takedown-text" class="textarea" rows="16" style="width:100%;margin-top:8px;font-family:var(--mono, monospace);font-size:12px">${d.body}</textarea>
    ${(record.history || []).length ? html`<p class="muted small" style="margin-top:8px">${record.history.map((h) => `${h.event} ${timeAgo(h.at)}${h.by ? ` by ${h.by}` : ""}`).join(" · ")}</p>` : ""}`);
  const open = ["drafted", "reported"].includes(record.status);
  setHTML($("#takedown-foot"), html`
    <button class="btn ghost" data-close>Close</button>
    <button class="btn" data-td="copy">Copy text</button>
    <button class="btn" data-td="mail" ${d.to.length ? "" : "disabled"}>Open in email</button>
    ${open ? html`<button class="btn ghost" data-td="close-takedown" title="Stop tracking (refused, false alarm, handled elsewhere)">Stop tracking</button>` : ""}
    ${record.status === "drafted" ? html`<button class="btn primary" data-td="reported">Mark as reported</button>` : ""}`);
  $("#takedown-body").onclick = null; // the campaign dialog shares this modal
  const foot = $("#takedown-foot");
  foot.onclick = async (e) => {
    const action = e.target.closest("[data-td]")?.dataset.td;
    if (!action) return;
    const subject = $("#takedown-subject").value;
    const body = $("#takedown-text").value;
    try {
      if (action === "copy") return copyText(`To: ${d.to.join(", ")}\nSubject: ${subject}\n\n${body}`);
      if (action === "mail") { window.location.href = `mailto:${d.to.map(encodeURIComponent).join(",")}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`; return; }
      if (action === "reported") await api.post(`/api/brand-watches/${enc(watchId)}/takedowns/${enc(domain)}/reported`);
      if (action === "close-takedown") await api.post(`/api/brand-watches/${enc(watchId)}/takedowns/${enc(domain)}/close`, { reason: "" });
      closeModal("takedown-modal");
      toast(action === "reported" ? "Reported: Argus will tell you when it goes down" : "No longer tracked", "success");
      refresh();
    } catch (err) { toast(err.message, "error"); }
  };
  openModal("takedown-modal");
}

const KIND = { lookalike: "Lookalike", server: "Server", tagged: "Tagged" };

/** Groups of lookalikes, watched servers and tagged indicators sharing infrastructure (one actor, one report). */
function campaignCard() {
  if (!campaigns.length) return "";
  return html`<div class="card card-pad" style="margin-top:16px">
    <div class="card-head"><h2>Campaigns</h2><span class="muted small">${campaigns.length} group${campaigns.length === 1 ? "" : "s"} sharing infrastructure</span></div>
    <p class="muted small">Lookalike domains, watched servers and tagged indicators that share an address, private name servers, a mail host, a favicon or a page title are probably one actor's. One report to their host can take several down.</p>
    ${campaigns.slice(0, 20).map((c) => html`<div class="list-row" style="align-items:flex-start">
      ${severityPill(c.severity)}
      <div class="list-main"><div class="list-title" style="white-space:normal"><b>${c.size} items</b> · ${c.name}${c.brands.length ? html` <span class="muted small">imitating ${c.brands.join(", ")}</span>` : ""}</div>
        <div class="list-sub">${c.links.slice(0, 4).map((l) => html`<span class="pill" style="text-transform:none" title="${l.members.join("\n")}">${l.label}: <span class="mono">${l.value}</span> (${l.members.length})</span> `)}</div>
        <div class="list-sub">${c.members.slice(0, 12).map((m) => html`<span class="pill ${m.verdict === "phishing" ? "critical" : ""}" style="text-transform:none" title="${[KIND[m.kind], m.verdict, m.takedown && `takedown ${m.takedown}`, (m.tags || []).join(", ")].filter(Boolean).join(" · ")}"><span class="mono">${m.display}</span>${m.takedown === "down" ? " ✓" : ""}</span> `)}${c.members.length > 12 ? html`<span class="muted small">+${c.members.length - 12} more</span>` : ""}</div>
        ${c.first_seen ? html`<div class="list-sub muted small">First seen ${timeAgo(c.first_seen)}${c.last_seen && c.last_seen !== c.first_seen ? ` · latest ${timeAgo(c.last_seen)}` : ""}</div>` : ""}</div>
      ${["analyst", "admin"].includes(state.workspace?.role) && c.members.some((m) => m.kind === "lookalike")
        ? html`<button class="btn sm" data-act="campaign-takedown" data-id="${c.id}" title="One abuse report per registrar and host, listing all of this campaign's domains">Take down campaign</button>` : ""}
    </div>`)}
  </div>`;
}

/** Takedowns for a whole campaign: one report per registrar and host, each domain tracked on its own. */
async function openCampaignTakedown(campaignId) {
  toast("Looking up the registrars and hosts of the campaign's domains…", "info", 6000);
  let result;
  try { result = await api.post(`/api/campaigns/${enc(campaignId)}/takedown`, {}); } catch (err) { toast(err.message, "error"); return; }
  const where = Object.fromEntries(result.domains.map((d) => [d.domain, d.watch_id]));
  setHTML($("#takedown-title"), html`Campaign takedown: ${result.letters.length} report${result.letters.length === 1 ? "" : "s"}`);
  setHTML($("#takedown-intro"), html`One report per registrar and host, each listing the campaign's domains it is responsible for. Send each from your own mailbox, then mark it reported: Argus follows every domain until it goes down.`);
  setHTML($("#takedown-body"), html`
    <p class="muted small">${result.drafted.length ? `${result.drafted.length} domain(s) drafted now` : "No new domains"}${result.already_open.length ? ` · ${result.already_open.length} already had a takedown` : ""}. Each registrar and host gets one report listing its domains; each domain is followed until it goes down.</p>
    ${!result.letters.length ? html`<div class="callout warn">No abuse address was found in RDAP for these domains: use the registrars' abuse forms.</div>` : ""}
    ${result.letters.map((l, i) => html`<div class="card card-pad" style="margin-top:10px">
      <div class="small"><b class="mono">${l.to.join(", ")}</b> <span class="muted">${(l.roles || []).join(", ")}</span></div>
      <div class="small muted">${l.domains.length} domain${l.domains.length === 1 ? "" : "s"}: <span class="mono">${l.domains.join(", ")}</span></div>
      <input class="input" data-letter-subject="${i}" value="${l.subject}" style="margin-top:6px">
      <textarea class="textarea" data-letter-body="${i}" rows="10" style="width:100%;margin-top:6px;font-family:var(--mono, monospace);font-size:12px">${l.body}</textarea>
      <div style="margin-top:6px;display:flex;gap:6px;justify-content:flex-end">
        <button class="btn sm" data-letter="copy" data-i="${i}">Copy text</button>
        <button class="btn sm" data-letter="mail" data-i="${i}">Open in email</button>
        <button class="btn sm primary" data-letter="reported" data-i="${i}">${l.domains.length > 1 ? `Mark these ${l.domains.length} reported` : "Mark reported"}</button></div></div>`)}`);
  setHTML($("#takedown-foot"), html`<button class="btn ghost" data-close>Close</button>`);
  $("#takedown-foot").onclick = null;
  $("#takedown-body").onclick = async (e) => {
    const btn = e.target.closest("[data-letter]");
    if (!btn) return;
    const i = Number(btn.dataset.i);
    const letter = result.letters[i];
    const subject = $(`[data-letter-subject="${i}"]`).value;
    const body = $(`[data-letter-body="${i}"]`).value;
    try {
      if (btn.dataset.letter === "copy") return copyText(`To: ${letter.to.join(", ")}\nSubject: ${subject}\n\n${body}`);
      if (btn.dataset.letter === "mail") { window.location.href = `mailto:${letter.to.map(encodeURIComponent).join(",")}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`; return; }
      let marked = 0;
      for (const domain of letter.domains) {
        try { await api.post(`/api/brand-watches/${enc(where[domain])}/takedowns/${enc(domain)}/reported`); marked += 1; } catch { /* already reported or down */ }
      }
      btn.disabled = true;
      btn.textContent = "Reported";
      toast(`${marked} domain(s) marked reported: Argus will tell you when they go down`, "success");
      refresh();
    } catch (err) { toast(err.message, "error"); }
  };
  openModal("takedown-modal");
  refresh();
}

/** The last 90 days in five numbers, and the report for management. */
function brandStrip() {
  const b = brandSummary;
  if (!b) return "";
  const take = b.takedowns;
  const cell = (value, label, tone = "") => html`<div style="flex:1;min-width:120px;padding:10px 12px;border:1px solid var(--border);border-radius:8px">
    <div style="font-size:20px;font-weight:700;${tone}">${value}</div><div class="muted small">${label}</div></div>`;
  return html`<div style="display:flex;gap:8px;flex-wrap:wrap;margin:8px 0 10px">
    ${cell(b.open_threats.count, "open threats", b.open_threats.count ? "color:var(--sev-critical)" : "")}
    ${cell(b.found.new, "new lookalikes (90 days)")}
    ${cell(take.down_in_period, "taken down (90 days)")}
    ${cell(take.median_days_to_down != null ? `${take.median_days_to_down} d` : "–", "median time to takedown")}
    ${cell(b.campaigns.count, "campaigns")}
    ${["analyst", "admin"].includes(state.workspace?.role) ? html`<div style="display:flex;align-items:center"><button class="btn sm" data-act="brand-report" title="A PDF for management, registered and verifiable like every Argus report">${ico("download")}Report (PDF)</button></div>` : ""}
  </div>`;
}

const STATUS = { open: ["high", "Open"], investigating: ["medium", "Investigating"], resolved: ["ok", "Resolved"], false_positive: ["", "False positive"] };

function hoursText(h) {
  return h < 1 ? `${Math.round(h * 60)} min` : h < 48 ? `${Math.round(h)} h` : `${Math.round(h / 24)} days`;
}

/** One alert: move it along, assign it, discuss it; everything is kept in its activity. */
async function openAlert(alertId) {
  let alert;
  try {
    [alert, assignees] = await Promise.all([api.get(`/api/alerts/${enc(alertId)}`), api.get("/api/alerts/assignees")]);
  } catch (err) { toast(err.message, "error"); return; }
  const canEdit = ["analyst", "admin"].includes(state.workspace?.role);
  const describe = (e) => e.event === "comment" ? e.body
    : e.event === "status" ? `${STATUS[e.from]?.[1] || e.from} → ${STATUS[e.to]?.[1] || e.to}${e.note ? `: ${e.note}` : ""}`
    : e.event === "assigned" ? (e.to ? `Assigned to ${e.to}` : "Unassigned") + (e.note ? `: ${e.note}` : "")
    : e.event === "acknowledged" ? "Acknowledged" : e.event;
  setHTML($("#alert-title"), html`${alert.headline}`);
  setHTML($("#alert-sub"), html`${severityPill(alert.severity)} raised ${timeAgo(alert.created_at)}${alert.resolved_at ? ` · closed ${timeAgo(alert.resolved_at)} by ${alert.resolved_by}` : ""}`);
  setHTML($("#alert-body"), html`
    ${canEdit ? html`<div class="grid two" style="gap:10px">
      <label class="small">Status<select id="alert-status" class="select">${Object.entries(STATUS).map(([k, [, label]]) => html`<option value="${k}" ${k === alert.status ? "selected" : ""}>${label}</option>`)}</select></label>
      <label class="small">Assigned to<select id="alert-assignee" class="select"><option value="">Unassigned</option>${assignees.assignees.map((n) => html`<option value="${n}" ${n === alert.assignee ? "selected" : ""}>${n}${n === assignees.me ? " (me)" : ""}</option>`)}</select></label></div>
      <textarea id="alert-note" class="textarea" rows="2" style="width:100%;margin-top:8px" placeholder="Why (optional): kept with the change"></textarea>
      <div style="margin-top:6px;text-align:right"><button class="btn sm primary" data-alert="save">Save</button></div>` : html`<p class="small">Status: <b>${STATUS[alert.status]?.[1]}</b> · ${alert.assignee || "unassigned"}</p>`}
    <div class="section-title" style="margin-top:14px">Activity</div>
    ${(alert.activity || []).length ? html`<div class="list">${[...alert.activity].reverse().map((e) => html`<div class="list-row" style="align-items:flex-start">
      <div class="list-main"><div class="small" style="white-space:pre-wrap">${describe(e)}</div><div class="list-sub">${e.by} · ${timeAgo(e.at)}</div></div></div>`)}</div>`
      : html`<p class="muted small">Nothing yet.</p>`}
    ${canEdit ? html`<textarea id="alert-comment" class="textarea" rows="3" style="width:100%;margin-top:10px" placeholder="Add a comment for the team"></textarea>
      <div style="margin-top:6px;text-align:right"><button class="btn sm" data-alert="comment">Comment</button></div>` : ""}`);
  $("#alert-body").onclick = async (e) => {
    const action = e.target.closest("[data-alert]")?.dataset.alert;
    if (!action) return;
    try {
      if (action === "save") {
        const body = { status: $("#alert-status").value, assignee: $("#alert-assignee").value, note: $("#alert-note").value.trim() };
        await api.patch(`/api/alerts/${enc(alertId)}`, body);
        toast("Alert updated", "success");
      } else {
        const text = $("#alert-comment").value.trim();
        if (!text) return;
        await api.post(`/api/alerts/${enc(alertId)}/comments`, { body: text });
      }
      await refresh();
      openAlert(alertId);
    } catch (err) { toast(err.message, "error"); }
  };
  openModal("alert-modal");
}

/** The lookalike's case, or (for analysts) a button to open one with the evidence. */
function caseButton(w, f) {
  if (f.case_id) return html`<button class="btn sm ghost" style="padding:0 6px" data-act="show-case" data-case="${f.case_id}">${ico("report")}Case</button> `;
  if (!["analyst", "admin"].includes(state.workspace?.role) || f.triage?.verdict === "yours") return "";
  return html`<button class="btn sm ghost" style="padding:0 6px" data-act="lookalike-case" data-id="${w.id}" data-domain="${f.name}" title="A case with the evidence, and a capture of the website">Open case</button> `;
}
