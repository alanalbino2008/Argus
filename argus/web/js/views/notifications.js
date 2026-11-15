// Notification destinations (Slack, Teams, email, signed webhooks), integrations (Jira,
// ServiceNow, Splunk, Microsoft Sentinel) and the delivery log.
// Rendered inside the Monitoring page for workspace administrators.

import { api, enc } from "../api.js";
import { empty, ico, severityPill } from "../components.js";
import { $, closeModal, confirmDialog, copyText, html, openModal, setHTML, timeAgo, toast } from "../dom.js";
import { state } from "../state.js";

const TYPES = {
  slack: {
    label: "Slack", sub: "Channel webhook", url: "Slack incoming-webhook URL", placeholder: "https://hooks.slack.com/services/…",
    hint: "In Slack: Apps → Incoming Webhooks → Add to Slack, pick the channel, copy the Webhook URL.",
  },
  teams: {
    label: "Microsoft Teams", sub: "Workflows webhook", url: "Teams workflow URL", placeholder: "https://…logic.azure.com/workflows/…",
    hint: "In the Teams channel: ⋯ → Workflows → “Post to a channel when a webhook request is received”, then copy the URL.",
  },
  email: { label: "Email", sub: "Via the server's SMTP", url: "", placeholder: "", hint: "" },
  webhook: {
    label: "Webhook", sub: "Signed JSON, any system", url: "HTTPS endpoint", placeholder: "https://siem.company.com/argus",
    hint: "Argus POSTs a signed JSON event (Standard Webhooks). Use it for a SIEM, SOAR, ticketing or PagerDuty-style tool.",
  },
  jira: {
    label: "Jira", sub: "Alert → issue", url: "Jira site", placeholder: "https://your-company.atlassian.net",
    hint: "Each alert becomes one issue (never a duplicate, even when a delivery is retried). Jira Data Center works too.",
    fields: [
      ["project_key", "Project key", { placeholder: "SEC" }],
      ["issue_type", "Issue type", { placeholder: "Task", optional: true }],
      ["email", "Account email (Jira Cloud)", { placeholder: "argus-bot@company.com", optional: true, hint: "Leave empty for a Data Center personal access token." }],
      ["api_token", "API token", { secret: true, hint: "Jira Cloud: id.atlassian.com → Security → API tokens. Use a dedicated account that can create issues in the project." }],
    ],
  },
  servicenow: {
    label: "ServiceNow", sub: "Alert → incident", url: "Instance URL", placeholder: "https://your-company.service-now.com",
    hint: "Each alert becomes one incident, correlated by the alert's ID, with impact and urgency set from its severity.",
    fields: [
      ["username", "Integration user", { placeholder: "argus.integration" }],
      ["password", "Password", { secret: true, hint: "Give the user the itil role (or REST access to the incident table) and nothing more." }],
      ["assignment_group", "Assignment group", { placeholder: "Security Operations", optional: true }],
    ],
  },
  splunk: {
    label: "Splunk", sub: "HTTP Event Collector", url: "HEC URL", placeholder: "https://http-inputs-acme.splunkcloud.com",
    hint: "Alerts, reports and tests are sent as JSON events to /services/collector/event.",
    fields: [
      ["token", "HEC token", { secret: true, hint: "Settings → Data inputs → HTTP Event Collector → New token." }],
      ["index", "Index", { placeholder: "security", optional: true }],
      ["sourcetype", "Sourcetype", { placeholder: "argus:event", optional: true }],
    ],
  },
  sentinel: {
    label: "Microsoft Sentinel", sub: "Logs Ingestion API", url: "Data collection endpoint", placeholder: "https://argus-dce-a1b2.westeurope-1.ingest.monitor.azure.com",
    hint: "Events land in a custom table of your Log Analytics workspace, ready for analytics rules. docs/API.md has the table schema.",
    fields: [
      ["dcr_id", "Data collection rule ID", { placeholder: "dcr-0123456789abcdef0123456789abcdef" }],
      ["stream", "Stream", { placeholder: "Custom-ArgusEvents_CL", optional: true }],
      ["tenant_id", "Tenant ID", { placeholder: "00000000-0000-0000-0000-000000000000" }],
      ["client_id", "Application (client) ID", { placeholder: "00000000-0000-0000-0000-000000000000" }],
      ["client_secret", "Client secret", { secret: true, hint: "The app registration needs the Monitoring Metrics Publisher role on the data collection rule." }],
    ],
  },
};
const TICKETING = new Set(["jira", "servicenow"]);

let data = null; // { caps, channels, deliveries }
let chosen = "slack";
let onChange = () => {};

export const isWorkspaceAdmin = () => state.workspace?.role === "admin";

export async function loadNotifications() {
  if (!isWorkspaceAdmin()) return (data = null);
  try {
    const [caps, channels, deliveries] = await Promise.all([
      api.get("/api/notifications/capabilities"),
      api.get("/api/notifications/channels"),
      api.get("/api/notifications/deliveries?limit=15"),
    ]);
    data = { caps, channels, deliveries };
  } catch {
    data = null;
  }
  return data;
}

function destination(c) {
  if (c.type === "email") return (c.recipients || []).join(", ");
  const extra = { jira: c.project_key && `project ${c.project_key} · ${c.issue_type}`, servicenow: c.username && `as ${c.username}`,
    splunk: c.index && `index ${c.index}`, sentinel: c.stream }[c.type];
  return extra ? `${c.destination} · ${extra}` : c.destination;
}

function healthPill(c) {
  if (!c.enabled) return html`<span class="pill">Paused</span>`;
  if (c.health === "failing") return html`<span class="pill critical" title="${c.last_error || ""}">Failing</span>`;
  if (c.health === "ok") return html`<span class="pill ok">Working</span>`;
  return html`<span class="pill">Not tested</span>`;
}

function statusPill(d) {
  const cls = { delivered: "ok", failed: "critical", pending: "warn", sending: "accent", cancelled: "" }[d.status] ?? "";
  const label = d.status === "pending" && d.attempts ? "retrying" : d.status;
  return html`<span class="pill ${cls}">${label}</span>`;
}

export function notificationsCard() {
  if (!isWorkspaceAdmin() || !data) return "";
  const { caps, channels, deliveries } = data;
  const unavailable = !caps.types.length;
  return html`<div class="card card-pad" style="margin-top:16px">
    <div class="card-head">
      <div><h2>Notifications</h2><p class="muted small">Where this workspace's alerts are sent. Each destination has its own severity threshold; failed deliveries are retried for about 7 hours.</p></div>
      <button class="btn" data-act="n-add" ${unavailable ? "disabled" : ""}>${ico("plus")}Add destination</button>
    </div>
    ${unavailable ? html`<p class="muted small">${ico("info")} Notifications need server configuration: an encryption key (<code>ARGUS_ENCRYPTION_KEY</code>) for Slack, Teams and webhooks, and an SMTP server (<code>ARGUS_SMTP_HOST</code>) for email. See the deployment guide.</p>` : ""}
    ${!caps.public_url && channels.length ? html`<p class="muted small">${ico("info")} Set <code>ARGUS_PUBLIC_URL</code> so messages include an “Open in Argus” link.</p>` : ""}
    ${!channels.length ? (unavailable ? "" : empty("bell", "No destinations yet", "Send alerts to Slack, Microsoft Teams, email or your own systems, so nobody has to watch this page."))
      : html`<table class="table"><thead><tr><th>Destination</th><th>Sends</th><th>Status</th><th></th></tr></thead><tbody>
        ${channels.map((c) => html`<tr style="${c.enabled ? "" : "opacity:.6"}">
          <td><b>${c.name}</b> <span class="muted small">${TYPES[c.type]?.label || c.type}</span>
            <div class="muted small mono" style="overflow-wrap:anywhere">${destination(c)}</div>
            ${c.health === "failing" && c.last_error ? html`<div class="delivery-error">${c.last_error}</div>` : ""}</td>
          <td>${severityPill(c.min_severity)}<span class="muted small"> and above</span></td>
          <td>${healthPill(c)}${c.last_success_at ? html`<div class="muted small">last sent ${timeAgo(c.last_success_at)}</div>` : ""}</td>
          <td class="actions">
            <button class="btn sm" data-act="n-test" data-id="${c.id}">Send test</button>
            <button class="btn sm ghost" data-act="n-toggle" data-id="${c.id}" data-enabled="${c.enabled}">${c.enabled ? "Pause" : "Resume"}</button>
            ${c.type === "webhook" ? html`<button class="btn sm ghost" data-act="n-rotate" data-id="${c.id}" title="New signing secret; the old one keeps working for 24 hours">Rotate secret</button>` : ""}
            <button class="btn sm ghost icon" data-act="n-delete" data-id="${c.id}" title="Remove" aria-label="Remove ${c.name}">${ico("trash")}</button>
          </td></tr>`)}
      </tbody></table>`}
    ${deliveries.length ? html`<div class="section"><div class="section-title">Recent deliveries</div>
      <table class="table"><thead><tr><th>When</th><th>To</th><th>Message</th><th>Result</th><th></th></tr></thead><tbody>
      ${deliveries.map((d) => html`<tr>
        <td>${timeAgo(d.created_at)}</td>
        <td>${d.channel_name}</td>
        <td style="max-width:380px">${d.event_type === "notification.test" ? html`<span class="muted">Test message</span>` : d.summary}</td>
        <td>${statusPill(d)}${d.reference && d.status === "delivered" ? html` <span class="pill accent mono" style="text-transform:none" title="Created by the integration">${d.reference}</span>` : ""}${d.attempts > 1 ? html` <span class="muted small">${d.attempts} attempts</span>` : ""}
          ${d.last_error && d.status !== "delivered" ? html`<div class="delivery-error">${d.last_error}</div>` : ""}</td>
        <td class="actions">${d.status === "failed" || d.status === "cancelled" ? html`<button class="btn sm ghost" data-act="n-retry" data-id="${d.id}">Retry</button>` : ""}</td>
      </tr>`)}</tbody></table></div>` : ""}
  </div>`;
}

function showSecret(secret) {
  $("#secret-value").textContent = secret;
  $("#secret-copy").onclick = () => copyText(secret);
  openModal("secret-modal");
}

function renderTypes() {
  const allowed = new Set(data?.caps.types || []);
  if (!allowed.has(chosen)) chosen = [...allowed][0] || "slack";
  setHTML($("#channel-types"), html`${Object.entries(TYPES).map(([key, t]) => html`
    <button type="button" class="channel-type" role="radio" aria-checked="${key === chosen}" data-type="${key}" ${allowed.has(key) ? "" : html`disabled title="${key === "email" ? "Email isn't configured on this server" : "Needs ARGUS_ENCRYPTION_KEY on the server"}"`}>
      <b>${t.label}</b><small>${t.sub}</small></button>`)}`);
  const t = TYPES[chosen];
  setHTML($("#channel-extra"), html`${(t.fields || []).map(([key, label, o]) => html`<div class="field">
    <label class="label" for="ch-${key}">${label}${o.optional ? html` <span class="muted small">optional</span>` : ""}</label>
    <input id="ch-${key}" data-key="${key}" class="input ${o.secret ? "mono" : ""}" type="${o.secret ? "password" : "text"}" autocomplete="${o.secret ? "new-password" : "off"}" spellcheck="false" placeholder="${o.placeholder || ""}">
    ${o.hint ? html`<div class="hint">${o.hint}</div>` : ""}</div>`)}`);
  $("#channel-severity-label").textContent = TICKETING.has(chosen) ? "Open a ticket for alerts of at least" : "Send alerts of at least";
  $("#channel-url-field").hidden = chosen === "email";
  $("#channel-recipients-field").hidden = chosen !== "email";
  $("#channel-url-label").textContent = t.url;
  $("#channel-url").placeholder = t.placeholder;
  $("#channel-url-hint").textContent = t.hint;
}

function openAdd() {
  $("#channel-form").reset();
  $("#channel-error").textContent = "";
  renderTypes();
  openModal("channel-modal");
}

export async function handleNotificationAction(act, id, btn) {
  if (!act.startsWith("n-")) return false;
  if (act === "n-add") {
    openAdd();
    return true;
  }
  try {
    if (act === "n-test") {
      await api.post(`/api/notifications/channels/${enc(id)}/test`);
      toast("Test message queued — it should arrive within seconds", "success");
      setTimeout(onChange, 4000); // show the result in the delivery log
    } else if (act === "n-toggle") {
      await api.patch(`/api/notifications/channels/${enc(id)}`, { enabled: btn.dataset.enabled !== "true" });
    } else if (act === "n-rotate") {
      const ok = await confirmDialog({ title: "Rotate the signing secret?", message: "Requests are signed with both the old and the new secret for 24 hours, so you can update your receiver without missing alerts.", confirm: "Rotate" });
      if (!ok) return true;
      showSecret((await api.post(`/api/notifications/channels/${enc(id)}/rotate-secret`)).signing_secret);
    } else if (act === "n-delete") {
      const ok = await confirmDialog({ title: "Remove this destination?", message: "Alerts stop being sent there. Its delivery history is removed too.", confirm: "Remove", danger: true });
      if (!ok) return true;
      await api.del(`/api/notifications/channels/${enc(id)}`);
      toast("Destination removed");
    } else if (act === "n-retry") {
      await api.post(`/api/notifications/deliveries/${enc(id)}/retry`);
      toast("Sending again", "success");
      setTimeout(onChange, 4000);
    }
  } catch (err) {
    toast(err.message, "error");
  }
  await onChange();
  return true;
}

export function initNotifications(refresh) {
  onChange = refresh;
  $("#channel-types").addEventListener("click", (e) => {
    const btn = e.target.closest("[data-type]");
    if (!btn || btn.disabled) return;
    chosen = btn.dataset.type;
    renderTypes();
  });
  $("#channel-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = $("#channel-name").value.trim();
    const error = $("#channel-error");
    if (!name) return (error.textContent = "Give the destination a name.");
    const dest = chosen === "email" ? { recipients: $("#channel-recipients").value } : { [chosen === "sentinel" ? "dce_url" : "url"]: $("#channel-url").value.trim() };
    if (!(dest.url || dest.dce_url || dest.recipients)) return (error.textContent = chosen === "email" ? "Add at least one recipient." : "Paste the URL.");
    for (const [key, label, o] of TYPES[chosen].fields || []) {
      const value = $(`#ch-${key}`).value.trim();
      if (!value && !o.optional) return (error.textContent = `Enter the ${label.toLowerCase()}.`);
      if (value) dest[key] = value;
    }
    const submit = $("#channel-submit");
    submit.disabled = true;
    try {
      const created = await api.post("/api/notifications/channels", { name, type: chosen, min_severity: $("#channel-severity").value, destination: dest });
      closeModal("channel-modal");
      toast(`“${created.name}” added — send a test to check ${created.integration ? "the connection" : "it"}`, "success", 5000);
      if (created.signing_secret) showSecret(created.signing_secret);
      await onChange();
    } catch (err) {
      error.textContent = err.message;
    } finally {
      submit.disabled = false;
    }
  });
}
