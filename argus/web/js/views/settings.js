// Settings: appearance, account and (for admins) API keys, audit log and plugins.

import { api, enc, request } from "../api.js";
import { empty, ico } from "../components.js";
import { $, confirmDialog, copyText, formatDate, html, on, openModal, setHTML, timeAgo, toast } from "../dom.js";
import { emit, on as onState, state } from "../state.js";
import { verifyFile } from "./reports.js";

let pendingLogo; // undefined = keep, "" = remove, "data:..." = replace
let logoUrl = null;

let root;
const checks = {}; // route name -> result of its last test
let data = { keys: null, audit: null, plugins: null, health: null, verify: null, users: null, members: null };

const VAULT_FORMS = {
  "vault-enable-form": async () => {
    if ($("#vault-new").value !== $("#vault-new2").value) throw new Error("The two passphrases don't match");
    const r = await api.post("/api/vault/enable", { passphrase: $("#vault-new").value, understood: $("#vault-understood").checked });
    recoveryCode = r.recovery_code;
    $("#btn-vault-lock").hidden = false;
    toast("The vault is on: your cases are encrypted", "success", 6000);
  },
  "vault-pass-form": async () => {
    await api.post("/api/vault/passphrase", { current: $("#vault-current").value, new: $("#vault-next").value });
    toast("Passphrase changed", "success");
  },
  "vault-code-form": async () => {
    recoveryCode = (await api.post("/api/vault/recovery-code", { passphrase: $("#vault-code-pass").value })).recovery_code;
  },
  "vault-off-form": async () => {
    if (!(await confirmDialog({ title: "Turn the vault off?", message: "Everything will be decrypted and stored readable on this computer again.", confirm: "Decrypt and turn off", danger: true }))) return;
    await api.post("/api/vault/disable", { passphrase: $("#vault-off-pass").value });
    $("#btn-vault-lock").hidden = true;
    toast("The vault is off", "success");
  },
};

export function initSettings(el) {
  root = el;
  root.addEventListener("submit", async (e) => {
    const handler = VAULT_FORMS[e.target.id];
    if (!handler) return;
    e.preventDefault();
    const error = e.target.querySelector(".error-text");
    const button = e.target.querySelector("button[type=submit]");
    error.textContent = "";
    button.disabled = true;
    try {
      await handler();
      data.vault = await api.get("/api/vault/status").catch(() => data.vault);
      render();
    } catch (err) {
      error.textContent = err.message;
    } finally {
      button.disabled = false;
    }
  });
  onState("workspace", () => { data = { ...data, keys: null, audit: null, members: null }; refresh(); });
  on(root, "click", "[data-copy]", (_e, btn) => copyText(btn.dataset.copy));
  on(root, "click", "[data-goto]", (e, el2) => { e.preventDefault(); document.querySelector(`.nav-item[data-view="${el2.dataset.goto}"]`)?.click(); });
  on(root, "click", "[data-theme-choice]", (_e, btn) => { window.argusTheme.set(btn.dataset.themeChoice); render(); });
  on(root, "click", "[data-act]", async (_e, btn) => {
    const { act, id } = btn.dataset;
    try {
      if (act === "vault-code-saved") { recoveryCode = null; render(); return; }
      if (act === "vault-lock") {
        await api.post("/api/vault/lock");
        window.dispatchEvent(new CustomEvent("argus:vault-locked"));
        return;
      }
      if (act === "licence-check") {
        data.personal = await api.post("/api/personal/refresh");
        toast(data.personal.access === "full" ? "Your subscription is active" : data.personal.reason, data.personal.access === "full" ? "success" : "error", 6000);
        render();
        return;
      }
      if (act === "route-check") {
        btn.disabled = true;
        btn.textContent = "Testing…";
        try {
          checks[id] = await api.post(`/api/opsec/routes/${enc(id)}/check`);
        } finally {
          btn.disabled = false;
        }
        render();
        return;
      }
      if (act === "brand-logo-remove") {
        pendingLogo = "";
        setHTML($("#brand-logo-preview"), html`<span class="muted small">Logo will be removed when you save</span>`);
        return;
      }
      if (act === "member-remove") {
        if (!(await confirmDialog({ title: "Remove from this workspace?", message: "They lose access to its investigations immediately.", confirm: "Remove", danger: true }))) return;
        await api.del(`/api/workspaces/${enc(state.workspace.id)}/members/${enc(id)}`);
        toast("Member removed", "success");
      } else if (act === "ws-delete") {
        if (!(await confirmDialog({ title: "Delete this workspace?", message: "Only empty workspaces can be deleted.", confirm: "Delete", danger: true }))) return;
        await api.del(`/api/workspaces/${enc(id)}`);
        toast("Workspace deleted", "success");
        emit("workspaces-changed");
      } else if (act === "user-toggle") {
        const disabling = btn.dataset.disabled !== "true";
        if (disabling && !(await confirmDialog({ title: "Disable this user?", message: "They are signed out everywhere immediately and cannot sign in again until re-enabled.", confirm: "Disable", danger: true }))) return;
        await api.patch(`/api/users/${enc(id)}`, { disabled: disabling });
        toast(disabling ? "User disabled and signed out" : "User re-enabled", "success");
      } else if (act === "revoke") {
        const ok = await confirmDialog({ title: "Revoke this API key?", message: "Anything using it will lose access immediately.", confirm: "Revoke", danger: true });
        if (!ok) return;
        await api.del(`/api/keys/${enc(id)}`);
        toast("Key revoked", "success");
      } else if (act === "verify") {
        data.verify = await api.get("/api/audit/verify");
        toast(data.verify.valid ? `Audit log intact — ${data.verify.checked} entries verified` : "Audit log has been tampered with!", data.verify.valid ? "success" : "error", 6000);
        render();
        return;
      }
      await refresh();
    } catch (err) {
      toast(err.message, "error");
    }
  });
  root.addEventListener("change", async (e) => {
    if (e.target.matches("[data-member-role]")) {
      try {
        await api.put(`/api/workspaces/${enc(state.workspace.id)}/members/${enc(e.target.dataset.memberRole)}`, { role: e.target.value });
        toast("Role updated", "success");
      } catch (err) { toast(err.message, "error"); }
      await refresh();
      return;
    }
    if (!e.target.matches("[data-user-role]")) return;
    try {
      await api.patch(`/api/users/${enc(e.target.dataset.userRole)}`, { role: e.target.value });
      toast("Role updated", "success");
      await refresh();
    } catch (err) {
      toast(err.message, "error");
      await refresh();
    }
  });
  root.addEventListener("change", async (e) => {
    if (e.target.id === "brand-logo-file") {
      const file = e.target.files[0];
      if (!file) return;
      if (file.size > 1_000_000) return toast("The logo must be smaller than 1 MB", "error");
      pendingLogo = await new Promise((resolve) => { const r = new FileReader(); r.onload = () => resolve(r.result); r.readAsDataURL(file); });
      setHTML($("#brand-logo-preview"), html`<img src="${pendingLogo}" alt="New logo preview">`);
    } else if (e.target.id === "brand-accent-picker") {
      $("#brand-accent").value = e.target.value;
    } else if (e.target.id === "verify-file") {
      const file = e.target.files[0];
      if (!file) return;
      const out = $("#verify-result");
      setHTML(out, html`<p class="muted small">Checking ${file.name}…</p>`);
      try {
        const { sha, ok, body } = await verifyFile(file);
        setHTML(out, ok
          ? html`<div class="verify ok">${ico("check")}<div><b>Genuine and unmodified.</b> Report ${body.report_id}, issued by ${body.issued_by} on ${formatDate(body.issued_at)} for ${body.target}${body.prepared_for ? html` (prepared for ${body.prepared_for})` : ""} · ${body.classification}</div></div>`
          : html`<div class="verify bad">${ico("alert")}<div><b>Not verified.</b> ${body.detail || "No report with this fingerprint was issued here."}<div class="muted small mono">SHA-256 ${sha}</div></div></div>`);
      } catch (err) {
        setHTML(out, html`<p class="error-text">${err.message}</p>`);
      }
      e.target.value = "";
    }
  });
  root.addEventListener("submit", async (e) => {
    if (e.target.id === "brand-form") {
      e.preventDefault();
      try {
        const body = { organisation: $("#brand-org").value.trim(), accent: $("#brand-accent").value.trim(), footer_note: $("#brand-footer").value.trim() };
        if (pendingLogo !== undefined) body.logo = pendingLogo;
        await api.put("/api/reports/branding", body);
        pendingLogo = undefined;
        toast("Report branding saved", "success");
        data.branding = null;
        await refresh();
      } catch (err) { toast(err.message, "error"); }
      return;
    }
    if (e.target.id === "member-form" || e.target.id === "ws-form") {
      e.preventDefault();
      try {
        if (e.target.id === "member-form") {
          await api.post(`/api/workspaces/${enc(state.workspace.id)}/members`, { email: $("#member-email").value.trim(), role: $("#member-role").value });
          toast("Member added", "success");
        } else {
          const ws = await api.post("/api/workspaces", { name: $("#ws-name").value.trim() });
          toast(`Workspace “${ws.name}” created — switch to it from the top bar`, "success", 5000);
          emit("workspaces-changed");
        }
        await refresh();
      } catch (err) { toast(err.message, "error"); }
      return;
    }
    if (e.target.id !== "key-form") return;
    e.preventDefault();
    const name = $("#key-name").value.trim();
    const role = $("#key-role").value;
    const platform = $("#key-platform")?.checked || false;
    if (!name) return toast("Give the key a name", "error");
    try {
      const created = await api.post("/api/keys", { name, role: platform ? "admin" : role, platform });
      $("#key-value").textContent = created.key;
      $("#key-copy").onclick = () => copyText(created.key);
      openModal("key-modal");
      await refresh();
    } catch (err) {
      toast(err.message, "error");
    }
  });
}

export async function refresh() {
  const wsAdmin = state.workspace?.role === "admin";
  const platform = !!state.me?.platform_admin;
  const ws = state.workspace ? enc(state.workspace.id) : "";
  const tasks = [
    api.get("/api/health").catch(() => null),
    wsAdmin ? api.get("/api/keys").catch(() => null) : null,
    wsAdmin ? api.get("/api/audit?limit=50").catch(() => null) : null,
    platform ? api.get("/api/plugins").catch(() => null) : null,
    platform ? api.get("/api/users").catch(() => null) : null,
    wsAdmin && ws ? api.get(`/api/workspaces/${ws}/members`).catch(() => null) : null,
    wsAdmin ? api.get("/api/reports/branding").catch(() => null) : null,
    api.get("/api/opsec/routes").catch(() => null),
    fetch("/api/personal/status").then((r) => (r.ok ? r.json() : null)).catch(() => null),
    platform ? api.get("/api/vault/status").catch(() => null) : null,
  ];
  const [health, keys, audit, plugins, users, members, branding, opsec, personal, vault] = await Promise.all(tasks);
  const credits = personal?.signed_in ? await api.get("/api/personal/credits").catch(() => null) : null;
  data = { ...data, health, keys, audit, plugins, users, members, branding, opsec, personal, credits, vault };
  if (logoUrl) URL.revokeObjectURL(logoUrl);
  logoUrl = null;
  if (branding?.has_logo) {
    try { logoUrl = URL.createObjectURL(await (await request("/api/reports/branding/logo", { raw: true })).blob()); } catch { /* no preview */ }
  }
  render();
}

function themeChooser() {
  const choice = window.argusTheme.choice();
  return html`<div class="segmented">${[["light", "Light"], ["dark", "Dark"], ["system", "System"]].map(([v, l]) =>
    html`<button class="${choice === v ? "active" : ""}" data-theme-choice="${v}">${l}</button>`)}</div>`;
}

function keysCard() {
  return html`<div class="card card-pad" style="margin-top:16px">
    <div class="card-head"><div><h2>API keys</h2><p class="muted small">Keys are stored only as SHA-256 hashes. Viewer: read · Analyst: + scan · Admin: + delete, keys, audit.</p></div></div>
    <p class="muted small" style="margin:-6px 0 12px">New keys are bound to <b>${state.workspace?.name || "this workspace"}</b> and cannot see any other workspace.</p>
    <form id="key-form" class="filters" style="margin-bottom:12px">
      <input id="key-name" class="input" placeholder="Key name, e.g. alice-laptop" maxlength="128" style="max-width:260px">
      <select id="key-role" class="select" style="max-width:150px"><option value="viewer">Viewer</option><option value="analyst" selected>Analyst</option><option value="admin">Admin</option></select>
      ${state.me?.platform_admin ? html`<label class="check small"><input type="checkbox" id="key-platform"> Platform-wide admin key</label>` : ""}
      <button class="btn primary" type="submit">${ico("plus")}Create key</button>
    </form>
    ${data.keys ? html`<table class="table"><thead><tr><th>Name</th><th>Role</th><th>Key</th><th>Last used</th><th>Created</th><th></th></tr></thead><tbody>
      ${data.keys.map((k) => html`<tr style="${k.revoked ? "opacity:.5" : ""}">
        <td><b>${k.name}</b>${k.id === state.me?.key_id ? html` <span class="pill accent">you</span>` : ""}</td>
        <td>${k.role}</td><td class="mono">${k.prefix}…</td>
        <td>${k.last_used_at ? timeAgo(k.last_used_at) : "never"}</td>
        <td>${formatDate(k.created_at)}</td>
        <td class="actions">${k.revoked ? html`<span class="pill">revoked</span>` : html`<button class="btn sm ghost danger" data-act="revoke" data-id="${k.id}">Revoke</button>`}</td>
      </tr>`)}</tbody></table>` : html`<p class="muted">Loading…</p>`}
  </div>`;
}

function snippet(text, label) {
  return html`<div class="snippet"><pre class="mono">${text}</pre>
    <button class="btn sm ghost" data-copy="${text}" aria-label="Copy ${label}">${ico("copy")}Copy</button></div>`;
}

function apiCard() {
  const base = location.origin;
  const ws = state.workspace?.slug || "default";
  const curl = `curl -H "Authorization: Bearer $ARGUS_API_KEY" \\
     -H "X-Argus-Workspace: ${ws}" \\
     ${base}/api/ratings`;
  const python = `import os
from argus_client import ArgusClient

argus = ArgusClient(
    "${base}",
    api_key=os.environ["ARGUS_API_KEY"],
    workspace="${ws}",
)
scan = argus.scan("example.com", purpose="Authorised test, SEC-42")
done = argus.wait(scan["investigation_id"])
print(argus.rating(done["id"])["grade"])`;
  return html`<div class="card card-pad" style="margin-top:16px" id="api-card">
    <div class="card-head wrap"><div><h2>API &amp; integrations</h2><p class="muted small">Everything in Argus is available through a documented REST API. Use an API key (below) and name the workspace with the <code>X-Argus-Workspace</code> header.</p></div>
      <div class="page-actions"><a class="btn sm" href="/docs" target="_blank" rel="noopener">${ico("external")}Interactive reference</a><a class="btn sm ghost" href="/openapi.json" target="_blank" rel="noopener">OpenAPI 3.1</a></div></div>
    <dl class="kv" style="margin-bottom:12px"><dt>Base URL</dt><dd class="mono">${base}</dd><dt>Workspace</dt><dd class="mono">${ws}</dd>
      <dt>Rate limit</dt><dd>A per-minute budget for each key; every response reports it in <code>RateLimit-*</code> headers</dd></dl>
    <div class="grid two" style="align-items:start">
      <div><div class="section-title">curl</div>${snippet(curl, "the curl example")}</div>
      <div><div class="section-title">Python (clients/python)</div>${snippet(python, "the Python example")}</div>
    </div>
    <p class="muted small" style="margin-top:12px">${ico("info")} To open Jira issues or ServiceNow incidents for alerts, or stream events to Splunk or Microsoft Sentinel, add them as destinations under <a href="#" data-goto="monitoring">Monitoring → Notifications</a>.</p>
  </div>`;
}

function checkResult(c) {
  if (!c) return "";
  if (!c.working) return html`<div class="callout warn" style="margin-top:6px">${ico("alert")}<span>${c.error}</span></div>`;
  const facts = html`Sites see <b class="mono">${c.exit_ip}</b>${c.direct_ip ? html` instead of this server's <span class="mono">${c.direct_ip}</span>` : ""}${c.is_tor === true ? " · confirmed Tor exit" : ""}`;
  return c.error ? html`<div class="callout warn" style="margin-top:6px">${ico("alert")}<span>${c.error}. ${facts}</span></div>`
    : html`<div class="callout safe" style="margin-top:6px">${ico("check")}<span>Working and hiding this server. ${facts}</span></div>`;
}

function safetyCard() {
  const o = data.opsec;
  if (!o) return "";
  const canTest = ["analyst", "admin"].includes(state.workspace?.role);
  const kind = { tor: "Tor", proxy: "Proxy / VPN" };
  return html`<div class="card card-pad" style="margin-top:16px" id="safety-card">
    <div class="card-head"><div><h2>Investigator safety</h2><p class="muted small">The people you investigate can see every visit in their logs. Routes send captures and scans through Tor, a VPN or a proxy so they never see this server's address. Choose a route per case (or per capture and scan); make a case <b>anonymous</b> so nothing in it touches its subjects directly.</p></div></div>
    ${o.routes.length ? html`<div class="list">${o.routes.map((r) => html`<div class="list-row" style="flex-wrap:wrap">
        <span class="pill ${r.anonymous ? "ok" : ""}">${kind[r.kind] || r.kind}</span>
        <div class="list-main"><div class="list-title">${r.name}${r.anonymous ? " · anonymous" : ""}</div><div class="list-sub">${r.description || (r.kind === "tor" ? "The Tor network: sites see a Tor exit, and neither they nor the exit learn who you are" : "A proxy or VPN: sites see its address; whoever runs it can see what is visited")}</div>
          ${checkResult(checks[r.name])}</div>
        ${canTest ? html`<button class="btn sm" data-act="route-check" data-id="${r.name}">${ico("check")}Test</button>` : ""}</div>`)}</div>
      <p class="muted small" style="margin-top:10px">${ico("info")} Test asks <span class="mono">${o.check_url}</span> who is calling, through the route and directly, and warns if the route leaks this server's address.</p>`
    : html`<p class="muted small">No routes are set up, so captures and scans connect directly. An administrator can add Tor or a VPN with <code>ARGUS_EGRESS_ROUTES</code> (see the deployment guide).</p>`}
    <p class="muted small" style="margin-top:8px">Captures and routed scans always present an ordinary browser (Chrome on Windows, US English, UTC), never "Argus".</p>
  </div>`;
}

function brandingCard() {
  const b = data.branding;
  if (!b) return "";
  return html`<div class="card card-pad" style="margin-top:16px">
    <div class="card-head"><div><h2>Report branding</h2><p class="muted small">How this workspace's PDF reports look to clients. Logos are re-encoded on upload (PNG or JPEG, up to 1 MB) so no hidden metadata reaches a report.</p></div></div>
    <form id="brand-form" class="brand-form">
      <div class="field"><label class="label" for="brand-org">Organisation (shown as “Prepared by”)</label>
        <input id="brand-org" class="input" maxlength="128" value="${b.organisation}" required></div>
      <div class="field"><label class="label" for="brand-accent">Accent colour</label>
        <div style="display:flex;gap:8px;align-items:center"><input type="color" id="brand-accent-picker" value="${b.accent}" aria-label="Pick accent colour" style="width:42px;height:34px;border:0;background:none">
        <input id="brand-accent" class="input mono" value="${b.accent}" pattern="#[0-9a-fA-F]{6}" style="max-width:120px"></div></div>
      <div class="field"><label class="label" for="brand-footer">Footer note (optional)</label>
        <input id="brand-footer" class="input" maxlength="200" value="${b.footer_note}" placeholder="e.g. Confidential — Northwind Security Ltd"></div>
      <div class="field"><span class="label">Logo</span>
        <div class="brand-logo"><div id="brand-logo-preview">${logoUrl ? html`<img src="${logoUrl}" alt="Current logo">` : html`<span class="muted small">No logo</span>`}</div>
          <label class="btn sm">${ico("plus")}Choose image<input type="file" id="brand-logo-file" accept="image/png,image/jpeg" hidden></label>
          ${b.has_logo ? html`<button type="button" class="btn sm ghost danger" data-act="brand-logo-remove">Remove</button>` : ""}</div></div>
      <div><button class="btn primary" type="submit">Save branding</button>
        ${b.updated_by ? html`<span class="muted small" style="margin-left:8px">Last changed by ${b.updated_by} ${timeAgo(b.updated_at)}</span>` : ""}</div>
    </form>
  </div>`;
}

function verifyCard() {
  return html`<div class="card card-pad" style="margin-top:16px">
    <div class="card-head"><div><h2>Verify a report</h2><p class="muted small">Check that a PDF really was issued by this Argus and has not been altered. The file never leaves your browser: only its SHA-256 fingerprint is looked up. Recipients without an account can do the same with <code>sha256sum</code> and <code>/api/reports/verify/&lt;fingerprint&gt;</code>.</p></div>
      <label class="btn">${ico("shield")}Choose PDF<input type="file" id="verify-file" accept="application/pdf" hidden></label></div>
    <div id="verify-result"></div>
  </div>`;
}

let recoveryCode = null; // shown once, right after it is created

function vaultCard() {
  const v = data.vault;
  if (!v) return "";
  const codeBlock = recoveryCode ? html`<div class="callout warn" style="margin:12px 0;display:block">
      <b>Your recovery code. Write it down and keep it somewhere safe, away from this computer.</b>
      <div class="key-reveal" style="margin:10px 0"><span class="mono">${recoveryCode}</span></div>
      <p class="small">It opens the vault if you forget your passphrase. It is shown only now. If you lose both, nobody can recover your cases: not you, not us.</p>
      <button class="btn sm" data-copy="${recoveryCode}">${ico("copy")}Copy</button> <button class="btn sm primary" data-act="vault-code-saved">I've saved it</button></div>` : "";
  if (!v.available) {
    return html`<div class="card card-pad" style="margin-top:16px"><div class="card-head"><h2>${ico("shield")}Case vault</h2></div>
      <p class="muted small">The case vault encrypts cases on one computer's own database (Argus Personal). This installation uses a shared database server; protect it with the server's own encryption at rest.</p></div>`;
  }
  if (!v.enabled) {
    return html`<div class="card card-pad" style="margin-top:16px"><div class="card-head"><h2>${ico("shield")}Case vault</h2><span class="pill">Off</span></div>
      <p>Encrypt your cases, evidence and scan results on this computer with a passphrase. If this computer is lost, stolen or seized, they can't be read without it.</p>
      <form id="vault-enable-form" style="display:grid;gap:8px;max-width:440px">
        <label class="label" for="vault-new">Passphrase <span class="muted small">at least 12 characters; a short sentence works well</span></label>
        <input class="input" type="password" id="vault-new" autocomplete="new-password" minlength="12" maxlength="1024" required>
        <label class="label" for="vault-new2">Type it again</label>
        <input class="input" type="password" id="vault-new2" autocomplete="new-password" maxlength="1024" required>
        <label class="small"><input type="checkbox" id="vault-understood" required> I understand: if I lose both this passphrase and the recovery code I'm given next, my cases can't be recovered by anyone.</label>
        <p class="error-text"></p>
        <div><button class="btn primary" type="submit">${ico("shield")}Turn on the vault</button></div>
      </form>
      <p class="muted small" style="margin-top:8px">For the strongest protection, also turn on your computer's own disk encryption (FileVault, BitLocker or LUKS).</p></div>`;
  }
  return html`<div class="card card-pad" style="margin-top:16px"><div class="card-head"><h2>${ico("shield")}Case vault</h2><span class="pill ok">On</span></div>
    ${codeBlock}
    <p>Your cases, evidence and scan results are encrypted on this computer. ${v.idle_minutes ? `The vault locks itself after ${v.idle_minutes} minutes without activity (never during a scan).` : "It locks only when you lock it."}</p>
    <button class="btn sm" data-act="vault-lock">${ico("shield")}Lock now</button>
    <details style="margin-top:12px"><summary>Change the passphrase</summary>
      <form id="vault-pass-form" style="display:grid;gap:8px;max-width:440px;margin-top:8px">
        <input class="input" type="password" id="vault-current" placeholder="Current passphrase" autocomplete="current-password" required>
        <input class="input" type="password" id="vault-next" placeholder="New passphrase (12+ characters)" autocomplete="new-password" minlength="12" required>
        <p class="error-text"></p><div><button class="btn sm" type="submit">Change passphrase</button></div></form></details>
    <details style="margin-top:8px"><summary>Get a new recovery code</summary>
      <form id="vault-code-form" style="display:grid;gap:8px;max-width:440px;margin-top:8px">
        <p class="muted small">The old code stops working.</p>
        <input class="input" type="password" id="vault-code-pass" placeholder="Passphrase" autocomplete="current-password" required>
        <p class="error-text"></p><div><button class="btn sm" type="submit">New recovery code</button></div></form></details>
    <details style="margin-top:8px"><summary>Turn the vault off</summary>
      <form id="vault-off-form" style="display:grid;gap:8px;max-width:440px;margin-top:8px">
        <p class="muted small">Everything is decrypted and stored readable on this computer again.</p>
        <input class="input" type="password" id="vault-off-pass" placeholder="Passphrase" autocomplete="current-password" required>
        <p class="error-text"></p><div><button class="btn sm danger" type="submit">Decrypt and turn off</button></div></form></details>
  </div>`;
}

function subscriptionCard() {
  const p = data.personal;
  if (!p) return "";
  const status = { trialing: ["accent", "In trial"], active: ["ok", "Active"], past_due: ["warn", "Payment due"], cancelled: ["critical", "Cancelled"], suspended: ["critical", "Suspended"] }[p.status] || ["", p.status || "—"];
  return html`<div class="card card-pad" style="margin-top:16px" id="subscription-card">
    <div class="card-head wrap"><div><h2>Your Argus subscription</h2><p class="muted small">Argus Personal keeps your cases on this computer; your account unlocks it. The account service only learns that this computer signed in, never anything about your cases.</p></div>
      <span style="display:flex;gap:6px"><button class="btn sm" data-act="licence-check">${ico("check")}Check now</button></span></div>
    ${p.access !== "full" ? html`<div class="callout warn" style="margin-bottom:12px">${ico("alert")}<span>${p.reason}</span></div>` : ""}
    <dl class="kv"><dt>Account</dt><dd>${p.account?.email || "—"}</dd><dt>Plan</dt><dd>${p.plan_label || "—"} <span class="pill ${status[0]}">${status[1]}</span></dd>
      <dt>${p.status === "trialing" ? "Trial ends" : "Paid until"}</dt><dd>${p.valid_until ? formatDate(p.valid_until) : "—"}</dd>
      <dt>Last renewed</dt><dd>${p.renewed_at ? timeAgo(p.renewed_at) : "—"}${p.renewal_problem ? html` <span class="muted small">(${p.renewal_problem})</span>` : ""}</dd>
      <dt>Works offline until</dt><dd>${p.offline_until ? formatDate(p.offline_until) : "—"}</dd>
      <dt>Account service</dt><dd class="mono small">${p.account_service || "not configured"}</dd></dl>
    ${data.credits ? html`<div class="section-title" style="margin-top:14px">Argus credits</div>
      <p class="muted small">Premium sources (such as UK Companies House) are included through Argus Connect: no accounts or API keys of your own needed. Each lookup uses credits; this month's allowance renews on the 1st, and purchased credits never expire.</p>
      <dl class="kv"><dt>Available</dt><dd><b>${data.credits.credits.available}</b> credits</dd><dt>This month</dt><dd>${data.credits.credits.allowance_remaining} of ${data.credits.credits.allowance} left</dd><dt>Purchased</dt><dd>${data.credits.credits.purchased}</dd>
        ${Object.values(data.credits.prices).map((p) => { const costs = Object.entries(p.lookups); const same = costs.every(([, c]) => c === costs[0][1]);
          return html`<dt>${p.label}</dt><dd>${same ? `${costs[0][1]} credit${costs[0][1] === 1 ? "" : "s"} per lookup` : costs.map(([n, c]) => `${n.replace(/_/g, " ")} ${c}`).join(" · ")}</dd>`; })}</dl>
      <p class="muted small" style="margin-top:6px">A brokered lookup tells the Argus account service what was looked up (a company number or name). The AI analyst sends the case material you confirm through it to Anthropic; the service keeps none of it. To keep even that private, set your own key for the source (or your own Claude API key); requests then go directly and cost no credits.</p>` : ""}
    <p class="muted small" style="margin-top:10px">If a subscription ends, nothing is lost: your cases stay readable, verifiable and exportable, and only new work waits until it is renewed.</p>
  </div>`;
}

function workspacesCard() {
  const current = state.workspace;
  const platform = !!state.me?.platform_admin;
  const members = data.members;
  return html`<div class="card card-pad" style="margin-top:16px">
    <div class="card-head"><div><h2>Workspace: ${current?.name || "—"}</h2>
      <p class="muted small">Each team works in its own workspace: investigations, monitors, alerts, API keys and audit entries are never visible to other workspaces. Your role here: <b>${current?.role || "—"}</b>.</p></div></div>
    ${members ? html`
      <form id="member-form" class="filters" style="margin-bottom:12px">
        <input id="member-email" class="input" type="email" placeholder="colleague@company.com (signed in once with SSO)" style="max-width:320px" required>
        <select id="member-role" class="select" style="max-width:150px"><option value="viewer">Viewer</option><option value="analyst" selected>Analyst</option><option value="admin">Admin</option></select>
        <button class="btn primary" type="submit">${ico("plus")}Add member</button>
      </form>
      ${members.length ? html`<table class="table"><thead><tr><th>Member</th><th>Role</th><th>Added</th><th></th></tr></thead><tbody>
        ${members.map((m) => {
          const self = state.me?.key_id === `user:${m.user_id}`;
          return html`<tr style="${m.disabled ? "opacity:.55" : ""}"><td><b>${m.name || m.email}</b> <span class="muted">${m.email || ""}</span>${self ? html` <span class="pill accent">you</span>` : ""}</td>
            <td><select class="select sm" data-member-role="${m.user_id}" ${self ? "disabled" : ""} aria-label="Role for ${m.email}">${["viewer", "analyst", "admin"].map((r) => html`<option value="${r}" ${m.role === r ? "selected" : ""}>${r[0].toUpperCase() + r.slice(1)}</option>`)}</select></td>
            <td>${m.added_at ? timeAgo(m.added_at) : "—"}</td>
            <td class="actions">${self ? "" : html`<button class="btn sm ghost danger" data-act="member-remove" data-id="${m.user_id}">Remove</button>`}</td></tr>`;
        })}</tbody></table>` : html`<p class="muted small">No people yet — API keys bound to this workspace can still use it.</p>`}` : ""}
    ${platform ? html`<div class="section"><div class="section-title">All workspaces (platform administration)</div>
      <form id="ws-form" class="filters" style="margin-bottom:10px">
        <input id="ws-name" class="input" placeholder="New workspace, e.g. Red Team" maxlength="128" style="max-width:260px" required>
        <button class="btn" type="submit">${ico("plus")}Create workspace</button>
      </form>
      <div class="chips">${(state.me.workspaces || []).map((w) => html`<span class="chip">${w.name}${w.default ? "" : html` <button class="btn sm ghost danger" style="height:20px;padding:0 6px" data-act="ws-delete" data-id="${w.id}" title="Delete (only if empty)">×</button>`}</span>`)}</div>
    </div>` : ""}
  </div>`;
}

function usersCard() {
  const users = data.users;
  if (!users?.length) return "";
  return html`<div class="card card-pad" style="margin-top:16px">
    <div class="card-head"><div><h2>People with access</h2><p class="muted small">Accounts created by single sign-on. Disabling someone signs them out everywhere at once. If roles come from your identity provider's groups, changes here last until their next sign-in.</p></div></div>
    <table class="table"><thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Last sign-in</th><th></th></tr></thead><tbody>
      ${users.map((u) => {
        const self = state.me?.key_id === `user:${u.id}`;
        return html`<tr style="${u.disabled ? "opacity:.55" : ""}">
          <td><b>${u.name || "—"}</b>${self ? html` <span class="pill accent">you</span>` : ""}</td>
          <td>${u.email || u.subject}</td>
          <td><select class="select sm" data-user-role="${u.id}" ${self ? "disabled" : ""} aria-label="Role for ${u.email || u.id}">
            ${["viewer", "analyst", "admin"].map((r) => html`<option value="${r}" ${u.role === r ? "selected" : ""}>${r[0].toUpperCase() + r.slice(1)}</option>`)}
          </select></td>
          <td>${u.last_login_at ? timeAgo(u.last_login_at) : "never"}</td>
          <td class="actions">${self ? "" : html`<button class="btn sm ghost ${u.disabled ? "" : "danger"}" data-act="user-toggle" data-id="${u.id}" data-disabled="${u.disabled}">${u.disabled ? "Enable" : "Disable"}</button>`}</td>
        </tr>`;
      })}
    </tbody></table>
  </div>`;
}

function auditCard() {
  const v = data.verify;
  return html`<div class="card card-pad" style="margin-top:16px">
    <div class="card-head">
      <div><h2>Audit log</h2><p class="muted small">Every scan, export, deletion and access decision. Each entry is hash-chained to the previous one, so edits are detectable.</p></div>
      <button class="btn" data-act="verify">${ico("shield")}Verify integrity</button>
    </div>
    ${v ? html`<div class="callout" style="margin-bottom:12px">${v.valid ? html`<span class="pill ok">Intact</span> All ${v.checked} entries verified — no tampering detected.`
      : html`<span class="pill critical">Tampered</span> Entry #${v.first_invalid_id} does not match the chain.`}</div>` : ""}
    ${data.audit ? data.audit.length ? html`<table class="table"><thead><tr><th>When</th><th>Who</th><th>Action</th><th>Resource</th><th>Outcome</th></tr></thead><tbody>
      ${data.audit.map((e) => html`<tr>
        <td title="${e.ts}">${timeAgo(e.ts)}</td><td>${e.actor_name}</td><td class="mono">${e.action}</td>
        <td class="mono" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${e.resource || "—"}</td>
        <td><span class="pill ${e.outcome === "success" ? "ok" : "critical"}">${e.outcome}</span></td></tr>`)}
      </tbody></table>` : html`<p class="muted">No events yet.</p>` : html`<p class="muted">Loading…</p>`}
  </div>`;
}

function pluginsCard() {
  const p = data.plugins;
  if (!p) return "";
  const loaded = Object.entries(p.loaded);
  const errors = Object.entries(p.errors);
  return html`<div class="card card-pad" style="margin-top:16px">
    <div class="card-head"><div><h2>Plugins</h2><p class="muted small">Third-party collectors load only when allowlisted in <code>ARGUS_PLUGINS</code>.</p></div></div>
    ${!loaded.length && !errors.length && !p.available.length ? html`<p class="muted small">No plugins installed.</p>` : html`<div class="list">
      ${loaded.map(([name, src]) => html`<div class="list-row"><span class="pill ok">loaded</span><div class="list-main"><div class="list-title">${name}</div><div class="list-sub mono">${src}</div></div></div>`)}
      ${errors.map(([name, why]) => html`<div class="list-row"><span class="pill critical">rejected</span><div class="list-main"><div class="list-title">${name}</div><div class="list-sub">${why}</div></div></div>`)}
      ${p.available.map((name) => html`<div class="list-row"><span class="pill">installed</span><div class="list-main"><div class="list-title">${name}</div><div class="list-sub">Not allowlisted</div></div></div>`)}
    </div>`}
  </div>`;
}

function render() {
  if (!root) return;
  const admin = state.workspace?.role === "admin";
  const platform = !!state.me?.platform_admin;
  const h = data.health;
  setHTML(root, html`<div class="page" style="max-width:1040px">
    <div class="page-head"><div><h1>Settings</h1><p>Appearance, access and accountability.</p></div></div>
    <div class="grid two">
      <div class="card card-pad"><div class="card-head"><h2>Appearance</h2></div>
        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px"><span>Theme</span>${themeChooser()}</div>
        <p class="muted small" style="margin-top:10px">“System” follows your device's light / dark setting. Shortcut: <span class="kbd">T</span></p>
      </div>
      <div class="card card-pad"><div class="card-head"><h2>Your access</h2></div>
        <dl class="kv"><dt>Signed in as</dt><dd>${state.me?.name || "—"}</dd><dt>Role</dt><dd>${state.me?.role || "—"}</dd>
          <dt>Method</dt><dd>${state.me?.auth === "session" ? "Single sign-on" : "API key"}</dd>
          <dt>Version</dt><dd>${h ? `Argus ${h.version}` : "—"}</dd><dt>Database</dt><dd>${h ? `${h.database.backend} · ${h.database.reachable ? "reachable" : "unreachable"}` : "—"}</dd></dl>
      </div>
    </div>
    ${subscriptionCard()}
    ${vaultCard()}
    ${data.personal ? "" : workspacesCard()}
    ${safetyCard()}
    ${apiCard()}
    ${brandingCard()}
    ${verifyCard()}
    ${admin ? html`${platform ? usersCard() : ""}${keysCard()}${auditCard()}${platform ? pluginsCard() : ""}`
      : html`<div class="card" style="margin-top:16px">${empty("shield", "Administration", "API keys and the audit log are available to this workspace's administrators.")}</div>`}
  </div>`);
}
