// Settings: appearance, account and (for admins) API keys, audit log and plugins.

import { api, download, enc, request } from "../api.js";
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
  "own-key-form": async () => {
    const provider = $("#own-key-provider").value;
    data.ownKeys = await api.put(`/api/personal/keys/${enc(provider)}`, { key: $("#own-key-value").value.trim() });
    toast("Key saved: lookups with it go straight to the source and use no credits", "success", 5000);
  },
  "team-invite-form": async () => {
    const r = await api.post("/api/personal/team/add", { email: $("#team-invite-email").value.trim(), name: $("#team-invite-name").value.trim() });
    toast(r.detail, "success");
    data.team = await api.get("/api/personal/team").catch(() => data.team);
  },
  "backup-form": async () => {
    const password = $("#backup-pass").value;
    if (password !== $("#backup-pass2").value) throw new Error("The two passwords don't match");
    data.backups = await api.put("/api/backups", { enabled: true, folder: $("#backup-folder").value.trim(), every_hours: Number($("#backup-every").value),
      keep: Number($("#backup-keep").value), password: password || null });
    toast(data.backups.last_success_at ? "Backup settings saved" : "Backups are on: the first one runs within a few minutes", "success", 6000);
  },
  "backup-file-form": async (e) => {
    const body = { file: $("#backup-file").value.trim(), password: $("#backup-file-pass").value };
    if (e.submitter?.value !== "restore") {
      const r = await api.post("/api/backups/check", body);
      const counts = r.backup.counts || {};
      toast(`The backup is complete and readable: made ${formatDate(r.backup.created_at)}, ${counts.cases ?? 0} case(s), ${counts.evidence_captures ?? 0} evidence capture(s)`, "success", 9000);
      return;
    }
    if (!await confirmDialog({ title: "Restore this backup?", message: "Argus restarts with the data from the backup. What's on this computer now is kept in a 'before-restore' folder in Argus's data folder, not deleted.", confirm: "Restore and restart", danger: true })) return;
    const r = await api.post("/api/backups/restore", body);
    if (r.restarting) return waitForRestart(r.detail);
    toast(r.detail, "success", 10000);
  },
  "account-delete-form": async () => {
    await api.post("/api/personal/delete-account", { password: $("#account-delete-pass").value, confirm: $("#account-delete-confirm").value });
    toast("Your account is deleted. Your cases are still on this computer.", "success", 8000);
    setTimeout(() => location.reload(), 2500);
  },
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
  window.addEventListener("argus:billing-updated", () => refresh());
  root.addEventListener("submit", async (e) => {
    const handler = VAULT_FORMS[e.target.id];
    if (!handler) return;
    e.preventDefault();
    const error = e.target.querySelector(".error-text");
    const button = e.target.querySelector("button[type=submit]");
    error.textContent = "";
    button.disabled = true;
    try {
      await handler(e);
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
      if (act === "key-remove") {
        data.ownKeys = await api.del(`/api/personal/keys/${enc(id)}`);
        toast("Key removed: that source now uses credits", "success");
        render();
        return;
      }
      if (act === "team-signout") {
        if (!(await confirmDialog({ title: `Sign ${btn.dataset.email} out of every computer?`, message: "Use this for a lost or stolen laptop. Their cases stay on their computers; they can sign in again with their password.", confirm: "Sign out", danger: true }))) return;
        toast((await api.post("/api/personal/team/sign-out-member", { member_id: id })).detail, "success");
        return;
      }
      if (act === "team-remove" || act === "team-cancel" || act === "team-leave") {
        const leaving = act === "team-leave";
        const ok = act === "team-cancel" || await confirmDialog({
          title: leaving ? "Leave the team?" : `Remove ${btn.dataset.email} from your team?`,
          message: leaving ? "Your cases stay on this computer. You'll need your own plan to start new work." : "Their account and their cases are theirs and stay on their computer; they lose the team's plan and credits, and a seat is freed.",
          confirm: leaving ? "Leave" : "Remove", danger: true,
        });
        if (!ok) return;
        const r = act === "team-remove" ? await api.post("/api/personal/team/remove", { member_id: id })
          : act === "team-cancel" ? await api.post("/api/personal/team/cancel-invite", { email: btn.dataset.email })
            : await api.post("/api/personal/team/leave");
        toast(r.detail, "success");
        await refresh();
        return;
      }
      if (act === "buy" || act === "billing-portal") {
        btn.disabled = true;
        try {
          const seats = btn.dataset.item === "plan:business" ? Math.max(2, Math.min(100, Number($("#team-seats")?.value) || 2)) : undefined;
          const page = act === "buy" ? await api.post("/api/personal/billing/checkout", { item: btn.dataset.item, ...(seats ? { seats } : {}) })
            : await api.post("/api/personal/billing/portal");
          if (page.url?.startsWith("https://")) { location.assign(page.url); return; }
          toast("The payment page could not be opened", "error");
        } finally {
          btn.disabled = false;
        }
        return;
      }
      if (act === "account-data") {
        await download("/api/personal/account-data", "argus-account-data.json");
        return;
      }
      if (act === "account-delete-show") { $("#account-delete-form").hidden = false; $("#account-delete-pass").focus(); return; }
      if (act === "terms-review") { window.argusAskTerms?.(); return; }
      if (act === "backup-now") {
        btn.disabled = true;
        btn.textContent = "Backing up…";
        try {
          data.backups = await api.post("/api/backups/run");
          toast("Backup made", "success");
        } catch (err) {
          toast(err.message, "error", 8000);
          data.backups = await api.get("/api/backups").catch(() => data.backups);
        }
        render();
        return;
      }
      if (act === "backup-folder") { $("#backup-folder").value = btn.dataset.path; return; }
      if (act === "backup-pick") {
        $("#backup-file-details").open = true;
        $("#backup-file").value = btn.dataset.file;
        $("#backup-file-pass").focus();
        return;
      }
      if (act === "backup-restore-cancel") {
        data.backups = await api.post("/api/backups/restore/cancel");
        render();
        return;
      }
      if (act === "quit-argus") {
        if (!await confirmDialog({ title: "Quit Argus?", message: "Argus closes on this computer. Your cases stay saved; open Argus again from its icon whenever you need it.", confirm: "Quit Argus" })) return;
        const r = await api.post("/api/personal/quit");
        document.body.innerHTML = "";
        const note = document.createElement("p");
        note.style.cssText = "font:16px system-ui;margin:20vh auto;max-width:480px;text-align:center";
        note.textContent = r.detail;
        document.body.append(note);
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
      } else if (act === "key-rotate") {
        const ok = await confirmDialog({ title: "Rotate this API key?", message: "You get a new key with the same name, role and networks. The old one keeps working for 24 hours so you can switch whatever uses it.", confirm: "Rotate" });
        if (!ok) return;
        const created = await api.post(`/api/keys/${enc(id)}/rotate`, { overlap_hours: 24 });
        $("#key-value").textContent = created.key;
        $("#key-copy").onclick = () => copyText(created.key);
        openModal("key-modal");
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
      const expiry = $("#key-expiry").value;
      const networks = $("#key-networks").value.split(/[\s,]+/).map((n) => n.trim()).filter(Boolean);
      const created = await api.post("/api/keys", { name, role: platform ? "admin" : role, platform,
        expires_in_days: expiry ? Number(expiry) : null, allowed_networks: networks });
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
    platform ? api.get("/api/backups").catch(() => null) : null,
  ];
  const [health, keys, audit, plugins, users, members, branding, opsec, personal, vault, backups] = await Promise.all(tasks);
  const [credits, billing, team, ownKeys] = personal?.signed_in ? await Promise.all([
    api.get("/api/personal/credits").catch(() => null),
    api.get("/api/personal/billing").catch(() => null),
    api.get("/api/personal/team").catch(() => null),
    api.get("/api/personal/keys").catch(() => null),
  ]) : [null, null, null, null];
  data = { ...data, health, keys, audit, plugins, users, members, branding, opsec, personal, credits, billing, team, ownKeys, vault, backups };
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

// Phase 89: when a key stops working (replaced keys show their overlap end).
function keyExpiry(k) {
  if (!k.expires_at) return html`<span class="muted">never</span>`;
  if (k.expired) return html`<span class="muted">${formatDate(k.expires_at)}</span>`;
  const soon = k.expires_in_days !== null && k.expires_in_days <= 14;
  return html`<span class="${soon ? "pill high" : ""}" title="${formatDate(k.expires_at)}">${k.replaced_by ? "replaced, ends " : ""}in ${k.expires_in_days} d</span>`;
}

function keysCard() {
  return html`<div class="card card-pad" style="margin-top:16px">
    <div class="card-head"><div><h2>API keys</h2><p class="muted small">Keys are stored only as SHA-256 hashes. Viewer: read · Analyst: + scan · Admin: + delete, keys, audit.</p></div></div>
    <p class="muted small" style="margin:-6px 0 12px">New keys are bound to <b>${state.workspace?.name || "this workspace"}</b> and cannot see any other workspace.</p>
    <form id="key-form" class="filters" style="margin-bottom:12px">
      <input id="key-name" class="input" placeholder="Key name, e.g. alice-laptop" maxlength="128" style="max-width:260px">
      <select id="key-role" class="select" style="max-width:150px"><option value="viewer">Viewer</option><option value="analyst" selected>Analyst</option><option value="admin">Admin</option></select>
      <select id="key-expiry" class="select" style="max-width:170px" title="When the key stops working">
        <option value="30">Expires in 30 days</option><option value="90" selected>Expires in 90 days</option>
        <option value="365">Expires in a year</option><option value="">Never expires</option></select>
      <input id="key-networks" class="input" placeholder="Allowed networks, e.g. 203.0.113.0/24 (optional)" style="max-width:300px"
        title="Comma-separated addresses or CIDRs the key may be used from; empty: anywhere">
      ${state.me?.platform_admin ? html`<label class="check small"><input type="checkbox" id="key-platform"> Platform-wide admin key</label>` : ""}
      <button class="btn primary" type="submit">${ico("plus")}Create key</button>
    </form>
    ${data.keys ? html`<table class="table"><thead><tr><th>Name</th><th>Role</th><th>Key</th><th>Last used</th><th>Expires</th><th>Networks</th><th></th></tr></thead><tbody>
      ${data.keys.map((k) => html`<tr style="${k.revoked ? "opacity:.5" : ""}">
        <td><b>${k.name}</b>${k.id === state.me?.key_id ? html` <span class="pill accent">you</span>` : ""}</td>
        <td>${k.role}</td><td class="mono">${k.prefix}…</td>
        <td>${k.last_used_at ? timeAgo(k.last_used_at) : "never"}${k.stale ? html` <span class="pill medium" title="Not used for 90 days: revoke it if nothing needs it">unused</span>` : ""}</td>
        <td>${keyExpiry(k)}</td>
        <td class="small">${k.allowed_networks?.length ? k.allowed_networks.join(", ") : html`<span class="muted">anywhere</span>`}</td>
        <td class="actions">${k.revoked ? html`<span class="pill">revoked</span>` : k.expired ? html`<span class="pill">expired</span>` : html`
          ${k.replaced_by ? "" : html`<button class="btn sm ghost" data-act="key-rotate" data-id="${k.id}" title="A new key; this one keeps working for 24 hours">Rotate</button>`}
          <button class="btn sm ghost danger" data-act="revoke" data-id="${k.id}">Revoke</button>`}</td>
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
    <div class="section-title" style="margin-top:14px">Threat-intelligence feed (TAXII 2.1)</div>
    <p class="muted small">OpenCTI, MISP, Microsoft Sentinel, Splunk and other TAXII clients can pull this workspace's indicators on their own schedule: entities your team has tagged (tags become labels), lookalike domains from brand watches, and servers found by fingerprint watches. Read-only. Use a <b>viewer</b> API key as the password (HTTP Basic; any user name) or as a Bearer token.</p>
    <dl class="kv"><dt>Discovery URL</dt><dd class="mono">${base}/taxii2/</dd><dt>API root</dt><dd class="mono">${base}/taxii2/${ws}/</dd></dl>
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

function waitForRestart(message) {
  document.body.innerHTML = "";
  const note = document.createElement("p");
  note.style.cssText = "font:16px system-ui;margin:20vh auto;max-width:480px;text-align:center";
  note.textContent = message;
  document.body.append(note);
  const started = Date.now();
  const poll = async () => {
    try {
      if ((await fetch("/api/live", { cache: "no-store" })).ok && Date.now() - started > 2500) { location.reload(); return; }
    } catch { /* still restarting */ }
    setTimeout(poll, 1000);
  };
  setTimeout(poll, 1500);
}

const sizeText = (n) => (n >= 1e9 ? `${(n / 1e9).toFixed(1)} GB` : n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1e3))} KB`);

function backupsCard() {
  const b = data.backups;
  if (!b) return "";
  const pill = { ok: ["ok", "Working"], warn: ["warn", b.enabled ? "Check" : "Off"], error: ["critical", "Failing"], off: ["", "Provider"] }[b.health] || ["", b.health];
  const head = html`<div class="card-head wrap"><div><h2>${ico("download")}Backups</h2><p class="muted small">Everything (cases, evidence, settings and this installation's encryption key) in one encrypted file, so a lost, stolen or broken computer doesn't mean lost cases.</p></div><span class="pill ${pill[0]}">${pill[1]}</span></div>`;
  if (!b.available) return html`<div class="card card-pad" style="margin-top:16px">${head}<p class="small">${b.summary}</p></div>`;
  const list = b.backups.length ? html`<table class="table" style="margin-top:8px"><thead><tr><th>Made</th><th>Size</th><th>Argus</th><th></th></tr></thead><tbody>
    ${b.backups.slice(0, 8).map((x) => html`<tr><td>${formatDate(x.created_at)} <span class="muted small">${timeAgo(x.created_at)}</span></td><td>${sizeText(x.size)}</td><td class="small">${x.argus_version}</td>
      <td class="actions"><button class="btn sm ghost" data-act="backup-pick" data-file="${x.file}">Check or restore…</button></td></tr>`)}</tbody></table>` : "";
  const setup = b.managed ? html`<dl class="kv"><dt>Folder</dt><dd class="mono small">${b.folder}</dd><dt>How often</dt><dd>every ${b.every_hours} hours, keeping ${b.keep}</dd></dl>
      <p class="muted small">Set by this server's configuration (ARGUS_BACKUP_DIR, ARGUS_BACKUP_PASSWORD).</p>` : html`<details ${b.enabled ? "" : "open"} style="margin-top:10px"><summary>${b.enabled ? "Change where and how often" : "Set up automatic backups"}</summary>
      <form id="backup-form" style="display:grid;gap:8px;max-width:560px;margin-top:8px">
        <label class="label" for="backup-folder">Backup folder <span class="muted small">best: a cloud folder that syncs (OneDrive, iCloud Drive, Dropbox, Google Drive) or an external drive</span></label>
        <input class="input mono" id="backup-folder" value="${b.folder || b.suggestions[0]?.path || ""}" placeholder="Full path, e.g. D:\\Argus backups" required>
        ${b.suggestions.length ? html`<div class="small" style="display:flex;gap:6px;flex-wrap:wrap">${b.suggestions.map((f) => html`<button type="button" class="btn sm ghost" data-act="backup-folder" data-path="${f.path}">${f.label}</button>`)}</div>` : ""}
        <label class="label" for="backup-pass">Backup password ${b.password_set ? html`<span class="muted small">leave empty to keep the current one</span>` : html`<span class="muted small">at least 10 characters; you'll need it to restore</span>`}</label>
        <input class="input" type="password" id="backup-pass" autocomplete="new-password" minlength="10" maxlength="256" ${b.password_set ? "" : "required"}>
        <label class="label" for="backup-pass2">Type it again</label>
        <input class="input" type="password" id="backup-pass2" autocomplete="new-password" maxlength="256">
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <label class="small">Every <select class="select" id="backup-every" style="width:auto">${[[6, "6 hours"], [12, "12 hours"], [24, "day"], [168, "week"]].map(([v, l]) => html`<option value="${v}" ${b.every_hours === v ? "selected" : ""}>${l}</option>`)}</select></label>
          <label class="small">keep the last <input class="input" type="number" id="backup-keep" min="1" max="365" value="${b.keep}" style="width:80px"></label></div>
        <p class="muted small">Keep the password somewhere safe (a password manager). Without it a backup can't be opened, by anyone: that's what makes it safe in a cloud folder.</p>
        <p class="error-text"></p><div><button class="btn primary" type="submit">${b.enabled ? "Save" : "Turn on backups"}</button></div>
      </form></details>`;
  return html`<div class="card card-pad" style="margin-top:16px" id="backups-card">${head}
    ${b.restore_pending ? html`<div class="callout warn" style="margin-bottom:10px">${ico("alert")}<span>A restore is ready and takes over the next time Argus starts. <button class="btn sm" data-act="backup-restore-cancel">Cancel it</button></span></div>` : ""}
    <p class="small"${b.health === "error" ? ' style="color:var(--sev-high)"' : ""}>${b.summary}${b.last_backup && b.health !== "error" ? ` · ${sizeText(b.last_backup.size)}` : ""}</p>
    ${b.enabled ? html`<button class="btn sm" data-act="backup-now" ${b.running ? "disabled" : ""}>${ico("download")}${b.running ? "Backing up…" : "Back up now"}</button>` : ""}
    ${setup}${list}
    <details style="margin-top:12px" id="backup-file-details"><summary>Check or restore a backup</summary>
      <form id="backup-file-form" style="display:grid;gap:8px;max-width:560px;margin-top:8px">
        <label class="label" for="backup-file">Backup file <span class="muted small">full path to a .argusbackup file (from this list, a USB drive, or another computer's cloud folder)</span></label>
        <input class="input mono" id="backup-file" required>
        <label class="label" for="backup-file-pass">Its backup password</label>
        <input class="input" type="password" id="backup-file-pass" autocomplete="off" required>
        <p class="error-text"></p>
        <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn" type="submit" value="check">${ico("check")}Check it</button>
          ${data.personal ? html`<button class="btn danger" type="submit" value="restore">Restore it…</button>` : ""}</div>
        <p class="muted small">Checking opens the whole backup and verifies every file's fingerprint without changing anything.${data.personal ? " Restoring replaces what's on this computer (kept aside, not deleted) and restarts Argus." : " On a server, restore with: argus --backup-restore FILE"}</p>
      </form></details>
  </div>`;
}

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

function appCard() {
  const p = data.personal;
  if (!p) return "";
  return html`<div class="card card-pad" style="margin-top:16px" id="app-card">
    <div class="card-head wrap"><div><h2>Argus on this computer</h2><p class="muted small">Version ${p.version}. Your cases are kept in Argus's data folder, so updating or reinstalling never touches them.</p></div>
      ${p.desktop ? html`<span><button class="btn sm" data-act="quit-argus">${ico("x")}Quit Argus</button></span>` : ""}</div>
    ${p.update ? html`<div class="callout accent">${ico("download")}<span><b>Argus ${p.update.version} is available.</b> Download and run the installer: it updates this copy and keeps your cases.
      <a class="btn sm primary" style="margin-left:8px" href="${p.update.download_url}" target="_blank" rel="noopener noreferrer">Download the update</a></span></div>` : html`<p class="muted small">You have the latest version.</p>`}
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
      <dl class="kv"><dt>Available</dt><dd><b>${data.credits.credits.available}</b> credits${data.credits.shared_with_team ? " (shared with your team)" : ""}</dd><dt>This month</dt><dd>${data.credits.credits.allowance_remaining} of ${data.credits.credits.allowance} left</dd><dt>Purchased</dt><dd>${data.credits.credits.purchased}</dd>
        ${Object.values(data.credits.prices).map((p) => { const costs = Object.entries(p.lookups); const same = costs.every(([, c]) => c === costs[0][1]);
          return html`<dt>${p.label}</dt><dd>${same ? `${costs[0][1]} credit${costs[0][1] === 1 ? "" : "s"} per lookup` : costs.map(([n, c]) => `${n.replace(/_/g, " ")} ${c}`).join(" · ")}</dd>`; })}</dl>
      <p class="muted small" style="margin-top:6px">A brokered lookup tells the Argus account service what was looked up (a company number or name). The AI analyst sends the case material you confirm through it to Anthropic; the service keeps none of it. To keep even that private, set your own key for the source (or your own Claude API key); requests then go directly and cost no credits.</p>` : ""}
    ${teamSection()}
    ${billingSection(p)}
    <p class="muted small" style="margin-top:10px">If a subscription ends, nothing is lost: your cases stay readable, verifiable and exportable, and only new work waits until it is renewed.</p>
    ${yourDataSection(p)}
  </div>`;
}

function yourDataSection(p) {
  const docs = p.terms?.documents || {};
  const link = (doc, text) => (/^https?:\/\//.test(docs[doc] || "") ? html`<a href="${docs[doc]}" target="_blank" rel="noopener">${text} ↗</a>` : "");
  return html`<div class="section-title" style="margin-top:16px">Your data and the legal side</div>
    <p class="muted small">The Argus account service holds your account details, computers, plan, credits and payments; never your cases. ${p.terms?.accepted_version ? `You accepted the terms of ${p.terms.accepted_version}.` : ""}</p>
    <div class="small" style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:8px">${link("terms", "Terms of Service")}${link("acceptable-use", "Acceptable Use Policy")}${link("privacy", "Privacy Policy")}${link("refunds", "Refunds")}${link("dpa", "Data Processing Agreement")}</div>
    ${p.terms?.required ? html`<div class="callout warn" style="margin-bottom:8px">${ico("alert")}<span>The terms have been updated (version ${p.terms.version}). <button class="btn sm" data-act="terms-review">Review and accept</button></span></div>` : ""}
    <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn sm" data-act="account-data">${ico("download")}Download my account data</button>
      <button class="btn sm ghost danger" data-act="account-delete-show">Delete my account…</button></div>
    <form id="account-delete-form" hidden style="display:grid;gap:8px;max-width:440px;margin-top:10px">
      <p class="small">This deletes your Argus account: your name, email, password and computers are erased, and any subscription ends now, without a refund for the rest of the period. Payment records are kept anonymously, as tax law requires. <b>Your cases stay on this computer</b>; back them up first if you'll want them.</p>
      <label class="label" for="account-delete-pass">Your password</label><input class="input" type="password" id="account-delete-pass" autocomplete="current-password" required>
      <label class="label" for="account-delete-confirm">Type DELETE to confirm</label><input class="input" id="account-delete-confirm" autocomplete="off" required>
      <p class="error-text"></p><div><button class="btn danger" type="submit">Delete my account</button></div>
    </form>`;
}

function money(price) {
  if (!price || price.amount == null) return "";
  const amount = new Intl.NumberFormat(undefined, { style: "currency", currency: price.currency || "USD" }).format(price.amount / 100);
  return price.interval ? `${amount} a ${price.interval}` : amount;
}

function teamSection() {
  const t = data.team;
  if (!t || t.role === "none") return "";
  if (t.role === "member") {
    return html`<div class="section-title" style="margin-top:14px">Your team</div>
      <p class="small">You're on <b>${t.team || "a team"}</b>'s team${t.owner_email ? ` (${t.owner_email})` : ""}. The team's plan covers your use of Argus and its shared credits; your cases stay on this computer and nobody else on the team can see them.</p>
      ${t.active ? "" : html`<div class="callout warn" style="margin:8px 0">${ico("alert")}<span>The team's plan isn't active. Ask its owner, or choose your own plan.</span></div>`}
      <button class="btn sm ghost danger" data-act="team-leave">Leave the team</button>`;
  }
  const free = t.seats - t.used - t.pending;
  return html`<div class="section-title" style="margin-top:14px">Your Business team · ${t.used} of ${t.seats} seats used</div>
    <p class="muted small">Each member signs in with their own account on their own computers and shares the team's credits. You see who is on the team and how many credits each used, never their cases. Add or remove seats under Manage billing.</p>
    <table class="table"><thead><tr><th>Member</th><th>Credits this month</th><th>Last sign-in</th><th></th></tr></thead><tbody>
      ${t.members.map((m) => html`<tr><td><b>${m.name || m.email}</b>${m.name ? html`<div class="muted small">${m.email}</div>` : ""}${m.owner ? html` <span class="pill accent">owner</span>` : ""}</td>
        <td>${m.credits_this_month}</td><td>${m.last_login_at ? timeAgo(m.last_login_at) : "never"}</td>
        <td class="actions">${m.owner ? "" : html`<button class="btn sm ghost" data-act="team-signout" data-id="${m.id}" data-email="${m.email}" title="For a lost or stolen laptop: they can sign in again">Sign out computers</button><button class="btn sm ghost danger" data-act="team-remove" data-id="${m.id}" data-email="${m.email}">Remove</button>`}</td></tr>`)}
      ${t.invites.map((i) => html`<tr><td>${i.email} <span class="pill">invited</span></td><td colspan="2" class="muted small">until ${formatDate(i.expires_at)}</td>
        <td class="actions"><button class="btn sm ghost" data-act="team-cancel" data-email="${i.email}">Cancel</button></td></tr>`)}
    </tbody></table>
    ${free > 0 ? html`<form id="team-invite-form" class="filters" style="margin-top:10px">
      <input class="input" id="team-invite-name" placeholder="Their name" maxlength="255" style="max-width:200px" aria-label="Their name">
      <input class="input" id="team-invite-email" type="email" placeholder="colleague@example.org" maxlength="320" required style="max-width:260px" aria-label="Their email">
      <button class="btn sm primary" type="submit">${ico("plus")}Add to team</button><p class="error-text"></p></form>
      <p class="muted small">${free} seat${free === 1 ? "" : "s"} free. New to Argus: an account is created and they're emailed a link to choose their password. Already have an account: they're sent an invitation to join (it works for a week).</p>`
      : html`<p class="muted small" style="margin-top:8px">All seats are taken or invited: add seats under Manage billing to invite more.</p>`}`;
}

const FEATURE_LABELS = { monitoring: "Monitoring and watches", branded_reports: "Branded reports", playbooks: "Playbooks", team: "Team tools: add members, shared credits" };
const PLAN_BLURB = {
  byok: "Every investigation tool, using your own API keys for paid sources. The lowest price.",
  personal: "Every investigation tool, with monthly credits for premium sources and the AI analyst.",
  professional: "Everything in Personal, plus monitoring and watches, branded reports and playbooks.",
  business: "Everything in Professional for each person, plus team tools. Priced per seat.",
};

function planCard(x, p) {
  const current = p.plan === x.plan;
  const credits = x.monthly_credits ? `${x.monthly_credits.toLocaleString()} credits a month${x.per_seat ? " per seat, shared" : ""}` : "No included credits: your own keys, or credit packs";
  const price = x.price ? `${money(x.price)}${x.per_seat ? " per seat" : ""}` : "";
  const setup = x.setup_price ? ` + ${money({ ...x.setup_price, interval: null })} one-off set-up` : "";
  return html`<div class="card card-pad plan-card${current ? " current" : ""}">
    <div style="display:flex;justify-content:space-between;align-items:baseline;gap:8px"><b>${x.label}</b>${current ? html`<span class="pill accent">your plan</span>` : ""}</div>
    ${price ? html`<div class="plan-price">${price}<span class="muted small">${setup}</span></div>` : ""}
    <p class="muted small" style="margin:6px 0">${PLAN_BLURB[x.plan] || ""}</p>
    <ul class="plan-list small">
      <li>${credits}</li>
      <li>${x.per_seat ? `${x.max_devices} computers per person` : `${x.max_devices} computer${x.max_devices === 1 ? "" : "s"}`}</li>
      ${x.features.map((f) => html`<li>${FEATURE_LABELS[f] || f}</li>`)}
    </ul>
    ${current ? "" : x.per_seat
      ? html`<div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-top:8px"><input class="input" type="number" id="team-seats" min="2" max="100" value="3" style="width:72px" aria-label="Seats"><span class="muted small">seats</span>
          <button class="btn sm primary" data-act="buy" data-item="${x.item}" style="width:100%">${ico("check")}Choose ${x.label}</button></div>`
      : html`<button class="btn sm primary" data-act="buy" data-item="${x.item}" style="margin-top:8px">${ico("check")}Choose ${x.label}</button>`}
  </div>`;
}

function includesLine(p) {
  if (!p.features) return "";
  const missing = Object.entries(p.features).filter(([f, ok]) => !ok && f !== "team").map(([f]) => FEATURE_LABELS[f]);
  return missing.length ? html`<p class="muted small" style="margin:6px 0 0">${ico("info")} Not in your plan: ${missing.join(", ")}. They're in Professional and Business.</p>` : "";
}

function billingSection(p) {
  const b = data.billing;
  if (data.team?.role === "member") return "";
  if (!b?.enabled) return includesLine(p);
  const subscribed = ["active", "past_due"].includes(p.status) && p.plan && p.plan !== "trial";
  return html`<div class="section-title" style="margin-top:14px">Plans and payment</div>
    <p class="muted small">Payment is taken by Stripe on its own secure page: Argus never sees your card. ${subscribed ? "To switch plan, update your card, download invoices or cancel, use Manage billing; a cancelled plan keeps working to the end of the period you have paid for." : ""}</p>
    ${includesLine(p)}
    ${p.status === "past_due" ? html`<div class="callout warn" style="margin:8px 0">${ico("alert")}<span>Your last payment didn't go through. Argus keeps working while Stripe retries; update your card in Manage billing.</span></div>` : ""}
    ${subscribed ? "" : html`<div class="plan-grid">${b.plans.map((x) => planCard(x, p))}</div>`}
    <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:10px">
      ${b.credit_packs.map((x) => html`<button class="btn sm" data-act="buy" data-item="${x.item}">${ico("plus")}Buy ${x.credits} credits${x.price ? ` (${money(x.price)})` : ""}</button>`)}
      ${b.has_billing ? html`<button class="btn sm ghost" data-act="billing-portal">${ico("external")}Manage billing</button>` : ""}
    </div>`;
}

function ownKeysCard() {
  const k = data.ownKeys;
  if (!k) return "";
  return html`<div class="card card-pad" style="margin-top:16px" id="own-keys-card">
    <div class="card-head"><div><h2>Your own API keys</h2><p class="muted small">With your own key, lookups go straight from this computer to the source and use no Argus credits (this is how the Bring-your-own-keys plan works; any plan can use it). Keys are stored encrypted on this computer only and are never sent to the Argus account service.</p></div></div>
    <table class="table"><tbody>${k.keys.map((x) => html`<tr>
      <td><b>${x.label}</b><div class="muted small">Get a key at ${x.where}</div></td>
      <td>${x.set ? html`<span class="pill ok">saved</span> <span class="mono small">…${x.ends_with}</span>` : html`<span class="muted small">not set: uses credits</span>`}</td>
      <td class="actions">${x.set ? html`<button class="btn sm ghost danger" data-act="key-remove" data-id="${x.provider}">Remove</button>` : ""}</td></tr>`)}</tbody></table>
    <form id="own-key-form" class="filters" style="margin-top:10px">
      <select class="select" id="own-key-provider" aria-label="Source" style="max-width:260px">${k.keys.map((x) => html`<option value="${x.provider}">${x.label}</option>`)}</select>
      <input class="input mono" id="own-key-value" type="password" placeholder="Paste the API key" autocomplete="off" maxlength="512" required style="max-width:300px" aria-label="API key">
      <button class="btn sm primary" type="submit">Save key</button><p class="error-text"></p>
    </form>
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
    ${appCard()}
    ${subscriptionCard()}
    ${data.personal?.signed_in ? ownKeysCard() : ""}
    ${backupsCard()}
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
