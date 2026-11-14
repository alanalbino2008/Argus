// Settings: appearance, account and (for admins) API keys, audit log and plugins.

import { api, enc, request } from "../api.js";
import { empty, ico } from "../components.js";
import { $, confirmDialog, copyText, formatDate, html, on, openModal, setHTML, timeAgo, toast } from "../dom.js";
import { emit, on as onState, state } from "../state.js";
import { verifyFile } from "./reports.js";

let pendingLogo; // undefined = keep, "" = remove, "data:..." = replace
let logoUrl = null;

let root;
let data = { keys: null, audit: null, plugins: null, health: null, verify: null, users: null, members: null };

export function initSettings(el) {
  root = el;
  onState("workspace", () => { data = { ...data, keys: null, audit: null, members: null }; refresh(); });
  on(root, "click", "[data-theme-choice]", (_e, btn) => { window.argusTheme.set(btn.dataset.themeChoice); render(); });
  on(root, "click", "[data-act]", async (_e, btn) => {
    const { act, id } = btn.dataset;
    try {
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
  ];
  const [health, keys, audit, plugins, users, members, branding] = await Promise.all(tasks);
  data = { ...data, health, keys, audit, plugins, users, members, branding };
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
    ${workspacesCard()}
    ${brandingCard()}
    ${verifyCard()}
    ${admin ? html`${platform ? usersCard() : ""}${keysCard()}${auditCard()}${platform ? pluginsCard() : ""}`
      : html`<div class="card" style="margin-top:16px">${empty("shield", "Administration", "API keys and the audit log are available to this workspace's administrators.")}</div>`}
  </div>`);
}
