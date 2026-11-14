// Settings: appearance, account and (for admins) API keys, audit log and plugins.

import { api, enc } from "../api.js";
import { empty, ico } from "../components.js";
import { $, confirmDialog, copyText, formatDate, html, on, openModal, setHTML, timeAgo, toast } from "../dom.js";
import { state } from "../state.js";

let root;
let data = { keys: null, audit: null, plugins: null, health: null, verify: null };

export function initSettings(el) {
  root = el;
  on(root, "click", "[data-theme-choice]", (_e, btn) => { window.argusTheme.set(btn.dataset.themeChoice); render(); });
  on(root, "click", "[data-act]", async (_e, btn) => {
    const { act, id } = btn.dataset;
    try {
      if (act === "revoke") {
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
  root.addEventListener("submit", async (e) => {
    if (e.target.id !== "key-form") return;
    e.preventDefault();
    const name = $("#key-name").value.trim();
    const role = $("#key-role").value;
    if (!name) return toast("Give the key a name", "error");
    try {
      const created = await api.post("/api/keys", { name, role });
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
  const admin = state.me?.role === "admin";
  const tasks = [api.get("/api/health").catch(() => null)];
  if (admin) tasks.push(api.get("/api/keys"), api.get("/api/audit?limit=50"), api.get("/api/plugins"));
  const [health, keys = null, audit = null, plugins = null] = await Promise.all(tasks).catch(() => [null]);
  data = { ...data, health, keys, audit, plugins };
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
    <form id="key-form" class="filters" style="margin-bottom:12px">
      <input id="key-name" class="input" placeholder="Key name, e.g. alice-laptop" maxlength="128" style="max-width:260px">
      <select id="key-role" class="select" style="max-width:150px"><option value="viewer">Viewer</option><option value="analyst" selected>Analyst</option><option value="admin">Admin</option></select>
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
  const admin = state.me?.role === "admin";
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
          <dt>Version</dt><dd>${h ? `Argus ${h.version}` : "—"}</dd><dt>Database</dt><dd>${h ? `${h.database.backend} · ${h.database.reachable ? "reachable" : "unreachable"}` : "—"}</dd></dl>
      </div>
    </div>
    ${admin ? html`${keysCard()}${auditCard()}${pluginsCard()}`
      : html`<div class="card" style="margin-top:16px">${empty("shield", "Administration", "API keys, the audit log and plugins are available to administrators.")}</div>`}
  </div>`);
}
