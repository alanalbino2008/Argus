// The owner console: set-up, sign-in with password + authenticator code, and the console itself
// (health, settings, plans, security, activity). Only the owner's own session reaches its API.

import { $, escape, formatDate, html, on, setHTML, timeAgo, toast, trusted } from "./dom.js";

const root = $("#owner-root");
let state = null;
let tab = "overview";
let cache = {};
let retry = null; // an action waiting for a fresh authenticator code
let reveal = null; // recovery codes or a QR code to show once

// ------------------------------------------------------------------ talking to the server
class Problem extends Error {
  constructor(status, detail, confirm) { super(detail); this.status = status; this.confirm = confirm; }
}

async function call(method, path, body) {
  const res = await fetch(path, {
    method, credentials: "same-origin",
    headers: body !== undefined ? { "Content-Type": "application/json" } : {},
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = typeof data.detail === "string" ? data.detail : "Something went wrong";
    throw new Problem(res.status, detail, res.headers.get("x-argus-confirm") === "code");
  }
  return data;
}

// A change that needs a fresh code asks for it, then runs again.
async function guarded(action) {
  try {
    return await action();
  } catch (err) {
    if (err instanceof Problem && err.confirm) {
      retry = action;
      renderConfirm();
      return null;
    }
    if (err instanceof Problem && err.status === 401) return start();
    toast(err.message, "error", 6000);
    return null;
  }
}

// ------------------------------------------------------------------ the screens before the console
function frame(content) {
  setHTML(root, html`<div class="signin-root"><div class="card signin owner-card">
    <div class="owner-badge">Argus · Owner console</div>${content}</div></div>`);
}

function screenNotConfigured() {
  frame(html`<h1>Not set up yet</h1>
    <p>The owner console opens only for the email set as this server's owner. Ask whoever deployed Argus to set <code>ARGUS_OWNER_EMAIL</code> to your email address (Helm: <code>config.ownerEmail</code>) and restart it.</p>`);
}

function screenSetup() {
  if (!state.encryption) {
    return frame(html`<h1>One more thing</h1><p>This server needs an encryption key to protect your secrets. Set <code>ARGUS_ENCRYPTION_KEY</code> (Helm: <code>secrets.encryptionKey</code>) to a long random value and restart it.</p>`);
  }
  if (reveal?.qr) {
    return frame(html`<h1>Set up your authenticator</h1>
      <p>Scan this with an authenticator app on your phone (Google Authenticator, Microsoft Authenticator, 1Password…).</p>
      <div class="owner-qr">${trusted(reveal.qr)}</div>
      <details class="small"><summary>Can't scan? Type this key instead</summary><p class="mono" style="word-break:break-all">${reveal.secret}</p></details>
      <form id="setup-finish" style="display:grid;gap:10px;margin-top:12px">
        <div class="field"><label class="label" for="s-pass">Choose a password</label><input id="s-pass" class="input" type="password" autocomplete="new-password" minlength="12" required></div>
        <div class="field"><label class="label" for="s-pass2">Password again</label><input id="s-pass2" class="input" type="password" autocomplete="new-password" minlength="12" required></div>
        <div class="field"><label class="label" for="s-code">The 6-digit code your app shows</label><input id="s-code" class="input mono" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required></div>
        <p class="error-text" role="alert"></p>
        <button class="btn primary" type="submit">Finish set-up</button>
      </form>`);
  }
  frame(html`<h1>Set up your owner console</h1>
    <p>This is done once. Prove you control this server with its administrator key (the <code>ARGUS_BOOTSTRAP_ADMIN_KEY</code> it was deployed with). After this, only you can sign in here.</p>
    <form id="setup-start" style="display:grid;gap:10px">
      <div class="field"><label class="label" for="s-email">Your email</label><input id="s-email" class="input" type="email" autocomplete="username" required></div>
      <div class="field"><label class="label" for="s-key">Server administrator key</label><input id="s-key" class="input mono" type="password" autocomplete="off" required></div>
      <p class="error-text" role="alert"></p>
      <button class="btn primary" type="submit">Continue</button>
    </form>`);
}

function screenRecoveryCodes() {
  frame(html`<h1>Save your recovery codes</h1>
    <p>If you lose your phone, each of these lets you in once instead of an authenticator code. Keep them somewhere safe, like a password manager. They won't be shown again.</p>
    <ol class="owner-codes mono">${reveal.codes.map((c) => html`<li>${c}</li>`)}</ol>
    <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn" data-act="copy-codes">Copy</button><button class="btn primary" data-act="codes-saved">I've saved them</button></div>`);
}

function screenLogin() {
  frame(html`<h1>Sign in</h1>
    <form id="login" style="display:grid;gap:10px">
      <div class="field"><label class="label" for="l-email">Email</label><input id="l-email" class="input" type="email" autocomplete="username" required></div>
      <div class="field"><label class="label" for="l-pass">Password</label><input id="l-pass" class="input" type="password" autocomplete="current-password" required></div>
      <p class="error-text" role="alert"></p>
      <button class="btn primary" type="submit">Continue</button>
    </form>
    <p class="muted small" style="margin-top:12px">Five wrong attempts lock this console for 15 minutes, and every sign-in is emailed to you.</p>`);
  $("#l-email")?.focus();
}

function screenCode() {
  frame(html`<h1>Authenticator code</h1>
    <form id="verify" style="display:grid;gap:10px">
      <div class="field"><label class="label" for="v-code">The 6-digit code from your authenticator app</label><input id="v-code" class="input mono" inputmode="numeric" autocomplete="one-time-code" maxlength="12" required></div>
      <p class="muted small">Lost your phone? Enter one of your recovery codes instead.</p>
      <p class="error-text" role="alert"></p>
      <button class="btn primary" type="submit">Sign in</button>
    </form>`);
  $("#v-code")?.focus();
}

function renderConfirm() {
  const box = document.createElement("div");
  box.className = "modal-root open owner-confirm";
  setHTML(box, html`<div class="modal-backdrop"></div><div class="modal card card-pad" role="dialog" aria-modal="true" aria-labelledby="c-title" style="max-width:380px">
    <h2 id="c-title">Confirm it's you</h2>
    <p class="muted small">Enter a fresh code from your authenticator app. It covers changes for the next 10 minutes.</p>
    <form id="confirm" style="display:grid;gap:10px;margin-top:10px">
      <input id="c-code" class="input mono" inputmode="numeric" autocomplete="one-time-code" maxlength="12" required aria-label="Authenticator code">
      <p class="error-text" role="alert"></p>
      <div style="display:flex;gap:8px;justify-content:flex-end"><button class="btn ghost" type="button" data-act="confirm-cancel">Cancel</button><button class="btn primary" type="submit">Confirm</button></div>
    </form></div>`);
  document.body.append(box);
  $("#c-code").focus();
}

// ------------------------------------------------------------------ the console
const TABS = [["overview", "Overview"], ["payments", "Payments"], ["email", "Email"], ["accounts", "Accounts & plans"],
  ["sources", "Data sources"], ["security", "Security"], ["activity", "Activity"]];
const STATUS = { ok: ["ok", "Working"], warn: ["warn", "Check"], error: ["critical", "Problem"], off: ["", "Off"] };

function shell(content) {
  setHTML(root, html`<div class="owner-shell">
    <header class="owner-head"><div><b>Argus</b> <span class="muted">· Owner console</span></div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><span class="muted small">${state.email}</span>
        <a class="btn sm" href="/" target="_blank" rel="noopener">Open Argus</a><button class="btn sm ghost" data-act="logout">Sign out</button></div></header>
    <nav class="owner-tabs" aria-label="Sections">${TABS.map(([k, l]) => html`<button class="${tab === k ? "active" : ""}" data-tab="${k}" aria-current="${tab === k ? "page" : "false"}">${l}</button>`)}</nav>
    <section class="owner-body">${content}</section></div>`);
}

function healthList(items) {
  return html`<table class="table"><tbody>${items.map((h) => html`<tr>
    <td style="width:190px"><b>${h.name}</b></td>
    <td><span class="pill ${STATUS[h.status][0]}">${STATUS[h.status][1]}</span></td>
    <td>${h.detail}${h.fix && h.status !== "ok" ? html`<div class="muted small">${h.fix}</div>` : ""}</td></tr>`)}</tbody></table>`;
}

function activityTable(events) {
  return html`<table class="table"><thead><tr><th>When</th><th>What</th><th>Who</th><th>Outcome</th></tr></thead><tbody>
    ${events.map((e) => html`<tr><td class="small">${formatDate(e.ts)}</td><td>${e.action}</td>
      <td class="small">${e.actor_name || e.actor_id || ""}${e.ip ? html`<div class="muted">${e.ip}</div>` : ""}</td><td><span class="pill ${e.outcome === "success" ? "" : "warn"}">${e.outcome || ""}</span></td></tr>`)}</tbody></table>`;
}

async function viewOverview() {
  const d = cache.overview = await call("GET", "/api/owner/console/overview");
  const problems = d.health.filter((h) => h.status === "error" || h.status === "warn").length;
  const b = d.business;
  shell(html`<div class="owner-grid">
    <div class="card card-pad" style="grid-column:1/-1"><div class="card-head"><div><h2>System health</h2><p class="muted small">Argus ${d.version}. ${problems ? `${problems} thing${problems === 1 ? "" : "s"} to look at.` : "Everything is working."}</p></div>
      <button class="btn sm" data-act="refresh">Check again</button></div>${healthList(d.health)}</div>
    ${b ? html`<div class="card card-pad"><h2>Your business</h2>
      <dl class="kv"><dt>Accounts</dt><dd>${b.customers.accounts}</dd><dt>Paying</dt><dd>${b.customers.paying}</dd><dt>On trial</dt><dd>${b.customers.trialing}</dd>
        <dt>Payment due</dt><dd>${b.customers.past_due}</dd><dt>Need attention</dt><dd>${b.attention}</dd></dl>
      <a class="btn sm" href="/#/business" target="_blank" rel="noopener" style="margin-top:10px">Open the Business page</a></div>` : ""}
    <div class="card card-pad" style="grid-column:1/-1"><h2>Recent activity</h2>${activityTable(d.activity)}</div></div>`);
}

async function loadConfig() {
  cache.config = await call("GET", "/api/owner/console/config");
  return cache.config;
}

function sourceNote(s) {
  if (s.source === "console") return html`<span class="pill accent" title="Set here; it overrides the deployment">set here</span> <button class="btn sm ghost" type="button" data-reset="${s.name}">Use deployment value</button>`;
  if (s.source === "deployment") return html`<span class="pill" title="From the deployment's configuration">from deployment</span>`;
  return html`<span class="muted small">default</span>`;
}

function fieldInput(s) {
  const id = `f-${s.name}`;
  if (s.kind === "bool") return html`<label class="check"><input type="checkbox" id="${id}" data-name="${s.name}" data-kind="bool" ${s.value ? "checked" : ""}> On</label>`;
  if (s.kind === "choice") return html`<select class="select" id="${id}" data-name="${s.name}" data-kind="choice">${s.choices.map((c) => html`<option value="${c}" ${c === s.value ? "selected" : ""}>${c}</option>`)}</select>`;
  if (s.kind === "secret") return html`<input class="input mono" type="password" id="${id}" data-name="${s.name}" data-kind="secret" autocomplete="off" placeholder="${s.set ? `Saved (…${s.ends_with}): type to replace` : "Not set"}">`;
  return html`<input class="input" id="${id}" data-name="${s.name}" data-kind="${s.kind}" type="${s.kind === "int" ? "number" : s.kind === "email" ? "email" : "text"}" value="${s.value ?? ""}" placeholder="${s.placeholder || ""}" autocomplete="off">`;
}

function settingsForm(section, extra = "") {
  const fields = cache.config.settings.filter((s) => s.section === section);
  return html`<form class="owner-settings" data-section="${section}">
    ${fields.map((s) => html`<div class="owner-field"><label class="label" for="f-${s.name}">${s.label}</label>${fieldInput(s)}
      <div class="owner-field-meta">${s.help ? html`<span class="muted small">${s.help}</span>` : ""}${sourceNote(s)}</div></div>`)}
    ${cache.config.encryption ? "" : html`<p class="callout warn">Secrets can't be saved: this server has no encryption key.</p>`}
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:6px"><button class="btn primary" type="submit">Save</button>${extra}</div></form>`;
}

async function viewSection(section, title, intro, extra = "") {
  await loadConfig();
  shell(html`<div class="card card-pad"><h2>${title}</h2><p class="muted small">${intro}</p>${settingsForm(section, extra)}</div>`);
}

async function viewPayments() {
  const hook = `${location.origin}/api/billing/webhook`;
  await viewSection("payments", "Payments (Stripe)", trusted(`Customers pay on Stripe's own pages. In Stripe, add a webhook endpoint <code>${escape(hook)}</code> for the events <code>checkout.session.completed</code>, <code>checkout.session.async_payment_succeeded</code>, <code>customer.subscription.created</code>, <code>.updated</code>, <code>.deleted</code>, <code>charge.refunded</code>, <code>charge.dispute.created</code> and <code>charge.dispute.closed</code>.`),
    html`<button class="btn" type="button" data-act="test-stripe">Test connection</button>`);
}

async function viewAccounts() {
  await loadConfig();
  const plans = (cache.plans = await call("GET", "/api/owner/console/plans")).plans;
  shell(html`<div class="card card-pad"><h2>Accounts and trials</h2><p class="muted small">Who can join and for how long trials last.</p>${settingsForm("accounts")}</div>
    <div class="card card-pad" style="margin-top:16px"><h2>Plans</h2><p class="muted small">Monthly credits and computers for each plan. Changes apply at once; customers' Argus picks them up at its next daily check. Prices are set in Stripe.</p>
      <form id="plans-form"><table class="table"><thead><tr><th>Plan</th><th>Monthly credits</th><th>Computers</th></tr></thead><tbody>
        ${plans.map((p) => html`<tr><td><b>${p.label}</b>${p.per_seat ? html`<div class="muted small">per seat</div>` : ""}</td>
          <td><input class="input" type="number" min="0" max="1000000" data-plan="${p.plan}" data-key="monthly_credits" value="${p.monthly_credits}" style="max-width:130px" aria-label="${p.label} monthly credits"></td>
          <td><input class="input" type="number" min="1" max="20" data-plan="${p.plan}" data-key="max_devices" value="${p.max_devices}" style="max-width:90px" aria-label="${p.label} computers"></td></tr>`)}
      </tbody></table><button class="btn primary" type="submit" style="margin-top:8px">Save plans</button></form></div>`);
}

async function viewSecurity() {
  await loadConfig();
  const [sec, keys] = await Promise.all([call("GET", "/api/owner/security"), call("GET", "/api/owner/console/keys")]);
  shell(html`<div class="owner-grid">
    <div class="card card-pad"><h2>You</h2><dl class="kv"><dt>Email</dt><dd>${sec.email}</dd><dt>Owner since</dt><dd>${formatDate(sec.created_at)}</dd><dt>Recovery codes left</dt><dd>${sec.recovery_left}</dd></dl>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px"><button class="btn sm" data-act="new-codes">New recovery codes</button><button class="btn sm" data-act="new-phone">Move to a new phone</button></div>
      <form id="password-form" style="display:grid;gap:8px;margin-top:14px;max-width:360px"><b class="small">Change password</b>
        <input class="input" type="password" id="p-current" placeholder="Current password" autocomplete="current-password" required>
        <input class="input" type="password" id="p-new" placeholder="New password (12+ characters)" autocomplete="new-password" minlength="12" required>
        <button class="btn sm" type="submit">Change password</button></form></div>
    <div class="card card-pad"><h2>Signed-in sessions</h2><table class="table"><tbody>${sec.sessions.map((x) => html`<tr>
      <td>${x.ip}<div class="muted small">${(x.user_agent || "").slice(0, 60)}</div></td><td class="small">active ${timeAgo(x.last_seen_at)}</td>
      <td class="actions">${x.current ? html`<span class="pill accent">this one</span>` : html`<button class="btn sm ghost danger" data-act="end-session" data-id="${x.id}">Sign out</button>`}</td></tr>`)}</tbody></table>
      <button class="btn sm ghost" data-act="end-others" style="margin-top:8px">Sign out every other session</button></div>
    <div class="card card-pad" style="grid-column:1/-1"><h2>Who can administer this server</h2>${settingsForm("security")}
      <h3 style="margin-top:16px">API keys</h3><p class="muted small">Keys let programs (and people with a key) use Argus's API. Revoke any you don't recognise.</p>
      <table class="table"><thead><tr><th>Name</th><th>Role</th><th>Key</th><th>Last used</th><th></th></tr></thead><tbody>${keys.keys.map((k) => html`<tr style="${k.revoked ? "opacity:.5" : ""}">
        <td><b>${k.name}</b></td><td>${k.role}${k.workspace_id ? "" : " · whole server"}</td><td class="mono">${k.prefix}…</td><td>${k.last_used_at ? timeAgo(k.last_used_at) : "never"}</td>
        <td class="actions">${k.revoked ? html`<span class="pill">revoked</span>` : html`<button class="btn sm ghost danger" data-act="revoke-key" data-id="${k.id}">Revoke</button>`}</td></tr>`)}</tbody></table></div></div>`);
}

async function viewActivity() {
  const filter = cache.activityFilter || "";
  const d = await call("GET", `/api/owner/console/activity?limit=200${filter ? `&action=${encodeURIComponent(filter)}` : ""}`);
  shell(html`<div class="card card-pad"><div class="card-head wrap"><div><h2>Activity</h2><p class="muted small">Everything done on this server, newest first. The log is tamper-evident.</p></div>
    <select class="select" id="activity-filter" style="max-width:240px" aria-label="Filter"><option value="">Everything</option>${["owner.sign_in", "owner.sign_in_failed", "owner.config", "account.signup", "billing.subscription", "billing.dispute_opened", "key.revoke"].map((a) => html`<option ${a === filter ? "selected" : ""}>${a}</option>`)}</select></div>
    ${activityTable(d.events)}</div>`);
}

const VIEWS = {
  overview: viewOverview,
  payments: viewPayments,
  email: () => viewSection("email", "Email", "The mail server Argus sends customer emails and your security alerts through. Ask your email provider for these details.", html`<button class="btn" type="button" data-act="test-email">Send test email</button>`),
  accounts: viewAccounts,
  sources: () => viewSection("sources", "Paid data sources", "Your keys for the paid sources customers use through Argus Connect, paid for with their credits. Customers on Bring-your-own-keys use their own."),
  security: viewSecurity,
  activity: viewActivity,
};

async function show(name) {
  tab = name;
  try {
    await VIEWS[name]();
  } catch (err) {
    if (err instanceof Problem && err.status === 401) return start();
    toast(err.message, "error", 6000);
  }
}

// ------------------------------------------------------------------ start
async function start() {
  state = await call("GET", "/api/owner/state").catch((err) => ({ error: err.message }));
  if (state.error) return frame(html`<h1>Not available</h1><p>${state.error}</p>`);
  if (reveal?.codes) return screenRecoveryCodes();
  if (!state.configured) return screenNotConfigured();
  if (!state.owner_exists) return screenSetup();
  if (state.stage === "full") return show(tab);
  if (state.stage === "code") return screenCode();
  return screenLogin();
}

async function submitForm(form, fn) {
  const error = form.querySelector(".error-text");
  const button = form.querySelector("button[type=submit]");
  if (error) error.textContent = "";
  button.disabled = true;
  try {
    await fn();
  } catch (err) {
    if (error) error.textContent = err.message;
    else toast(err.message, "error", 6000);
  } finally {
    button.disabled = false;
  }
}

root.addEventListener("submit", (e) => {
  e.preventDefault();
  const form = e.target;
  const v = (id) => $(`#${id}`).value;
  if (form.id === "setup-start") return submitForm(form, async () => {
    const r = await call("POST", "/api/owner/setup/start", { email: v("s-email").trim(), setup_key: v("s-key").trim() });
    reveal = { qr: r.qr_svg, secret: r.secret, email: v("s-email").trim(), key: v("s-key").trim() };
    screenSetup();
  });
  if (form.id === "setup-finish") return submitForm(form, async () => {
    if (v("s-pass") !== v("s-pass2")) throw new Error("The two passwords are different");
    const r = await call("POST", "/api/owner/setup/finish", { email: reveal.email, setup_key: reveal.key, password: v("s-pass"), code: v("s-code").trim() });
    reveal = { codes: r.recovery_codes };
    await start();
  });
  if (form.id === "login") return submitForm(form, async () => {
    await call("POST", "/api/owner/login", { email: v("l-email").trim(), password: v("l-pass") });
    screenCode();
  });
  if (form.id === "verify") return submitForm(form, async () => {
    const r = await call("POST", "/api/owner/verify", { code: v("v-code").trim() });
    if (r.used_recovery_code) toast("You used a recovery code. If you've lost your phone, use Security → Move to a new phone.", "info", 8000);
    await start();
  });
  if (form.id === "plans-form") return guarded(async () => {
    const plans = {};
    form.querySelectorAll("input[data-plan]").forEach((i) => { (plans[i.dataset.plan] ||= {})[i.dataset.key] = Number(i.value); });
    await call("PUT", "/api/owner/console/plans", { plans });
    toast("Plans saved", "success");
  });
  if (form.id === "password-form") return guarded(async () => {
    await call("POST", "/api/owner/password", { current: v("p-current"), new: v("p-new") });
    toast("Password changed; every other session was signed out", "success", 6000);
    form.reset();
  });
  if (form.classList.contains("owner-settings")) return guarded(async () => {
    const values = {};
    const byName = Object.fromEntries(cache.config.settings.map((s) => [s.name, s]));
    form.querySelectorAll("[data-name]").forEach((i) => {
      const s = byName[i.dataset.name];
      if (i.dataset.kind === "bool") { if (i.checked !== !!s.value) values[s.name] = i.checked; return; }
      if (i.dataset.kind === "secret") { if (i.value.trim()) values[s.name] = i.value.trim(); return; }
      const value = i.dataset.kind === "int" ? Number(i.value) : i.value.trim();
      if (String(value) !== String(s.value ?? "")) values[s.name] = value;
    });
    if (!Object.keys(values).length) return toast("Nothing changed", "info");
    await call("PUT", "/api/owner/console/config", { values });
    toast("Saved: it applies straight away", "success");
    await show(tab);
  });
});

document.addEventListener("submit", (e) => {
  if (e.target.id !== "confirm") return;
  e.preventDefault();
  submitForm(e.target, async () => {
    await call("POST", "/api/owner/confirm", { code: $("#c-code").value.trim() });
    document.querySelector(".owner-confirm")?.remove();
    const again = retry;
    retry = null;
    if (again) await guarded(again);
  });
});

document.addEventListener("click", (e) => {
  if (e.target.closest("[data-act='confirm-cancel']")) { document.querySelector(".owner-confirm")?.remove(); retry = null; }
});

on(root, "click", "[data-tab]", (_e, b) => show(b.dataset.tab));
on(root, "change", "#activity-filter", (e) => { cache.activityFilter = e.target.value; show("activity"); });
on(root, "click", "[data-reset]", (_e, b) => guarded(async () => {
  await call("PUT", "/api/owner/console/config", { values: { [b.dataset.reset]: null } });
  toast("Back to the deployment's value", "success");
  await show(tab);
}));
on(root, "click", "[data-act]", async (_e, b) => {
  const act = b.dataset.act;
  if (act === "logout") { await call("POST", "/api/owner/logout").catch(() => null); cache = {}; return start(); }
  if (act === "refresh") return show("overview");
  if (act === "copy-codes") { await navigator.clipboard?.writeText(reveal.codes.join("\n")); return toast("Copied", "success"); }
  if (act === "codes-saved") { reveal = null; return start(); }
  if (act === "test-email") return guarded(async () => toast(`Test email sent to ${(await call("POST", "/api/owner/console/test-email", {})).to}`, "success", 6000));
  if (act === "test-stripe") return guarded(async () => {
    const r = await call("POST", "/api/owner/console/test-stripe");
    toast(r.ok ? `Stripe works${r.plans_found.length ? `: prices found for ${r.plans_found.join(", ")}` : ""}` : `Stripe works, but these prices weren't found: ${r.plans_missing.join(", ")}`, r.ok ? "success" : "error", 8000);
  });
  if (act === "end-session") return guarded(async () => { await call("POST", "/api/owner/sessions/end", { id: b.dataset.id }); await show("security"); });
  if (act === "end-others") return guarded(async () => { const r = await call("POST", "/api/owner/sessions/end-others"); toast(`${r.ended} other session(s) signed out`, "success"); await show("security"); });
  if (act === "revoke-key") {
    if (!confirm("Revoke this key? Anything using it stops working.")) return;
    return guarded(async () => { await call("POST", `/api/owner/console/keys/${encodeURIComponent(b.dataset.id)}/revoke`); toast("Key revoked", "success"); await show("security"); });
  }
  if (act === "new-codes") return guarded(async () => { reveal = { codes: (await call("POST", "/api/owner/recovery-codes")).recovery_codes }; screenRecoveryCodes(); });
  if (act === "new-phone") return guarded(async () => {
    const r = await call("POST", "/api/owner/authenticator/start");
    shell(html`<div class="card card-pad" style="max-width:460px"><h2>Move to a new phone</h2><p class="muted small">Scan this with the authenticator app on your new phone, then enter the code it shows. Your old phone stops working.</p>
      <div class="owner-qr">${trusted(r.qr_svg)}</div><details class="small"><summary>Can't scan? Type this key</summary><p class="mono" style="word-break:break-all">${r.secret}</p></details>
      <form id="phone-form" style="display:grid;gap:8px;margin-top:10px"><input class="input mono" id="np-code" inputmode="numeric" maxlength="6" required aria-label="Code from the new phone"><button class="btn primary" type="submit">Use this phone</button></form></div>`);
    $("#phone-form").addEventListener("submit", (ev) => {
      ev.preventDefault();
      guarded(async () => { await call("POST", "/api/owner/authenticator/finish", { code: $("#np-code").value.trim() }); toast("Your new phone is set up", "success"); await show("security"); });
    });
  });
});

start();
