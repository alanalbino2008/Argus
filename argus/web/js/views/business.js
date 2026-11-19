// The business dashboard (account service operators): customers, revenue, sign-ups, credits,
// who needs attention, and every account, with the tools to look after them.

import { api, download, enc } from "../api.js";
import { empty, ico } from "../components.js";
import { confirmDialog, formatDate, formatDay, html, on, setHTML, timeAgo, toast } from "../dom.js";

let root;
let days = 30;
let data = null;
let list = null;
let query = { q: "", status: "", plan: "" };
let selected = null; // the account open in the detail card
let searchTimer = null;

const STATUS = { trialing: ["accent", "Trial"], active: ["ok", "Active"], past_due: ["warn", "Payment due"], cancelled: ["", "Cancelled"], suspended: ["critical", "Suspended"] };
const PLAN = { trial: "Free trial", personal: "Personal", professional: "Professional" };
const statusPill = (s) => html`<span class="pill ${(STATUS[s] || [""])[0]}">${(STATUS[s] || ["", s])[1]}</span>`;

function money(amount, currency) {
  if (amount == null || !currency) return "—";
  return new Intl.NumberFormat(undefined, { style: "currency", currency, maximumFractionDigits: amount % 100 ? 2 : 0 }).format(amount / 100);
}

const kpi = (label, value, sub = "") => html`<div class="card kpi"><div class="kpi-label">${label}</div><div class="kpi-value">${value}</div>${sub ? html`<div class="kpi-sub">${sub}</div>` : ""}</div>`;

// Sign-ups per week: one series, thin bars on a shared baseline, a tooltip on each bar.
function signupChart(weeks) {
  const max = Math.max(1, ...weeks.map((w) => w.accounts));
  const W = 600, H = 150, pad = 22, gap = 2;
  const bw = (W - 2 * pad) / weeks.length - gap;
  const y = (n) => H - pad - (n / max) * (H - 2 * pad);
  const bars = weeks.map((w, i) => {
    const x = pad + i * (bw + gap);
    const top = y(w.accounts);
    const h = H - pad - top;
    const tip = `Week of ${formatDay(w.week)}: ${w.accounts} new account${w.accounts === 1 ? "" : "s"}, ${w.paying} now paying`;
    return html`<g class="bar-hit" tabindex="0" aria-label="${tip}"><title>${tip}</title>
      <rect x="${x}" y="${pad}" width="${bw}" height="${H - 2 * pad}" fill="transparent"></rect>
      ${h > 0 ? html`<path d="M${x},${H - pad} V${top + Math.min(4, h)} Q${x},${top} ${x + Math.min(4, bw / 2)},${top} H${x + bw - Math.min(4, bw / 2)} Q${x + bw},${top} ${x + bw},${top + Math.min(4, h)} V${H - pad} Z" fill="var(--accent)"></path>` : ""}
    </g>`;
  });
  const labels = [0, weeks.length - 1].map((i) => html`<text x="${pad + i * (bw + gap) + bw / 2}" y="${H - 6}" text-anchor="middle" class="chart-axis">${formatDay(weeks[i].week)}</text>`);
  return html`<svg viewBox="0 0 ${W} ${H}" class="biz-chart" role="img" aria-label="New accounts per week, last 12 weeks">
    <line x1="${pad}" x2="${W - pad}" y1="${H - pad}" y2="${H - pad}" stroke="var(--border)" stroke-width="1"></line>
    <text x="${pad}" y="${pad - 8}" class="chart-axis">${max}</text>
    ${bars}${labels}</svg>`;
}

function sourceBars(rows) {
  const max = Math.max(1, ...rows.map((r) => r.credits));
  return html`<table class="table"><tbody>${rows.map((r) => html`<tr>
    <td style="width:40%">${r.label}</td>
    <td><div class="biz-bar"><span style="width:${Math.max(2, (r.credits / max) * 100)}%"></span></div></td>
    <td class="mono" style="text-align:right;width:70px">${r.credits}</td></tr>`)}</tbody></table>`;
}

function attentionCard(rows) {
  return html`<div class="card card-pad">
    <div class="card-head"><div><h2>Needs attention</h2><p class="muted small">Customers to help or follow up with.</p></div></div>
    ${rows.length ? html`<table class="table"><tbody>${rows.map((a) => html`<tr class="clickable" data-open="${a.id}">
      <td><b>${a.email}</b><div class="muted small">${PLAN[a.plan] || a.plan}</div></td>
      <td><span class="pill ${a.why === "payment failing" || a.why.startsWith("locked") ? "warn" : ""}">${a.why}</span></td>
      <td class="muted small">${a.valid_until ? formatDay(a.valid_until) : ""}</td></tr>`)}</tbody></table>`
      : html`<p class="muted">${ico("check")} Nothing needs attention.</p>`}
  </div>`;
}

function detailCard() {
  const a = selected;
  if (!a) return "";
  const c = a.credits || {};
  return html`<div class="card card-pad" id="biz-account" style="margin-top:16px">
    <div class="card-head wrap"><div><h2>${a.email}</h2><p class="muted small">${a.name || "No name"} · ${a.id} · joined ${formatDate(a.created_at)}${a.last_login_at ? ` · last signed in ${timeAgo(a.last_login_at)}` : ""}</p></div>
      <button class="btn sm ghost" data-act="close">${ico("x")}Close</button></div>
    <div class="grid two" style="align-items:start">
      <div>
        <dl class="kv"><dt>Plan</dt><dd>${PLAN[a.plan] || a.plan} ${statusPill(a.status)}</dd>
          <dt>${a.status === "trialing" ? "Trial ends" : "Paid until"}</dt><dd>${a.valid_until ? formatDate(a.valid_until) : "—"}</dd>
          <dt>Stripe customer</dt><dd class="mono small">${a.billing_reference || "—"}</dd>
          <dt>Credits</dt><dd><b>${c.available ?? "—"}</b> available (${c.allowance_remaining ?? 0} of this month's ${c.allowance ?? 0}, ${c.purchased ?? 0} bought)</dd></dl>
        <form id="biz-plan" class="filters" style="margin-top:12px">
          <select class="select" id="biz-plan-plan" aria-label="Plan" style="max-width:160px">${Object.entries(PLAN).map(([k, l]) => html`<option value="${k}" ${k === a.plan ? "selected" : ""}>${l}</option>`)}</select>
          <select class="select" id="biz-plan-status" aria-label="Status" style="max-width:160px">${Object.entries(STATUS).map(([k, [, l]]) => html`<option value="${k}" ${k === a.status ? "selected" : ""}>${l}</option>`)}</select>
          <input class="input" type="date" id="biz-plan-until" aria-label="Paid until" style="max-width:170px" value="${(a.valid_until || "").slice(0, 10)}">
          <button class="btn sm" type="submit">Save</button>
        </form>
        <p class="muted small">Payments update this automatically; change it by hand only to correct something or give a free extension. Stripe stays the record of what was paid.</p>
        <form id="biz-credits" class="filters" style="margin-top:12px">
          <input class="input" type="number" id="biz-credits-amount" placeholder="Credits (+ or -)" min="-1000000" max="1000000" required style="max-width:150px">
          <input class="input" id="biz-credits-why" placeholder="Reason (kept in the ledger)" maxlength="200" required style="max-width:260px">
          <button class="btn sm" type="submit">${ico("plus")}Adjust credits</button>
        </form>
      </div>
      <div>
        <div class="section-title">Computers</div>
        ${(a.device_list || []).length ? html`<table class="table"><tbody>${a.device_list.map((d) => html`<tr style="${d.revoked ? "opacity:.5" : ""}">
          <td>${d.name || d.device_id.slice(0, 10)}<div class="muted small">last seen ${timeAgo(d.last_seen)}</div></td>
          <td class="actions">${d.revoked ? html`<span class="pill">signed out</span>` : html`<button class="btn sm ghost danger" data-act="device-out" data-id="${d.device_id}">Sign out</button>`}</td></tr>`)}</tbody></table>` : html`<p class="muted small">Never signed in.</p>`}
        <div class="section-title" style="margin-top:12px">Emails</div>
        <p class="muted small" style="margin:0 0 6px">Reminder emails: <b>${a.reminder_emails ? "on" : "off (unsubscribed)"}</b>. Emails about the account itself are always sent.</p>
        ${(a.emails || []).length ? html`<table class="table"><tbody>${a.emails.slice(0, 10).map((m) => html`<tr>
          <td class="muted small">${formatDate(m.sent_at || m.created_at)}</td><td class="small">${m.subject}</td>
          <td><span class="pill ${m.status === "sent" ? "ok" : m.status === "failed" ? "critical" : ""}" title="${m.error || ""}">${m.status}</span></td></tr>`)}</tbody></table>` : html`<p class="muted small">No emails yet.</p>`}
        <div class="section-title" style="margin-top:12px">Credit history</div>
        ${(c.ledger || []).length ? html`<table class="table"><tbody>${c.ledger.slice(0, 15).map((e) => html`<tr>
          <td class="muted small">${formatDate(e.at)}</td><td>${e.kind}</td><td class="small">${e.detail}</td>
          <td class="mono" style="text-align:right">${e.delta > 0 ? "+" : ""}${e.delta}</td></tr>`)}</tbody></table>` : html`<p class="muted small">No credit movements yet.</p>`}
      </div>
    </div>
  </div>`;
}

function accountsCard() {
  const rows = list?.accounts || [];
  return html`<div class="card card-pad" style="margin-top:16px">
    <div class="card-head wrap"><div><h2>Accounts</h2><p class="muted small">${list ? `${list.total} account${list.total === 1 ? "" : "s"}` : "Loading…"}${list && list.total > rows.length ? `, showing the newest ${rows.length}` : ""}. Click one to see and change it.</p></div>
      <button class="btn sm" data-act="csv">${ico("download")}Download CSV</button></div>
    <div class="filters" style="margin-bottom:12px">
      <input class="input" id="biz-q" placeholder="Search email, name, account or Stripe id" value="${query.q}" style="max-width:320px" aria-label="Search accounts">
      <select class="select" id="biz-status" aria-label="Status" style="max-width:170px"><option value="">Any status</option>${Object.entries(STATUS).map(([k, [, l]]) => html`<option value="${k}" ${k === query.status ? "selected" : ""}>${l}</option>`)}</select>
      <select class="select" id="biz-plan-filter" aria-label="Plan" style="max-width:170px"><option value="">Any plan</option>${Object.entries(PLAN).map(([k, l]) => html`<option value="${k}" ${k === query.plan ? "selected" : ""}>${l}</option>`)}</select>
    </div>
    ${rows.length ? html`<div class="table-wrap"><table class="table"><thead><tr><th>Account</th><th>Plan</th><th>Paid until</th><th>Computers</th><th>Joined</th><th>Last sign-in</th></tr></thead><tbody>
      ${rows.map((a) => html`<tr class="clickable" data-open="${a.id}">
        <td><b>${a.email}</b>${a.name ? html`<div class="muted small">${a.name}</div>` : ""}</td>
        <td>${PLAN[a.plan] || a.plan} ${statusPill(a.status)}</td>
        <td>${a.valid_until ? formatDay(a.valid_until) : "—"}</td>
        <td>${a.max_devices}</td>
        <td>${formatDay(a.created_at)}</td>
        <td>${a.last_login_at ? timeAgo(a.last_login_at) : "never"}</td></tr>`)}</tbody></table></div>`
      : html`<p class="muted">${list ? "No accounts match." : ""}</p>`}
  </div>`;
}

function render() {
  if (!data) return setHTML(root, html`<div class="page"><p class="muted">Loading…</p></div>`);
  const d = data;
  const c = d.customers;
  const mrr = d.mrr;
  const mrrText = mrr.currency ? money(mrr.amount, mrr.currency) : c.paying ? "—" : money(0, "USD");
  const conv = d.signups.conversion;
  const packs = d.credits.pack_sales;
  const packRevenue = packs.filter((p) => p.revenue != null);
  const packCurrency = packRevenue[0]?.currency;
  setHTML(root, html`<div class="page">
    <div class="page-head">
      <div><h1>Business</h1><p>Your Argus customers at a glance: who pays, what it brings in, how people use their credits, and who needs a hand.</p></div>
      <div class="page-actions"><div class="segmented" role="tablist" aria-label="Period">${[30, 90, 365].map((n) => html`<button class="${days === n ? "active" : ""}" data-days="${n}">${n === 365 ? "12 months" : `${n} days`}</button>`)}</div></div>
    </div>
    ${d.payments_enabled ? "" : html`<div class="callout warn" style="margin-bottom:16px">${ico("info")}<span>Payments aren't set up on this account service yet, so revenue can't be shown. See "Payments with Stripe" in the deployment guide.</span></div>`}
    <div class="grid kpis">
      ${kpi("Paying customers", c.paying, Object.entries(c.plans).map(([p, n]) => `${n} ${PLAN[p] || p}`).join(" · ") || "none yet")}
      ${kpi("Monthly recurring revenue", mrrText, mrr.complete ? "from subscriptions, at Stripe's prices" : "some plans have no price in Stripe")}
      ${kpi("On free trial", c.trialing, conv == null ? "no finished trials yet" : `${Math.round(conv * 100)}% of finished trials became paying`)}
      ${kpi("Payment due", c.past_due, c.past_due ? "Stripe is retrying their card" : "all payments up to date")}
    </div>
    <div class="grid two" style="align-items:start;margin-top:16px">
      <div class="card card-pad">
        <div class="card-head"><div><h2>New accounts per week</h2><p class="muted small">Last 12 weeks. Hover a bar for how many of them now pay.</p></div></div>
        ${signupChart(d.signups.weeks)}
        <details style="margin-top:6px"><summary class="small muted">As a table</summary><table class="table"><thead><tr><th>Week of</th><th>New accounts</th><th>Now paying</th></tr></thead><tbody>${d.signups.weeks.map((w) => html`<tr><td>${formatDay(w.week)}</td><td>${w.accounts}</td><td>${w.paying}</td></tr>`)}</tbody></table></details>
      </div>
      ${attentionCard(d.attention)}
    </div>
    <div class="grid two" style="align-items:start;margin-top:16px">
      <div class="card card-pad">
        <div class="card-head"><div><h2>Credits used</h2><p class="muted small">Last ${d.period_days} days, by source: <b>${d.credits.used}</b> credits. Refunded lookups (failed or found nothing) don't count.</p></div></div>
        ${d.credits.by_source.length ? sourceBars(d.credits.by_source) : empty("sparkle", "No credits used yet", "Lookups through Argus Connect will show here.")}
        ${d.credits.top_accounts.length ? html`<div class="section-title" style="margin-top:12px">Using the most</div><table class="table"><tbody>${d.credits.top_accounts.map((t) => html`<tr class="clickable" data-open="${t.id}"><td>${t.email}</td><td class="mono" style="text-align:right">${t.credits}</td></tr>`)}</tbody></table>` : ""}
      </div>
      <div class="card card-pad">
        <div class="card-head"><div><h2>Credit packs sold</h2><p class="muted small">Last ${d.period_days} days: <b>${d.credits.bought}</b> credits bought${packRevenue.length && packCurrency ? `, about ${money(packRevenue.reduce((s, p) => s + p.revenue, 0), packCurrency)} at today's prices` : ""}.</p></div></div>
        ${packs.length ? html`<table class="table"><thead><tr><th>Pack</th><th>Sold</th><th>Takings</th></tr></thead><tbody>${packs.map((p) => html`<tr><td>${p.credits} credits</td><td>${p.sold}</td><td>${money(p.revenue, p.currency)}</td></tr>`)}</tbody></table>` : html`<p class="muted">No credit packs sold in this period.</p>`}
        <p class="muted small" style="margin-top:8px">Stripe's dashboard is the record of what was actually paid, refunded and paid out; these figures are for steering.</p>
      </div>
    </div>
    ${detailCard()}
    ${accountsCard()}
  </div>`);
}

async function loadList() {
  const params = new URLSearchParams(Object.entries(query).filter(([, v]) => v));
  list = await api.get(`/api/business/accounts?${params}`).catch(() => null);
  render();
}

async function openAccount(id) {
  try {
    const [account, credits] = await Promise.all([api.get(`/api/accounts/${enc(id)}`), api.get(`/api/accounts/${enc(id)}/credits`)]);
    selected = { ...account, credits };
    render();
    root.querySelector("#biz-account")?.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (err) {
    toast(err.message, "error");
  }
}

export async function refreshBusiness() {
  if (!root) return;
  try {
    data = await api.get(`/api/business/summary?days=${days}`);
  } catch (err) {
    return setHTML(root, html`<div class="page">${empty("alert", "The business dashboard isn't available", err.message)}</div>`);
  }
  render();
  loadList();
}

export function initBusiness(el) {
  root = el;
  on(root, "click", "[data-days]", (_e, btn) => { days = Number(btn.dataset.days); refreshBusiness(); });
  on(root, "click", "[data-open]", (_e, row) => openAccount(row.dataset.open));
  on(root, "click", "[data-act]", async (_e, btn) => {
    const { act, id } = btn.dataset;
    try {
      if (act === "close") { selected = null; render(); }
      if (act === "csv") {
        const params = new URLSearchParams(Object.entries(query).filter(([, v]) => v));
        await download(`/api/business/accounts.csv?${params}`, `argus-accounts-${new Date().toISOString().slice(0, 10)}.csv`);
      }
      if (act === "device-out") {
        const ok = await confirmDialog({ title: "Sign this computer out?", message: "It frees a place on the account. The person keeps their cases and can sign in again.", confirm: "Sign out", danger: true });
        if (!ok) return;
        await api.del(`/api/accounts/${enc(selected.id)}/devices/${enc(id)}`);
        toast("Computer signed out", "success");
        await openAccount(selected.id);
      }
    } catch (err) {
      toast(err.message, "error");
    }
  });
  root.addEventListener("input", (e) => {
    if (e.target.id !== "biz-q") return;
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { query.q = e.target.value; loadList().then(() => { const q = root.querySelector("#biz-q"); q?.focus(); q?.setSelectionRange(q.value.length, q.value.length); }); }, 300);
  });
  root.addEventListener("change", (e) => {
    if (e.target.id === "biz-status") { query.status = e.target.value; loadList(); }
    if (e.target.id === "biz-plan-filter") { query.plan = e.target.value; loadList(); }
  });
  root.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      if (e.target.id === "biz-plan") {
        const until = root.querySelector("#biz-plan-until").value;
        await api.patch(`/api/accounts/${enc(selected.id)}`, {
          plan: root.querySelector("#biz-plan-plan").value, status: root.querySelector("#biz-plan-status").value,
          ...(until ? { valid_until: `${until}T23:59:59Z` } : {}),
        });
        toast("Account updated: their Argus picks it up at its next check", "success", 5000);
      }
      if (e.target.id === "biz-credits") {
        const amount = Number(root.querySelector("#biz-credits-amount").value);
        if (!Number.isInteger(amount) || !amount) return toast("Enter a whole number of credits", "error");
        await api.post(`/api/accounts/${enc(selected.id)}/credits`, { amount, kind: "adjustment", detail: root.querySelector("#biz-credits-why").value.trim() });
        toast(`${amount > 0 ? "Added" : "Removed"} ${Math.abs(amount)} credits`, "success");
      }
      const id = selected.id;
      await refreshBusiness();
      await openAccount(id);
    } catch (err) {
      toast(err.message, "error");
    }
  });
}
