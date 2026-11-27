// Guided first scan: choose a target -> check it's OK -> choose how -> watch it run.
// Every step explains *why*, so a newcomer learns how to scan responsibly, not just which
// buttons to press. The pre-flight check runs on the server, so the guidance matches what
// will really happen (which sources run, which contact the target, what the warnings are).

import { api, enc } from "../api.js";
import { ico } from "../components.js";
import { $, closeModal, html, openModal, setHTML, toast } from "../dom.js";
import { emit, state } from "../state.js";

const STEPS = ["Target", "Check", "How", "Run"];
const TIPS = [
  "Certificate Transparency logs record every TLS certificate issued — a quiet way to find subdomains, used by attackers and defenders alike.",
  "Passive reconnaissance never touches the target: everything comes from DNS, public registries and third-party databases.",
  "Each finding becomes a node in the graph; Argus then chains findings into attack paths an adversary could realistically follow.",
  "Attack paths are mapped to MITRE ATT&CK, the industry's shared vocabulary for adversary behaviour.",
  "A DMARC policy of p=reject stops attackers sending email that pretends to come from your domain.",
];

let actions;
let g = null; // wizard state

const fresh = () => ({ step: 0, target: "", preflight: null, passive: true, depth: 2, purpose: "Learning: first scan of a domain I own", authorised: false, writtenPermission: false, invId: null, poll: null, inv: null, paths: null, error: "", tip: 0 });

export function openGuide(appActions, target = "") {
  actions = appActions || actions;
  stopPolling();
  g = fresh();
  g.target = target;
  render();
  openModal("guide-modal");
  setTimeout(() => $("#guide-target")?.focus(), 80);
}

function stopPolling() {
  if (g?.poll) clearInterval(g.poll);
  if (g) g.poll = null;
}

function stepper() {
  setHTML($("#guide-steps"), html`${STEPS.map((label, i) => html`<li class="${i === g.step ? "on" : i < g.step ? "done" : ""}" ${i === g.step ? html`aria-current="step"` : ""}><span class="dot">${i < g.step ? "✓" : i + 1}</span>${label}</li>`)}`);
}

function render() {
  stepper();
  const views = [stepTarget, stepCheck, stepHow, stepRun];
  const [body, foot] = views[g.step]();
  setHTML($("#guide-body"), body);
  setHTML($("#guide-foot"), foot);
}

// ------------------------------------------------------------------ 1. target
function stepTarget() {
  return [html`
    <p style="margin-top:0">Argus maps what anyone on the internet can learn about a target. Even though it uses public sources, <b>only scan what you're allowed to</b>.</p>
    <div class="guide-ok">
      <div class="yes"><h4>${ico("check")}Good first targets</h4><ul>
        <li>A domain you own (a personal site or portfolio)</li>
        <li>Your employer's domain, with written permission</li>
        <li>A bug bounty programme's in-scope assets</li>
        <li>A CTF or lab target meant for practice</li></ul></div>
      <div class="no"><h4>${ico("x")}Not without permission</h4><ul>
        <li>Big companies "just to see"</li>
        <li>Government, police or NHS sites</li>
        <li>Your university, school or a friend's site</li>
        <li>Individuals, without a lawful reason</li></ul></div>
    </div>
    <div class="field">
      <label class="label" for="guide-target">What would you like to scan?</label>
      <input id="guide-target" class="input" value="${g.target}" placeholder="yourdomain.com" autocomplete="off" spellcheck="false">
      <div class="hint">A domain works best for a first scan. Nothing is scanned until the last step.</div>
    </div>
    <div class="error-text" role="alert">${g.error}</div>
    <p class="muted small">No domain of your own? <button type="button" class="btn sm ghost" data-g="demo">${ico("sparkle")}Explore the demo instead</button> — a fictional company, nothing is scanned.</p>`,
  html`<button type="button" class="btn" data-close>Cancel</button><button type="button" class="btn primary" data-g="check">Check this target</button>`];
}

// ------------------------------------------------------------------ 2. check
function stepCheck() {
  const p = g.preflight;
  if (!p.allowed) {
    return [html`<div class="guide-warning danger">${ico("alert")}<div><b>Argus won't scan this.</b><br>${p.blocked_reason}. Scanning private or internal addresses from a server can be abused to attack the network it runs in (server-side request forgery), so it is blocked.</div></div>`,
      html`<button type="button" class="btn" data-g="back">Choose another target</button>`];
  }
  const danger = p.warnings.some((w) => w.level === "danger");
  const icons = { danger: "alert", warning: "alert", info: "info" };
  return [html`
    <p style="margin-top:0"><b>${p.target}</b> looks like ${p.type_label}.</p>
    ${p.warnings.filter((w) => w.code !== "active_contact").map((w) => html`<div class="guide-warning ${w.level}">${ico(icons[w.level])}<div><b>${w.title}</b><br>${w.message}</div></div>`)}
    ${p.warnings.length ? "" : html`<div class="guide-warning info">${ico("check")}<div><b>Nothing unusual about this target.</b><br>Just make sure it's yours, or that you have permission.</div></div>`}
    ${p.recent ? html`<div class="guide-warning info">${ico("history")}<div>This workspace scanned ${p.target} recently. <button type="button" class="btn sm ghost" data-g="open-recent">Open that scan</button></div></div>` : ""}
    <div class="field" style="margin-top:14px">
      <label class="label" for="guide-purpose">Why are you scanning it? <span class="muted small">(recorded in the audit log)</span></label>
      <input id="guide-purpose" class="input" maxlength="500" value="${g.purpose}" placeholder="e.g. Acme bug bounty programme (HackerOne), in-scope asset">
    </div>
    <div class="field">
      <label class="check"><input type="checkbox" id="guide-authorised" ${g.authorised ? "checked" : ""}> <span>I own <b>${p.target}</b>, or I have permission from its owner to assess it.</span></label>
      ${danger ? html`<label class="check"><input type="checkbox" id="guide-written" ${g.writtenPermission ? "checked" : ""}> <span>I have <b>written</b> authorisation (for example, it is in a bug bounty programme's scope) and I will follow its rules.</span></label>` : ""}
    </div>
    <div class="error-text" role="alert">${g.error}</div>`,
  html`<button type="button" class="btn" data-g="back">Back</button><button type="button" class="btn primary" data-g="how">Continue</button>`];
}

// ------------------------------------------------------------------ 3. how
function stepHow() {
  const s = g.preflight.sources;
  const active = s.active.length;
  return [html`
    <p style="margin-top:0">How should Argus gather information?</p>
    <div class="guide-modes" role="radiogroup" aria-label="Scan mode">
      <button type="button" class="guide-mode" role="radio" aria-checked="${g.passive}" data-g="passive"><b>${ico("eye")} Passive (recommended)</b><small>Only public sources — DNS, certificate logs, registries, archives, breach databases. The target never sees a request from Argus.</small></button>
      <button type="button" class="guide-mode" role="radio" aria-checked="${!g.passive}" data-g="standard"><b>${ico("shield")} Standard</b><small>Passive sources plus ${active} light check${active === 1 ? "" : "s"} that contact the target directly — a TLS handshake and an ordinary web request. No attacks, no password guessing.</small></button>
    </div>
    <div class="field">
      <span class="label">How far should it follow leads?</span>
      <div class="segmented" role="radiogroup" aria-label="Depth">
        <button type="button" role="radio" aria-checked="${g.depth === 1}" class="${g.depth === 1 ? "active" : ""}" data-g="depth1">Focused — direct findings</button>
        <button type="button" role="radio" aria-checked="${g.depth === 2}" class="${g.depth === 2 ? "active" : ""}" data-g="depth2">Thorough — findings about findings</button>
      </div>
    </div>
    <p class="guide-tip">${g.passive ? s.passive.length : s.passive.length + active} sources will be consulted${s.needs_key.length ? html` (${s.needs_key.length} more need API keys, which an administrator can add)` : ""}. A first scan usually takes one to three minutes.</p>`,
  html`<button type="button" class="btn" data-g="back">Back</button><button type="button" class="btn primary" data-g="start">${ico("plus")}Start the scan</button>`];
}

// ------------------------------------------------------------------ 4. run
function stepRun() {
  const inv = g.inv;
  const done = inv && !["running", "initializing", "paused"].includes(inv.status);
  const describe = Object.fromEntries([...g.preflight.sources.passive, ...g.preflight.sources.active].map((m) => [m.name, m.description]));
  const consulted = Object.entries(inv?.module_stats || {}).filter(([, s]) => (s.runs || 0) > 0);
  if (!done) {
    return [html`
      <p style="margin-top:0">${ico("sparkle")} Scanning <b>${g.preflight.target}</b>${g.passive ? " passively" : ""}…</p>
      <div class="guide-live">
        <div><b>${inv?.node_count ?? 0}</b><span class="muted small">things found</span></div>
        <div><b>${inv?.edge_count ?? 0}</b><span class="muted small">connections</span></div>
        <div><b>${consulted.length}</b><span class="muted small">sources consulted</span></div>
      </div>
      <ul class="guide-sources">${consulted.slice(-8).reverse().map(([name]) => html`<li><b>${name.replaceAll("_", " ")}</b>${describe[name] || ""}</li>`)}</ul>
      <p class="guide-tip">${ico("info")} ${TIPS[g.tip % TIPS.length]}</p>`,
    html`<button type="button" class="btn" data-g="background">Continue in the background</button>`];
  }
  const sev = g.paths?.summary?.by_severity || {};
  const top = g.paths?.paths?.[0];
  const ok = inv.status === "completed";
  return [html`
    <p style="margin-top:0">${ok ? html`${ico("check")} <b>Scan complete.</b>` : html`<b>The scan ended: ${inv.status}.</b>`} Here's what an attacker could learn about <b>${g.preflight.target}</b>:</p>
    <div class="guide-live">
      <div><b>${inv.node_count}</b><span class="muted small">things found</span></div>
      <div><b>${g.paths?.summary?.total ?? 0}</b><span class="muted small">attack paths</span></div>
      <div><b style="color:var(--sev-critical-text)">${(sev.critical || 0) + (sev.high || 0)}</b><span class="muted small">critical or high</span></div>
    </div>
    ${top ? html`<div class="guide-warning ${["critical", "high"].includes(top.severity) ? "danger" : "info"}">${ico("paths")}<div><b>Most important: ${top.title}</b><br>${top.narrative}<br><span class="muted small">First fix: ${top.remediation?.[0] || "see the attack path"}</span></div></div>`
      : html`<div class="guide-warning info">${ico("check")}<div><b>No attack paths found.</b><br>That's a good sign. The graph still shows everything that's publicly discoverable.</div></div>`}
    <p class="muted small">Next steps: explore the attack paths, keep watching the target so you're alerted when it changes, or turn this into a client-ready PDF report.</p>`,
  html`<button type="button" class="btn" data-g="watch">${ico("eye")}Keep watching it</button><button type="button" class="btn" data-g="report">${ico("report")}Get the report</button><button type="button" class="btn primary" data-g="paths">See the attack paths</button>`];
}

// ------------------------------------------------------------------ behaviour
async function check() {
  g.target = $("#guide-target").value.trim();
  if (!g.target) { g.error = "Enter a target — or explore the demo."; return render(); }
  g.error = "";
  try {
    // passive_only=false: list every source, so step 3 can explain both modes.
    g.preflight = await api.post("/api/scan/preflight", { target: g.target, passive_only: false });
    g.authorised = false;
    g.writtenPermission = false;
    // A sensitive target needs a real reason, not the "my own domain" default.
    if (g.preflight.warnings.some((w) => w.level === "danger")) g.purpose = "";
    else if (!g.purpose) g.purpose = fresh().purpose;
    g.step = 1;
  } catch (err) {
    g.error = err.message;
  }
  render();
}

async function start() {
  try {
    const { investigation_id: id } = await api.post("/api/scan", {
      target: g.preflight.target, target_type: g.preflight.target_type, max_depth: g.depth,
      passive_only: g.passive, purpose: g.purpose, authorized: true,
    });
    g.invId = id;
    g.step = 3;
    emit("history-changed");
    render();
    g.poll = setInterval(pollRun, 1500);
  } catch (err) {
    toast(`Couldn't start: ${err.message}`, "error", 6000);
  }
}

async function pollRun() {
  if (!g?.invId) return;
  try {
    g.inv = await api.get(`/api/investigation/${enc(g.invId)}`);
  } catch {
    return;
  }
  g.tip += 1;
  if (!["running", "initializing", "paused"].includes(g.inv.status)) {
    stopPolling();
    g.paths = await api.get(`/api/investigation/${enc(g.invId)}/paths`).catch(() => null);
    emit("history-changed");
    emit("onboarding-changed");
  }
  if ($("#guide-modal").classList.contains("open")) render();
}

export function initGuide(appActions) {
  actions = appActions;
  const modal = $("#guide-modal");
  modal.addEventListener("modal-closed", () => {
    if (g?.poll && g.step === 3) toast("The scan continues — find it in History", "info");
    stopPolling();
  });
  modal.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.target.id === "guide-target") { e.preventDefault(); check(); }
  });
  modal.addEventListener("click", async (e) => {
    const btn = e.target.closest("[data-g]");
    if (!btn || !g) return;
    const act = btn.dataset.g;
    if (act === "check") return check();
    if (act === "back") { g.step = Math.max(0, g.step - 1); g.error = ""; return render(); }
    if (act === "demo") { closeModal("guide-modal"); return actions.loadDemo(); }
    if (act === "open-recent") { closeModal("guide-modal"); return actions.open(g.preflight.recent.id); }
    if (act === "how") {
      g.purpose = $("#guide-purpose").value.trim();
      g.authorised = $("#guide-authorised").checked;
      g.writtenPermission = $("#guide-written")?.checked ?? true;
      if (g.purpose.length < 5) { g.error = "Say briefly why you're scanning it (at least 5 characters)."; return render(); }
      if (!g.authorised || !g.writtenPermission) { g.error = "Confirm you're allowed to assess this target to continue."; return render(); }
      g.error = "";
      g.step = 2;
      return render();
    }
    if (act === "passive" || act === "standard") { g.passive = act === "passive"; return render(); }
    if (act === "depth1" || act === "depth2") { g.depth = act === "depth1" ? 1 : 2; return render(); }
    if (act === "start") { btn.disabled = true; return start(); }
    if (act === "background") return closeModal("guide-modal");
    const id = g.invId;
    closeModal("guide-modal");
    if (act === "paths") return actions.open(id, { view: "paths" });
    if (act === "report") { await actions.open(id); return actions.report(); }
    if (act === "watch") return actions.newInvestigation({ target: g.preflight.target, type: g.preflight.target_type, watch: true });
  });
}

// ------------------------------------------------------------------ getting-started checklist
const CHECKLIST = {
  demo: ["Explore the demo", "A fictional company with a realistic attack surface — nothing is scanned.", "loadDemo"],
  first_scan: ["Run your first scan", "Guided, step by step, with checks that keep you on the right side of the law.", "guide"],
  paths: ["Review the attack paths", "See how findings chain into routes an attacker could take, ranked by risk.", "goPaths"],
  watch: ["Keep watching a target", "Re-scan on a schedule and get alerted when something important changes.", "goMonitoring"],
  destination: ["Send alerts somewhere", "Slack, Microsoft Teams, email or your own systems.", "goMonitoring"],
  report: ["Create a client report", "A branded, verifiable PDF from any finished scan.", "report"],
  schedule: ["Schedule a report", "Send it automatically, every week or month.", "goMonitoring"],
};

const key = (name) => `argus.onboarding.${state.workspace?.id || "ws"}.${name}`;
const flag = (name) => { try { return localStorage.getItem(key(name)) === "1"; } catch { return false; } };
const setFlag = (name) => { try { localStorage.setItem(key(name), "1"); } catch { /* private mode */ } };

export function markPathsReviewed() {
  if (state.investigation) setFlag("paths");
}

export async function checklistCard() {
  if (flag("hidden")) return null;
  let data;
  try {
    data = await api.get("/api/onboarding");
  } catch {
    return null;
  }
  const steps = data.steps.filter((s) => s.available);
  steps.splice(2, 0, { id: "paths", done: flag("paths"), available: true });
  const done = steps.filter((s) => s.done).length;
  if (done === steps.length) return null;
  return { done, total: steps.length, latestId: data.latest_id, render: () => html`
    <div class="card card-pad" style="margin-top:16px" id="checklist">
      <div class="card-head">
        <div><h2>Getting started</h2><p class="muted small">${done} of ${steps.length} done — each step takes a minute or two.</p></div>
        <button class="btn ghost sm" data-action="hideChecklist">Hide</button>
      </div>
      <div class="progress" role="progressbar" aria-label="Getting started: steps done" aria-valuemin="0" aria-valuemax="${steps.length}" aria-valuenow="${done}"><span style="width:${Math.round((done / steps.length) * 100)}%"></span></div>
      <div class="checklist">${steps.map((s) => {
        const [title, text, action] = CHECKLIST[s.id];
        return html`<div class="checklist-row ${s.done ? "done" : ""}"><span class="tick">${s.done ? ico("check") : ""}</span>
          <div class="what"><b>${title}</b><div>${text}</div></div>
          ${s.done ? "" : html`<button class="btn sm ${s.id === "first_scan" ? "primary" : ""}" data-action="checklist" data-step="${s.id}" data-act="${action}">${s.id === "first_scan" ? "Start" : "Go"}</button>`}</div>`;
      })}</div>
    </div>` };
}

export function hideChecklist() {
  setFlag("hidden");
}
