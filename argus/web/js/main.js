// Argus web app entry point: sign-in, routing, top bar, shortcuts and cross-view actions.

import { activeWorkspace, api, authConfig, clearKey, download, enc, endSession, setActiveWorkspace, storeKey, whoAmI } from "./api.js";
import { $, $$, closeTopModal, html, openModal, setHTML, setupModals, toast, trusted } from "./dom.js";
import * as graph from "./graph.js";
import { icon, installSprite } from "./icons.js";
import { closeInvestigation, openInvestigation, startScan, stopScan } from "./live.js";
import { emit, isRunning, on, state } from "./state.js";
import { initGraphView } from "./views/graphview.js";
import { initHistory, refresh as refreshHistory } from "./views/history.js";
import { initModals, openDiff, openNewInvestigation, openReport, startTour } from "./views/modals.js";
import { initMonitoring, refresh as refreshMonitoring } from "./views/monitoring.js";
import { initOverview } from "./views/overview.js";
import { initPaths } from "./views/paths.js";
import { initPeople, refresh as refreshPeople } from "./views/people.js";
import { initSettings, refresh as refreshSettings } from "./views/settings.js";

const VIEWS = ["overview", "graph", "paths", "people", "monitoring", "history", "settings"];
let currentView = null;
let pollTimer = null;

// ------------------------------------------------------------------ routing
function go(view) {
  if (location.hash !== `#/${view}`) location.hash = `#/${view}`;
  else route();
}

function route() {
  const view = VIEWS.find((v) => location.hash === `#/${v}`) || "overview";
  if (view === currentView) return;
  currentView = view;
  $$(".view").forEach((el) => el.classList.toggle("active", el.id === `view-${view}`));
  $$(".nav-item").forEach((el) => el.classList.toggle("active", el.dataset.view === view));
  if (view === "graph") setTimeout(graph.resizeCanvas, 50);
  if (view === "people") refreshPeople();
  if (view === "history") refreshHistory();
  if (view === "monitoring") refreshMonitoring();
  if (view === "settings") refreshSettings();
}

// ------------------------------------------------------------------ actions shared by views
const actions = {
  toast,
  async open(id, { view = "overview" } = {}) {
    await openInvestigation(id);
    go(view);
  },
  close() {
    closeInvestigation();
    go("overview");
  },
  newInvestigation: (opts) => openNewInvestigation(opts),
  async loadDemo() {
    try {
      const { investigation_id: id } = await api.post("/api/demo");
      toast("Demo loaded: a fictional company with a realistic attack surface", "success");
      emit("history-changed");
      await actions.open(id);
    } catch (err) {
      toast(err.status === 403 ? "Only administrators can load the demo" : err.message, "error");
    }
  },
  async startScan(body) {
    try {
      await startScan(body);
      go("graph");
    } catch (err) {
      toast(`Couldn't start: ${err.message}`, "error", 6000);
    }
  },
  showPath(path) {
    if (!path) return;
    go("graph");
    setTimeout(() => graph.highlightPath(path), 260);
    toast("Showing the attack path — press Esc to clear", "info", 2600);
  },
  openDiff: (inv, prev) => openDiff(inv, prev),
  compare: () => state.investigation && openDiff(state.investigation.id),
  watch: () => state.investigation && openNewInvestigation({ target: state.investigation.target, type: state.investigation.target_type, watch: true }),
  report: () => openReport(),
  goGraph: () => go("graph"),
  goPaths: () => go("paths"),
  goPeople: () => go("people"),
  goHistory: () => go("history"),
  exportStix: () => exportAs("stix", "stix.json"),
  exportNavigator: () => exportAs("navigator", "attack_layer.json"),
  exportCsv: () => exportAs("csv", "maltego.csv"),
  exportJson: () => exportAs("json", "graph.json"),
};

async function exportAs(kind, suffix) {
  const id = state.investigation?.id;
  if (!id) return;
  try {
    await download(`/api/investigation/${enc(id)}/export/${kind}`, `argus_${id}_${suffix}`);
  } catch (err) {
    toast(`Export failed: ${err.message}`, "error");
  }
}

// ------------------------------------------------------------------ top bar
function renderContext() {
  const inv = state.investigation;
  const status = $("#context-status");
  if (!inv) {
    status.hidden = true;
    $("#context-title").textContent = "No investigation open";
    $("#context-meta").textContent = "";
  } else {
    status.hidden = false;
    const cls = inv.status === "initializing" ? "running" : inv.status;
    status.className = `status ${cls}`;
    status.lastElementChild.textContent = { initializing: "Starting", running: "Scanning", completed: "Complete", failed: "Failed", cancelled: "Stopped" }[inv.status] || inv.status;
    $("#context-title").textContent = inv.target || "Loading…";
    $("#context-meta").textContent = `${state.entities.size} assets · ${state.relations.size} connections`;
  }
  const running = isRunning();
  $("#btn-stop").hidden = !running;
  $("#scan-progress").hidden = !running;
}

function renderBadges() {
  const alerts = $("#alerts-dot");
  alerts.textContent = state.alertsOpen;
  alerts.hidden = !state.alertsOpen;
  const urgent = state.paths ? state.paths.summary.by_severity.critical + state.paths.summary.by_severity.high : 0;
  const paths = $("#paths-dot");
  paths.textContent = urgent;
  paths.hidden = !urgent;
}

function renderThemeButton() {
  const dark = window.argusTheme.current() === "dark";
  setHTML($("#btn-theme"), trusted(icon(dark ? "sun" : "moon")));
}

// ------------------------------------------------------------------ keyboard
function setupShortcuts() {
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (!closeTopModal()) graph.clearHighlight();
      return;
    }
    const typing = ["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement?.tagName);
    if (typing || e.metaKey || e.ctrlKey || e.altKey || !$("#signin").hidden || $(".modal-root.open")) return;
    const map = { o: "overview", g: "graph", p: "paths", u: "people", m: "monitoring", h: "history" };
    if (map[e.key]) go(map[e.key]);
    else if (e.key === "n") { e.preventDefault(); actions.newInvestigation(); }
    else if (e.key === "/") { e.preventDefault(); go("graph"); setTimeout(() => $("#graph-search").focus(), 120); }
    else if (e.key === "f") graph.fit();
    else if (e.key === "t") window.argusTheme.toggle();
    else if (e.key === "?") openModal("shortcuts-modal");
  });
}

// ------------------------------------------------------------------ auth & boot
const SSO_ERRORS = {
  expired: "That sign-in link expired or was already used. Please try again.",
  provider_denied: "Sign-in was cancelled or refused by your identity provider.",
  unverified_email: "Your identity provider did not confirm your email address.",
  domain_not_allowed: "Your account's email domain is not allowed to use this Argus.",
  no_role: "Your account has no Argus role yet — ask an administrator to grant access.",
  disabled: "Your Argus account has been disabled by an administrator.",
  invalid_token: "The identity provider's response could not be verified. Please try again.",
  token_exchange_failed: "Sign-in could not be completed with the identity provider.",
  provider_unreachable: "The identity provider could not be reached. Try again shortly.",
  provider_misconfigured: "Single sign-on is misconfigured. Contact your administrator.",
};

async function setupSignInOptions() {
  const config = await authConfig();
  if (!config.sso?.enabled) return;
  $("#signin-sso").hidden = false;
  $("#signin-sso-name").textContent = `Continue with ${config.sso.name || "single sign-on"}`;
  $("#signin-key-hint").textContent = "For automation and break-glass access.";
  const returnTo = location.pathname + location.search.replace(/[?&]sso_error=[^&]*/, "") + location.hash;
  $("#signin-sso-link").href = `/auth/oidc/login?return_to=${encodeURIComponent(returnTo || "/")}`;
}

function takeSsoError() {
  const url = new URL(location.href);
  const code = url.searchParams.get("sso_error");
  if (!code) return "";
  url.searchParams.delete("sso_error");
  history.replaceState(null, "", url);
  return SSO_ERRORS[code] || "Single sign-on failed. Please try again.";
}

function showSignIn(message = "") {
  $("#signin").hidden = false;
  $("#signin-error").textContent = message;
  setTimeout(() => ($("#signin-sso").hidden ? $("#signin-key") : $("#signin-sso-link")).focus(), 50);
}

function chooseWorkspace(me) {
  const list = me.workspaces || [];
  const stored = activeWorkspace();
  const pick = list.find((w) => w.id === stored) || list.find((w) => w.default) || list[0];
  setActiveWorkspace(pick ? pick.id : "");
  state.workspace = pick || null;
  const sw = $("#workspace-switch");
  sw.hidden = list.length < 2;
  setHTML($("#workspace-select"), html`${list.map((w) => html`<option value="${w.id}" ${pick && w.id === pick.id ? "selected" : ""}>${w.name}</option>`)}`);
}

async function switchWorkspace(id) {
  setActiveWorkspace(id);
  state.workspace = (state.me?.workspaces || []).find((w) => w.id === id) || null;
  closeInvestigation(); // an investigation belongs to exactly one workspace
  emit("history-changed");
  emit("workspace", state.workspace);
  refreshMonitoring();
  go("overview");
  toast(`Switched to ${state.workspace?.name || "workspace"}`, "success", 2200);
}

async function enterApp(me) {
  state.me = me;
  const linkedWs = new URLSearchParams(location.search).get("ws"); // links in notifications name their workspace
  if (linkedWs && (me.workspaces || []).some((w) => w.id === linkedWs)) setActiveWorkspace(linkedWs);
  chooseWorkspace(me);
  $("#signin").hidden = true;
  $("#user-name").textContent = `${me.name}`;
  $("#btn-user").title = `Signed in as ${me.name} (${me.role}) — click to sign out`;
  refreshMonitoring();
  clearInterval(pollTimer);
  pollTimer = setInterval(refreshMonitoring, 60000);
  const deepLink = new URLSearchParams(location.search).get("inv");
  if (deepLink && state.investigation?.id !== deepLink) await openInvestigation(deepLink);
  route();
  startTour();
}

function setupAuth() {
  $("#signin-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const key = $("#signin-key").value.trim();
    const me = key ? await whoAmI(key) : null;
    if (!me) {
      $("#signin-error").textContent = "That key wasn't accepted. Check it and try again.";
      return;
    }
    storeKey(key);
    $("#signin-key").value = "";
    await enterApp(me);
  });
  $("#btn-user").addEventListener("click", async () => {
    const viaSession = state.me?.auth === "session";
    clearKey();
    clearInterval(pollTimer);
    closeInvestigation();
    if (viaSession) {
      const providerSignOut = await endSession();
      if (providerSignOut) {
        location.href = providerSignOut; // single logout at the identity provider
        return;
      }
    }
    showSignIn("You've been signed out.");
  });
  window.addEventListener("argus:auth-required", () => {
    clearKey();
    showSignIn("Your session ended or the key was revoked. Please sign in again.");
  });
}

async function boot() {
  installSprite();
  setupModals();
  setupAuth();
  setupShortcuts();
  initModals(actions);
  initGraphView(actions);
  initOverview($("#view-overview"), actions);
  initPaths($("#view-paths"), actions);
  initPeople($("#view-people"), actions);
  initMonitoring($("#view-monitoring"), actions);
  initHistory($("#view-history"), actions);
  initSettings($("#view-settings"));

  $$(".nav-item").forEach((el) => el.addEventListener("click", () => go(el.dataset.view)));
  $("#btn-new").addEventListener("click", () => actions.newInvestigation());
  $("#workspace-select").addEventListener("change", (e) => switchWorkspace(e.target.value));
  on("workspaces-changed", async () => { const me = await whoAmI(); if (me) { state.me = me; chooseWorkspace(me); } });
  $("#btn-stop").addEventListener("click", stopScan);
  $("#btn-theme").addEventListener("click", () => window.argusTheme.toggle());
  $("#btn-shortcuts").addEventListener("click", () => openModal("shortcuts-modal"));
  window.addEventListener("hashchange", route);
  document.addEventListener("argus:theme", renderThemeButton);

  ["investigation", "graph", "reset", "progress"].forEach((e) => on(e, renderContext));
  ["paths", "alerts", "reset"].forEach((e) => on(e, renderBadges));
  on("monitors-changed", refreshMonitoring);
  renderThemeButton();
  renderContext();

  const ssoError = takeSsoError();
  await setupSignInOptions();
  const me = await whoAmI();
  if (me) await enterApp(me);
  else showSignIn(ssoError);
}

boot();
