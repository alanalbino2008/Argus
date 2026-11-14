// Argus web app entry point: sign-in, routing, top bar, shortcuts and cross-view actions.

import { api, clearKey, download, enc, storeKey, whoAmI } from "./api.js";
import { $, $$, closeTopModal, openModal, setHTML, setupModals, toast, trusted } from "./dom.js";
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
function showSignIn(message = "") {
  $("#signin").hidden = false;
  $("#signin-error").textContent = message;
  setTimeout(() => $("#signin-key").focus(), 50);
}

async function enterApp(me) {
  state.me = me;
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
  $("#btn-user").addEventListener("click", () => {
    clearKey();
    clearInterval(pollTimer);
    closeInvestigation();
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

  const me = await whoAmI();
  if (me) await enterApp(me);
  else showSignIn();
}

boot();
