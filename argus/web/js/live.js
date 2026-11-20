// Opening investigations and following them live over a ticketed WebSocket.

import { api, enc } from "./api.js";
import { toast } from "./dom.js";
import * as graph from "./graph.js";
import { emit, pushFeed, resetInvestigation, state } from "./state.js";

let socket = null;

function setInvestigation(payload) {
  state.investigation = { ...(state.investigation || {}), ...payload };
  emit("investigation", state.investigation);
}

/** Modules add details to entities after first reporting them; at the end, read the final versions. */
async function refreshEntities() {
  const id = state.investigation?.id;
  if (!id) return;
  try {
    const saved = await api.get(`/api/investigation/${enc(id)}/graph`);
    if (state.investigation?.id !== id) return;
    for (const element of saved.elements || []) {
      const d = element.data || {};
      const entity = element.group === "nodes" ? state.entities.get(d.id) : null;
      if (entity && d.metadata) entity.metadata = d.metadata;
    }
    emit("entities-refreshed");
  } catch { /* the live versions stay shown */ }
}

export async function loadIntel() {
  const id = state.investigation?.id;
  if (!id) return;
  try {
    const [paths, attack] = await Promise.all([
      api.get(`/api/investigation/${enc(id)}/paths`),
      api.get(`/api/investigation/${enc(id)}/attack`),
    ]);
    if (state.investigation?.id !== id) return; // user switched investigation meanwhile
    state.paths = paths;
    state.attack = attack;
    emit("paths", paths);
    emit("attack", attack);
  } catch (err) {
    if (err.status !== 401) toast(`Could not load analysis: ${err.message}`, "error");
  }
}

const DISCOVERIES = new Set(["entity_discovered", "relation_discovered"]);
const FEED_DETAIL_LIMIT = 4; // more discoveries than this in one frame are summarised in one feed line

/** Add a run of discoveries in one graph batch, with one redraw, one re-render and one feed line. */
function applyDiscoveries(messages) {
  const found = [];
  let changed = false;
  graph.batch(() => {
    for (const { type, data } of messages) {
      if (type === "entity_discovered") {
        state.entities.set(data.entity.id, data.entity);
        if (graph.addEntity(data.entity)) { found.push(data.entity); changed = true; }
      } else {
        state.relations.set(data.relation.id, data.relation);
        if (graph.addRelation(data.relation)) changed = true;
      }
    }
  });
  if (found.length > FEED_DETAIL_LIMIT) {
    const byType = {};
    found.forEach((e) => { byType[e.type] = (byType[e.type] || 0) + 1; });
    const parts = Object.entries(byType).sort((a, b) => b[1] - a[1]).map(([t, n]) => `${n} ${t.replaceAll("_", " ")}`);
    pushFeed(`Found ${found.length} entities: ${parts.join(", ")}`);
  } else {
    found.forEach((e) => pushFeed(`Found ${e.type.replaceAll("_", " ")}: ${e.label}`));
  }
  if (found.length) graph.scheduleRelayout();
  if (changed) emit("graph");
}

function handle(msg) {
  const { type, data } = msg;
  switch (type) {
    case "snapshot": {
      setInvestigation(data.investigation);
      state.analytics = data.analytics;
      data.entities.forEach((e) => state.entities.set(e.id, e));
      data.relations.forEach((r) => state.relations.set(r.id, r));
      graph.bulkLoad(data.entities, data.relations);
      graph.relayout(undefined, false);
      graph.fit();
      emit("graph");
      emit("analytics", state.analytics);
      if (!["running", "initializing"].includes(data.investigation.status)) loadIntel();
      break;
    }
    case "entity_discovered":
    case "relation_discovered":
      applyDiscoveries([msg]);
      break;
    case "scan_progress":
      emit("progress", data);
      break;
    case "scan_completed":
      setInvestigation({ status: "completed", completed_at: new Date().toISOString() });
      state.analytics = data.analytics;
      emit("analytics", state.analytics);
      graph.relayout();
      loadIntel();
      refreshEntities();
      pushFeed("Investigation complete");
      toast(`Investigation of ${state.investigation.target} complete`, "success");
      emit("history-changed");
      break;
    case "scan_failed":
    case "scan_cancelled": {
      const failed = type === "scan_failed";
      setInvestigation({ status: failed ? "failed" : "cancelled" });
      loadIntel();
      pushFeed(failed ? `Scan failed: ${data.error || "unknown error"}` : "Scan stopped", failed ? "error" : "warn");
      toast(failed ? "The scan failed — partial results are kept" : "Scan stopped — partial results are kept", failed ? "error" : "info");
      emit("history-changed");
      break;
    }
    case "log_message":
      if (data.level !== "DEBUG") pushFeed(data.message, data.level === "ERROR" ? "error" : "warn");
      break;
    default:
      break;
  }
}

// Messages are buffered and applied once per animation frame: a busy scan sends hundreds of
// discoveries a second, and rendering each one separately is what makes a graph stutter.
let pending = [];
let flushTimer = null;
let flushFrame = null;

// Messages that must be handled exactly where they fall: everything before them is drawn first.
const BARRIERS = new Set(["snapshot", "scan_completed", "scan_failed", "scan_cancelled"]);

function flush() {
  if (flushTimer) clearTimeout(flushTimer);
  if (flushFrame) cancelAnimationFrame(flushFrame);
  flushTimer = flushFrame = null;
  const messages = pending;
  pending = [];
  let segment = [];
  for (const msg of messages) {
    if (!BARRIERS.has(msg.type)) { segment.push(msg); continue; }
    applySegment(segment);
    segment = [];
    handle(msg);
  }
  applySegment(segment);
}

/** Between barriers: all discoveries in one batch, then log lines, then only the newest progress. */
function applySegment(messages) {
  if (!messages.length) return;
  const discoveries = messages.filter((m) => DISCOVERIES.has(m.type));
  if (discoveries.length) applyDiscoveries(discoveries);
  let progress = null;
  for (const msg of messages) {
    if (DISCOVERIES.has(msg.type)) continue;
    if (msg.type === "scan_progress") progress = msg;
    else handle(msg);
  }
  if (progress) handle(progress);
}

function enqueue(msg) {
  pending.push(msg);
  if (flushTimer || flushFrame) return;
  flushFrame = requestAnimationFrame(flush);
  flushTimer = setTimeout(flush, 250); // background tabs get no animation frames
}

function resetQueue() {
  if (flushTimer) clearTimeout(flushTimer);
  if (flushFrame) cancelAnimationFrame(flushFrame);
  flushTimer = flushFrame = null;
  pending = [];
}

async function connect(id) {
  socket?.close();
  resetQueue();
  let ticket;
  try {
    ticket = (await api.post("/api/ws-ticket")).ticket;
  } catch (err) {
    if (err.status !== 401) toast("Could not open the live stream", "error");
    return;
  }
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const ws = new WebSocket(`${proto}//${location.host}/ws/stream/${enc(id)}?ticket=${enc(ticket)}`);
  socket = ws;
  ws.onmessage = (event) => {
    if (socket !== ws) return;
    try { enqueue(JSON.parse(event.data)); } catch (err) { console.error("Bad stream message", err); }
  };
  ws.onclose = (event) => {
    if (socket === ws && event.code === 4404) toast("That investigation no longer exists", "error");
  };
}

export async function openInvestigation(id) {
  if (!id) return;
  resetInvestigation();
  graph.clearGraph();
  setInvestigation({ id, status: "initializing" });
  const url = new URL(location.href);
  url.searchParams.set("inv", id);
  history.replaceState(null, "", url);
  await connect(id);
}

export function closeInvestigation() {
  socket?.close();
  socket = null;
  resetQueue();
  resetInvestigation();
  graph.clearGraph();
  const url = new URL(location.href);
  url.searchParams.delete("inv");
  history.replaceState(null, "", url);
  emit("investigation", null);
}

export async function startScan(body) {
  const data = await api.post("/api/scan", { ...body, authorized: true });
  await openInvestigation(data.investigation_id);
  pushFeed(`Started investigation of ${data.target}`);
  emit("history-changed");
  return data;
}

export async function stopScan() {
  const id = state.investigation?.id;
  if (!id) return;
  try {
    await api.post(`/api/investigation/${enc(id)}/cancel`);
    toast("Stopping scan…");
  } catch (err) {
    toast(err.message, "error");
  }
}
