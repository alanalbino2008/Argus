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
    case "entity_discovered": {
      state.entities.set(data.entity.id, data.entity);
      if (graph.addEntity(data.entity)) {
        pushFeed(`Found ${data.entity.type.replace("_", " ")}: ${data.entity.label}`);
        graph.scheduleRelayout();
        emit("graph");
      }
      break;
    }
    case "relation_discovered":
      state.relations.set(data.relation.id, data.relation);
      if (graph.addRelation(data.relation)) emit("graph");
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

async function connect(id) {
  socket?.close();
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
    try { handle(JSON.parse(event.data)); } catch (err) { console.error("Bad stream message", err); }
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
