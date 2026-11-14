// Tiny observable store for the open investigation and session.

const listeners = new Map();

export const state = {
  me: null,
  investigation: null, // investigation payload from the API / snapshot
  entities: new Map(), // id -> entity
  relations: new Map(), // id -> relation
  analytics: null,
  paths: null, // { paths, summary }
  attack: null, // ATT&CK mapping
  people: null, // { personas, role_mailboxes, summary } - fetched when the People view opens
  feed: [],
  alertsOpen: 0,
};

export function on(event, fn) {
  if (!listeners.has(event)) listeners.set(event, new Set());
  listeners.get(event).add(fn);
  return () => listeners.get(event).delete(fn);
}

export function emit(event, payload) {
  (listeners.get(event) || []).forEach((fn) => {
    try { fn(payload); } catch (err) { console.error(`listener for ${event} failed`, err); }
  });
}

export function resetInvestigation() {
  state.investigation = null;
  state.entities.clear();
  state.relations.clear();
  state.analytics = null;
  state.paths = null;
  state.attack = null;
  state.people = null;
  state.feed = [];
  emit("reset");
}

export function isRunning() {
  const s = state.investigation?.status;
  return s === "running" || s === "initializing";
}

export function pushFeed(text, level = "info") {
  state.feed.unshift({ at: new Date(), text, level });
  if (state.feed.length > 200) state.feed.length = 200;
  emit("feed");
}
