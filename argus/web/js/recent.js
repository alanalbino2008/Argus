// "Pick up where you left off": the most recent finished investigations, one click from any view that
// needs one open. Used by the empty states of Graph, Attack paths and People.

import { api } from "./api.js";
import { ico } from "./components.js";
import { html, setHTML, timeAgo } from "./dom.js";

let cache = null;
let cachedAt = 0;

export async function fillRecent(container, view, actions) {
  const box = container?.querySelector("[data-recent]");
  if (!box) return;
  try {
    if (!cache || Date.now() - cachedAt > 30_000) {
      cache = await api.get("/api/investigations?limit=6");
      cachedAt = Date.now();
    }
  } catch {
    return; // the start / demo buttons still work
  }
  const rows = (cache || []).filter((r) => r.status === "completed").slice(0, 3);
  if (!rows.length || !box.isConnected) return;
  setHTML(box, html`<p class="muted small" style="margin:16px 0 8px">Or open a recent investigation</p>
    <div class="recent-open-list">${rows.map((r) => html`<button type="button" class="btn sm" data-open-recent="${r.id}">${ico("history")}<span class="mono">${r.target}</span><span class="muted">${timeAgo(r.completed_at || r.created_at)}</span></button>`)}</div>`);
  box.onclick = (e) => {
    const btn = e.target.closest("[data-open-recent]");
    if (btn) actions.open(btn.dataset.openRecent, { view });
  };
}

/** Forget the cached list (after an investigation starts or finishes). */
export function forgetRecent() {
  cache = null;
}
