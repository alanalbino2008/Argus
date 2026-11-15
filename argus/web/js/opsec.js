// Investigator safety: the egress routes (Tor, VPN, proxy) the operator set up, by name only.

import { api } from "./api.js";
import { html } from "./dom.js";

let cached = null;

/** The routes investigators can choose ([] if none are configured). */
export async function loadRoutes() {
  if (!cached) cached = api.get("/api/opsec/routes").then((r) => r.routes).catch(() => { cached = null; return []; });
  return cached;
}

const KIND = { tor: "Tor", proxy: "Proxy / VPN" };
export const routeLabel = (r) => `${r.name} · ${KIND[r.kind] || r.kind}${r.anonymous ? " (anonymous)" : ""}`;

/** <option>s for a route <select>: "Direct" first unless only anonymous routes are allowed. */
export function routeOptions(routes, selected = "", { anonymousOnly = false } = {}) {
  const usable = routes.filter((r) => !anonymousOnly || r.anonymous);
  return html`${anonymousOnly ? "" : html`<option value="" ${selected ? "" : "selected"}>Direct: sites see this server's address</option>`}
    ${usable.map((r) => html`<option value="${r.name}" ${r.name === selected ? "selected" : ""}>${routeLabel(r)}</option>`)}`;
}

/** What a choice means for the investigator, in a sentence. */
export function routeWarning(routes, name) {
  if (!name) return "Direct: the site, and anyone watching its logs, sees this server's own address. Choose a route if the subject must not know they are being looked at.";
  const r = routes.find((x) => x.name === name);
  if (!r) return "";
  return r.anonymous ? "" : `${r.name} hides this server's address, but it is not marked anonymous: whoever runs it can see what you visit.`;
}
