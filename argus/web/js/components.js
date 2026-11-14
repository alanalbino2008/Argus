// Reusable UI pieces. Every interpolated value goes through html`` (auto-escaped).

import { html, trusted } from "./dom.js";
import { icon, typeInfo } from "./icons.js";

export const ico = (name, cls = "") => trusted(icon(name, cls));

export const SEVERITIES = ["critical", "high", "medium", "low"];

export const severityPill = (sev) => html`<span class="pill ${sev}">${sev}</span>`;

export function statusBadge(status) {
  const label = { initializing: "Starting", running: "Scanning", completed: "Complete", failed: "Failed", cancelled: "Stopped" }[status] || status;
  const cls = status === "initializing" ? "running" : status;
  return html`<span class="status ${cls}"><span class="dot"></span>${label}</span>`;
}

export function tip(text) {
  return html`<span class="tip-icon" tabindex="0" data-tip="${text}">?</span>`;
}

/** Circular gauge for a 0-100 score; colour follows severity bands. */
export function gauge(score) {
  const value = Math.max(0, Math.min(100, Number(score) || 0));
  const r = 26;
  const c = 2 * Math.PI * r;
  const color = value >= 70 ? "var(--sev-critical)" : value >= 45 ? "var(--sev-high)" : value >= 25 ? "var(--sev-medium)" : "var(--ok)";
  return html`<svg class="gauge" viewBox="0 0 64 64" role="img" aria-label="Score ${value} of 100">
    <circle class="track" cx="32" cy="32" r="${r}"/>
    <circle class="value" cx="32" cy="32" r="${r}" stroke="${color}"
      stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${(c * (1 - value / 100)).toFixed(1)}" transform="rotate(-90 32 32)"/>
    <text x="32" y="37" text-anchor="middle" font-size="15" font-weight="700" fill="currentColor">${value}</text>
  </svg>`;
}

export function entityIcon(type, size = "") {
  const info = typeInfo(type);
  return html`<span class="${size || "ico"}" style="background:${info.color}">${ico(type)}</span>`;
}

export function chainNode(step) {
  return html`<span class="chain-node" title="${step.role}: ${step.label}">${entityIcon(step.type)}<span class="txt">${step.label}</span></span>`;
}

export function chain(steps) {
  return html`<div class="chain">${steps.map((s, i) => html`${i ? html`<span class="chain-arrow">→</span>` : ""}${chainNode(s)}`)}</div>`;
}

export function ttpRoute(techniques) {
  return html`<div class="ttp-route">${techniques.map((t, i) => html`${i ? html`<span class="chain-arrow">›</span>` : ""}<a class="ttp" href="${t.url}" target="_blank" rel="noopener noreferrer" title="${t.name}"><small>${t.tactic}</small>${t.id}</a>`)}</div>`;
}

/** Full attack-path card. `compact` hides details for dashboard use. */
export function pathCard(p, index, { compact = false } = {}) {
  return html`<article class="card path-card" data-index="${index}">
    <div class="path-top">
      <span class="score-badge ${p.severity}" data-tip="Risk ${p.score}/100 = impact ${p.impact}/5 × likelihood ${p.likelihood}">${p.score}</span>
      <div class="path-title">${p.title}</div>
      ${severityPill(p.severity)}
    </div>
    ${compact ? "" : html`<p class="path-narrative">${p.narrative}</p>`}
    <div style="margin-top:${compact ? "12px" : "0"}">${chain(p.steps)}</div>
    ${compact ? "" : ttpRoute(p.techniques)}
    <div class="path-foot">
      ${compact ? html`<span class="muted small">${p.techniques.map((t) => t.tactic).filter((v, i, a) => a.indexOf(v) === i).join(" → ")}</span>`
        : html`<details class="more">
          <summary>Why this matters &amp; how to fix it</summary>
          <div class="more-body">
            <div><div class="section-title">Evidence</div><ul>${p.evidence.map((e) => html`<li>${e}</li>`)}</ul></div>
            <div><div class="section-title">Fix, in order</div><ol>${p.remediation.map((r) => html`<li>${r}</li>`)}</ol></div>
          </div>
        </details>`}
      <button class="btn sm" data-action="show-path" data-index="${index}">${ico("graph")}Show on graph</button>
    </div>
  </article>`;
}

export function empty(iconName, title, text, actions = "") {
  return html`<div class="empty">${ico(iconName)}<h3>${title}</h3><p>${text}</p>${actions}</div>`;
}

export function skeletonRows(n = 3) {
  return html`${Array.from({ length: n }, (_, i) => html`<div class="skeleton" style="width:${90 - i * 15}%;margin:12px 0"></div>`)}`;
}
