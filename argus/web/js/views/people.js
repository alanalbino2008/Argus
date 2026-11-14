// People: identity fragments resolved into personas, each with a dossier.
// Remote avatars are deliberately never loaded - fetching one would reveal the
// analyst's IP address to the subject's platform. Initials are used instead.

import { api, enc } from "../api.js";
import { empty, entityIcon, ico, severityPill } from "../components.js";
import { formatDay, html, on, plural, setHTML } from "../dom.js";
import { isRunning, on as onState, state } from "../state.js";

let root;
let actions;
let selectedId = null;
let loading = false;
let loadedFor = null;
let failed = false;

const STRENGTH = {
  verified: { label: "Verified link", cls: "ok", tip: "At least one account is confirmed by the platform or a cryptographic proof." },
  strong: { label: "Strong match", cls: "accent", tip: "Collected with high confidence, but not independently proven." },
  probable: { label: "Possible match", cls: "", tip: "Based on the same handle existing elsewhere: it may be a different person." },
};

export function initPeople(el, appActions) {
  root = el;
  actions = appActions;
  onState("reset", () => { selectedId = null; loadedFor = null; failed = false; render(); });
  ["investigation", "paths", "people"].forEach((e) => onState(e, render));
  on(root, "click", "[data-persona]", (_e, el2) => { selectedId = el2.dataset.persona; render(); root.querySelector(".dossier")?.scrollIntoView({ block: "start", behavior: "smooth" }); });
  on(root, "click", "[data-action='back']", () => { selectedId = null; render(); });
  on(root, "click", "[data-action='show-persona']", () => showOnGraph(current()));
  on(root, "click", "[data-action='newInvestigation'], [data-action='loadDemo']", (_e, btn) => actions[btn.dataset.action]());
  on(root, "click", "[data-path-id]", (_e, el2) => actions.showPath((state.paths?.paths || []).find((p) => p.id === el2.dataset.pathId)));
  on(root, "click", "[data-action='retry']", () => { failed = false; refresh(); });
  render();
}

/** Called when the People view becomes visible: dossiers are fetched (and audited) only when viewed. */
export async function refresh() {
  const id = state.investigation?.id;
  if (!id || isRunning() || loading || loadedFor === id) return;
  loading = true;
  render();
  try {
    const people = await api.get(`/api/investigation/${enc(id)}/people`);
    if (state.investigation?.id !== id) return;
    state.people = people;
    loadedFor = id;
  } catch (err) {
    failed = err.status !== 401;
  } finally {
    loading = false;
    render();
  }
}

function current() {
  return state.people?.personas.find((p) => p.id === selectedId) || null;
}

function showOnGraph(persona) {
  if (!persona) return;
  const ids = new Set(persona.entity_ids);
  const edges = [...state.relations.values()].filter((r) => ids.has(r.source_id) && ids.has(r.target_id)).map((r) => r.id);
  actions.showPath({ steps: persona.entity_ids.map((id) => ({ entity_id: id })), edges });
}

function initials(name) {
  const words = String(name).replace(/@.*/, "").split(/[\s._-]+/).filter(Boolean);
  return ((words[0]?.[0] || "?") + (words.length > 1 ? words[words.length - 1][0] : "")).toUpperCase();
}

function avatar(p, size = "") {
  return html`<span class="avatar ${size}" aria-hidden="true">${initials(p.name)}</span>`;
}

function strengthPill(p) {
  const s = STRENGTH[p.strength] || STRENGTH.probable;
  return html`<span class="pill ${s.cls}" data-tip="${s.tip}">${s.label}</span>`;
}

function riskPill(risk) {
  const sev = risk >= 70 ? "critical" : risk >= 45 ? "high" : risk >= 20 ? "medium" : "low";
  return html`<span class="pill ${sev}" data-tip="Exposure score ${risk}/100">Exposure ${risk}</span>`;
}

function render() {
  if (!root) return;
  const inv = state.investigation;
  if (!inv) {
    setHTML(root, html`<div class="page"><div class="card">${empty("persona", "No investigation open", "Argus links usernames, emails, accounts and names it finds into people, and builds a dossier for each.",
      html`<div class="hero-actions" style="justify-content:center"><button class="btn primary" data-action="newInvestigation">${ico("plus")}New investigation</button><button class="btn" data-action="loadDemo">Try the demo</button></div>`)}</div></div>`);
    return;
  }
  if (loadedFor !== inv.id && !loading && !failed && !isRunning()) queueMicrotask(refresh);
  const persona = current();
  setHTML(root, html`<div class="page" style="max-width:1080px">${persona ? dossier(persona) : overview(inv)}</div>`);
}

function overview(inv) {
  const data = loadedFor === inv.id ? state.people : null;
  const head = html`<div class="page-head"><div>
      <h1>People</h1>
      <p>Identifiers found about <b>${inv.target}</b> — usernames, emails, accounts, names — linked into the people behind them. Open a person for their dossier.</p>
    </div></div>`;
  if (isRunning()) return html`${head}<div class="card">${empty("persona", "Discovery in progress", "People are resolved once the scan has finished collecting findings.")}</div>`;
  if (failed) return html`${head}<div class="card">${empty("info", "Couldn't load people", "Something went wrong while resolving identities.", html`<button class="btn" data-action="retry">Try again</button>`)}</div>`;
  if (!data) return html`${head}<div class="card card-pad"><div class="skeleton" style="width:60%"></div><div class="skeleton" style="width:40%;margin-top:12px"></div></div>`;
  const people = data.personas;
  return html`${head}
    <div class="callout" style="margin-bottom:16px">${ico("info")}<span>Only public information is shown. Links are graded: <b>verified</b> (proven by the platform), <b>strong</b> and <b>possible</b> (same handle — may be someone else). Viewing dossiers is recorded in the audit log.</span></div>
    ${data.email_format ? html`<div class="card card-pad" style="margin-bottom:16px;display:flex;gap:14px;align-items:center;flex-wrap:wrap">
      ${ico("email")}<div style="flex:1;min-width:220px"><div class="list-title">Email format: <span class="mono">${data.email_format.example}</span></div>
      <div class="list-sub">Learned from ${plural(data.email_format.evidence, "known address", "known addresses")}. Likely addresses for people found without one are marked <i>inferred</i>.</div></div></div>` : ""}
    ${people.length ? html`<div class="persona-grid">${people.map(personaCard)}</div>`
      : html`<div class="card">${empty("persona", "No people found", "This investigation didn't surface any linked identities. Try a username or email address as the target.")}</div>`}
    ${data.role_mailboxes.length || data.public_phones?.length ? html`<div class="card card-pad" style="margin-top:16px">
      <div class="section-title">Public contact points</div>
      <p class="muted small" style="margin:0 0 10px">Team inboxes and switchboard numbers belong to the organisation, not a person — Argus doesn't hunt them on social networks.</p>
      <div class="chips">${[...data.role_mailboxes, ...(data.public_phones || [])].map((m) => html`<span class="chip">${m}</span>`)}</div></div>` : ""}`;
}

function personaCard(p) {
  const facts = [
    p.accounts.length && plural(p.accounts.length, "account"),
    p.emails.length && plural(p.emails.length, "email"),
    p.breaches.length && plural(p.breaches.length, "breach", "breaches"),
  ].filter(Boolean);
  return html`<button class="card persona-card" data-persona="${p.id}">
    <div class="persona-top">
      ${avatar(p)}
      <div class="persona-name"><div class="list-title">${p.name}</div>
        <div class="list-sub">${p.usernames.slice(0, 3).map((u) => `@${u}`).join(" · ") || p.emails[0] || (p.likely_email && `${p.likely_email.address} (inferred)`) || (p.shared_mailboxes[0] && `Contact for ${p.shared_mailboxes[0]}`) || p.phones[0] || ""}</div></div>
    </div>
    ${p.bio ? html`<p class="persona-bio">${p.bio}</p>` : ""}
    <div class="persona-meta">
      ${p.locations[0] ? html`<span>${ico("location")}${p.locations[0]}</span>` : ""}
      ${p.organisations[0] ? html`<span>${ico("organization")}${p.organisations[0]}</span>` : ""}
    </div>
    <div class="persona-foot">${strengthPill(p)}${p.exposures.length ? riskPill(p.risk) : ""}<span class="muted small" style="margin-left:auto">${facts.join(" · ")}</span></div>
  </button>`;
}

function dossier(p) {
  const factRows = [
    ["Also known as", p.names.filter((n) => n !== p.name).join(", ")],
    ["Handles", p.usernames.map((u) => `@${u}`).join(", ")],
    ["Email", p.emails.join(", ")],
    ["Likely work email", p.likely_email ? `${p.likely_email.address} — inferred from the ${p.likely_email.basis} format, not confirmed` : ""],
    ["Phone", p.phones.join(", ")],
    ["Location", p.locations.join(" · ")],
    ["Works at", p.organisations.join(", ")],
    ["Websites", p.websites.join(", ")],
    ["Listed on", p.shared_mailboxes.join(", ")],
  ].filter(([, v]) => v);
  return html`<div class="dossier">
    <button class="btn ghost sm" data-action="back" style="margin-bottom:12px">← All people</button>
    <div class="card card-pad dossier-head">
      ${avatar(p, "lg")}
      <div style="flex:1;min-width:0">
        <h1 style="margin:0">${p.name}</h1>
        ${p.bio ? html`<p class="muted" style="margin:6px 0 0">${p.bio}</p>` : ""}
        <div class="persona-foot" style="margin-top:10px">${strengthPill(p)}${riskPill(p.risk)}</div>
      </div>
      <button class="btn" data-action="show-persona">${ico("graph")}Show on graph</button>
    </div>

    <div class="grid two" style="margin-top:16px">
      <div class="grid">
        <div class="card card-pad"><div class="section-title">Accounts</div>
          ${p.accounts.length ? html`<div class="list">${p.accounts.map(account)}</div>` : html`<p class="muted small">No accounts linked.</p>`}</div>
        <div class="card card-pad"><div class="section-title">Timeline</div>
          ${p.timeline.length ? html`<ol class="timeline">${p.timeline.map((t) => html`<li><time>${formatDay(t.date)}</time><span>${t.event}</span></li>`)}</ol>`
            : html`<p class="muted small">No dated events.</p>`}</div>
      </div>
      <div class="grid">
        <div class="card card-pad"><div class="section-title">What is known</div>
          ${factRows.length ? html`<dl class="kv">${factRows.map(([k, v]) => html`<dt>${k}</dt><dd>${v}</dd>`)}</dl>` : html`<p class="muted small">—</p>`}</div>
        <div class="card card-pad"><div class="section-title">Exposure</div>
          ${p.exposures.length ? p.exposures.map((e) => html`<div class="flag">${severityPill(e.severity)}<span>${e.text}</span></div>`)
            : html`<p class="muted small">Nothing notable exposed.</p>`}
          ${p.attack_paths.length ? html`<div class="section"><div class="section-title">Part of ${plural(p.attack_paths.length, "attack path")}</div>
            ${p.attack_paths.map((a) => html`<div class="list-row clickable" data-path-id="${a.id}">${severityPill(a.severity)}<div class="list-main"><div class="list-title">${a.title}</div></div>${ico("graph")}</div>`)}</div>` : ""}
        </div>
      </div>
    </div>
  </div>`;
}

function account(a) {
  const f = a.facts || {};
  const sub = [f.display_name, f.location, f.created_at && `joined ${formatDay(f.created_at)}`, f.followers != null && `${f.followers} followers`].filter(Boolean).join(" · ");
  const grade = { verified: ["ok", "Verified"], strong: ["accent", "Strong"], probable: ["", "Possible"] }[a.link] || ["", a.link];
  return html`<div class="list-row">
    ${entityIcon("social_profile")}
    <div class="list-main">
      <div class="list-title">${a.platform}${a.handle ? html` <span class="muted">@${a.handle}</span>` : ""}</div>
      ${sub ? html`<div class="list-sub">${sub}</div>` : ""}
      ${f.bio ? html`<div class="list-sub account-bio">${f.bio}</div>` : ""}
    </div>
    <span class="pill ${grade[0]}">${grade[1]}</span>
    ${a.url ? html`<a class="btn ghost sm icon" href="${a.url}" target="_blank" rel="noopener noreferrer nofollow" referrerpolicy="no-referrer" title="Open profile (leaves Argus)">${ico("external")}</a>` : ""}
  </div>`;
}
