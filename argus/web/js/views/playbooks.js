// The Playbooks tab of a case: run the standard steps of an investigation from one starting point,
// follow them as they run, and add what stood out to the case.

import { api, enc } from "../api.js";
import { ico } from "../components.js";
import { $, formatDate, html, on, setHTML, timeAgo, toast } from "../dom.js";
import { state } from "../state.js";
import { briefView } from "./analyst.js";

const canEdit = () => ["analyst", "admin"].includes(state.workspace?.role);
const STEP = { pending: ["", "Waiting"], running: ["accent", "Running"], done: ["ok", "Done"], skipped: ["", "Skipped"], failed: ["warn", "Failed"] };
const safeUrl = (u) => /^https?:\/\//.test(u || "");
const RUN = { running: "accent", completed: "ok", failed: "warn", cancelled: "", interrupted: "warn" };
const LEVEL = { high: ["critical", "Needs attention"], medium: ["warn", "Worth checking"], info: ["", "Also found"] };
let el = null;
let caseRef = null;
let catalogue = [];
let runs = [];
let analystOn = false;
let chosen = null;
let timer = null;
let onChanged = () => {};

export async function renderPlaybooks(target, caseObj) {
  el = target;
  caseRef = caseObj;
  el.dataset.mode = "playbooks";
  [catalogue, runs, analystOn] = await Promise.all([
    api.get("/api/playbooks"),
    api.get(`/api/cases/${enc(caseObj.id)}/playbooks`),
    api.get("/api/analyst").then((s) => s.available).catch(() => false),
  ]);
  chosen ??= catalogue[0]?.id;
  draw();
  poll();
}

function poll() {
  clearTimeout(timer);
  if (!runs.some((r) => r.status === "running")) return;
  timer = setTimeout(async () => {
    if (!el?.isConnected || el.dataset.mode !== "playbooks") return;
    try {
      const before = runs.filter((r) => r.status === "running").length;
      runs = await api.get(`/api/cases/${enc(caseRef.id)}/playbooks`);
      draw();
      if (runs.filter((r) => r.status === "running").length < before) onChanged({ quiet: true });
    } catch { /* try again next time */ }
    poll();
  }, 3000);
}

function stepRow(s) {
  const [cls, label] = STEP[s.status] || ["", s.status];
  return html`<div class="list-row" style="align-items:flex-start">
    <div class="list-main"><div class="list-title">${s.title}</div>
      <div class="list-sub">${s.detail || (s.kind === "scan" && s.modules?.length ? `Sources: ${s.modules.join(", ")}` : "")}</div>
      ${s.unavailable?.length && s.status === "pending" ? html`<div class="muted small">Needs a key, so left out: ${s.unavailable.join(", ")}</div>` : ""}
      ${s.problems?.length ? html`<details class="small"><summary>Pages that could not be preserved</summary>${s.problems.map((p) => html`<div class="muted">${p}</div>`)}</details>` : ""}</div>
    <span class="pill ${cls}">${label}${s.status === "running" ? "…" : ""}</span></div>`;
}

function highlightRow(h, i, runId) {
  const [cls, label] = LEVEL[h.level];
  return html`<tr><td>${h.entity && canEdit() ? html`<input type="checkbox" data-hl="${runId}:${i}" aria-label="Add ${h.entity.value}" ${h.tick ? "checked" : ""}>` : ""}</td>
    <td><span class="pill ${cls}">${label}</span></td>
    <td><b>${h.title}</b>${h.detail ? html`<div class="muted small">${h.detail}</div>` : ""}</td>
    <td>${safeUrl(h.url) ? html`<a href="${h.url}" target="_blank" rel="noopener noreferrer" class="small">${ico("external")}Open</a>` : ""}</td></tr>`;
}

function runCard(r) {
  const book = catalogue.find((p) => p.id === r.playbook);
  const brief = r.steps.find((s) => s.kind === "brief" && s.brief)?.brief;
  return html`<div class="card card-pad" style="margin-top:16px">
    <div class="card-head"><h2>${book?.name || r.playbook}: ${r.seed}</h2>
      <span><span class="pill ${RUN[r.status] || ""}">${r.status}</span>
      ${r.status === "running" && canEdit() ? html` <button class="btn sm ghost" data-pb="cancel" data-id="${r.id}">Stop</button>` : ""}</span></div>
    <p class="muted small">Started by ${r.created_by} ${timeAgo(r.created_at)}${r.finished_at ? ` · finished ${formatDate(r.finished_at)}` : ""} · route: ${r.options.route}${r.options.passive_only ? " · passive only (anonymous case)" : ""}</p>
    ${r.status === "interrupted" ? html`<p class="error-text">The server stopped while this ran. Start it again to finish.</p>` : ""}
    ${r.error ? html`<p class="error-text">${r.error}</p>` : ""}
    <div class="list">${r.steps.map(stepRow)}</div>
    ${r.highlights.length ? html`<h3 style="margin-top:16px">What stood out (${r.highlights.length})</h3>
      <div style="overflow-x:auto"><table class="table"><tbody>${r.highlights.map((h, i) => highlightRow(h, i, r.id))}</tbody></table></div>
      ${canEdit() && r.highlights.some((h) => h.entity) ? html`<p class="muted small">Name matches are possibilities, not identifications. Ticked items are added to the case as entities.</p>
        <button class="btn sm primary" data-pb="add" data-id="${r.id}">${ico("plus")}Add ticked to the case</button>` : ""}`
      : r.status === "completed" ? html`<p class="muted small" style="margin-top:12px">Nothing stood out. Sources are incomplete, so this is not proof of absence.</p>` : ""}
    ${brief ? html`<h3 style="margin-top:16px">${ico("sparkle")}AI briefing</h3>${briefView(brief, { save: false })}` : ""}
  </div>`;
}

function startCard() {
  const book = catalogue.find((p) => p.id === chosen);
  const running = runs.some((r) => r.status === "running");
  return html`<div class="card card-pad">
    <div class="card-head"><h2>${ico("paths")}Playbooks</h2></div>
    <p class="muted small">The standard steps of an investigation, run for you in order from one starting point. Each scan is linked to this case and uses its route${caseRef.opsec_mode === "anonymous" ? "; this case is anonymous, so only passive sources are used" : ""}. Findings are written to the case as a note.</p>
    <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px;margin:12px 0" role="radiogroup" aria-label="Playbook">
      ${catalogue.map((p) => html`<button type="button" class="note" role="radio" aria-checked="${p.id === chosen}" data-pb="choose" data-id="${p.id}"
        style="text-align:left;cursor:pointer;${p.id === chosen ? "outline:2px solid var(--accent)" : ""}"><b>${p.name}</b><div class="muted small">${p.when}</div></button>`)}
    </div>
    ${book ? html`<p>${book.summary}</p>
      <ol class="small">${book.steps.map((s) => html`<li>${s.title}${s.unavailable.length ? html` <span class="muted">(needs a key: ${s.unavailable.join(", ")})</span>` : ""}</li>`)}</ol>
      ${canEdit() ? html`<form id="pb-form" style="display:grid;gap:8px;max-width:520px">
        <label class="small" for="pb-seed">Starting point</label>
        <input class="input" id="pb-seed" required maxlength="253" placeholder="${book.when.split(",")[0]}" autocomplete="off">
        <label class="small"><input type="checkbox" id="pb-confirm" required> There is a legitimate purpose for this (the case's: ${caseRef.purpose})</label>
        ${analystOn ? html`<label class="small"><input type="checkbox" id="pb-brief"> End with an AI briefing. This sends the case's material to Anthropic, the company that makes Claude${caseRef.opsec_mode === "anonymous" ? html`, <b>including what you know about the subjects of this anonymous case</b>` : ""}.</label>` : ""}
        <p class="error-text" id="pb-error"></p>
        <div><button class="btn primary" type="submit" ${running ? "disabled" : ""}>${running ? "A playbook is running…" : html`${ico("search")}Run ${book.name}`}</button></div>
      </form>` : ""}` : ""}
  </div>`;
}

function draw() {
  if (!el) return;
  setHTML(el, html`${startCard()}${runs.map(runCard)}`);
}

async function addTicked(runId) {
  const run = runs.find((r) => r.id === runId);
  const picked = [...el.querySelectorAll(`[data-hl^="${runId}:"]:checked`)].map((b) => run.highlights[Number(b.dataset.hl.split(":")[1])]);
  if (!picked.length) return toast("Tick the items to add", "error");
  for (const h of picked) {
    await api.post(`/api/cases/${enc(caseRef.id)}/items`, { kind: "entity", title: h.entity.value,
      body: `Found by the ${catalogue.find((p) => p.id === run.playbook)?.name || run.playbook} playbook: ${h.title}${h.detail ? `. ${h.detail}` : ""}`.slice(0, 50000),
      data: { type: h.entity.type, value: h.entity.value, attributes: h.entity.attributes || {} } });
  }
  toast(`${picked.length} item${picked.length === 1 ? "" : "s"} added to the case`, "success");
  onChanged();
}

export function initPlaybooks(root, changed) {
  onChanged = changed;
  on(root, "click", "[data-pb]", async (e, btn) => {
    e.preventDefault();
    try {
      const { pb, id } = btn.dataset;
      if (pb === "choose") { chosen = id; return draw(); }
      if (pb === "add") return await addTicked(id);
      if (pb === "cancel") {
        await api.post(`/api/cases/${enc(caseRef.id)}/playbooks/${enc(id)}/cancel`);
        runs = await api.get(`/api/cases/${enc(caseRef.id)}/playbooks`);
        return draw();
      }
    } catch (err) { toast(err.message, "error", 8000); }
  });
  root.addEventListener("submit", async (e) => {
    if (e.target.id !== "pb-form") return;
    e.preventDefault();
    const brief = $("#pb-brief")?.checked || false;
    try {
      await api.post(`/api/cases/${enc(caseRef.id)}/playbooks`, { playbook: chosen, seed: $("#pb-seed").value,
        confirmed: $("#pb-confirm").checked, ai_brief: brief, ai_acknowledged: brief });
      runs = await api.get(`/api/cases/${enc(caseRef.id)}/playbooks`);
      draw();
      poll();
      toast("Playbook started: follow its steps below", "success");
    } catch (err) {
      $("#pb-error").textContent = err.message;
    }
  });
}
