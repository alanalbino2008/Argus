// The AI analyst tab of a case: a briefing with next steps, names and dates found in the evidence
// (reviewed before anything is added), and a report draft to edit.
//
// Nothing is sent without the investigator's confirmation, every time: the dialog says how much
// of the case goes to Anthropic, from which documents, and what it costs.

import { api, enc } from "../api.js";
import { ico } from "../components.js";
import { $, confirmDialog, formatDate, html, on, setHTML, toast } from "../dom.js";
import { state } from "../state.js";

const TASKS = {
  brief: ["Brief me", "What the case shows so far, what is missing, and the next steps worth taking."],
  extract: ["Find names & dates", "People, organisations, accounts, places and dates named in the evidence, each checked against the words it came from. You choose what to add."],
  report: ["Draft a report", "A first draft of a written report, citing its sources, for you to edit."],
};
const CONFIDENCE = { confirmed: "ok", likely: "accent", possible: "warn" };
const canEdit = () => ["analyst", "admin"].includes(state.workspace?.role);
const results = new Map(); // case id -> {task -> last answer}, kept while Argus is open
let status = null;
let caseRef = null;
let el = null;
let busy = null; // the task running now
let onChanged = () => {};
const size = (n) => (n < 1000 ? `${n} characters` : `${Math.round(n / 1000)}k characters`);

export async function renderAnalyst(target, caseObj) {
  el = target;
  caseRef = caseObj;
  el.dataset.mode = "analyst";
  status = await api.get("/api/analyst");
  draw();
}

function sourceChips(sources) {
  return html`${(sources || []).map((s) => html`<span class="pill" title="${s.kind}: ${s.title}" style="margin:2px 4px 2px 0;text-transform:none">${s.ref} · ${s.title.length > 40 ? `${s.title.slice(0, 40)}…` : s.title}</span>`)}`;
}

function materialNote(m) {
  if (!m) return "";
  const parts = [`${size(m.characters)} from ${m.sources} source${m.sources === 1 ? "" : "s"}`];
  if (m.shortened.length) parts.push(`${m.shortened.length} document(s) shortened`);
  if (m.left_out.length) parts.push(`${m.left_out.length} left out (too large)`);
  if (m.unreadable.length) parts.push(`${m.unreadable.length} without readable text (photos, other files)`);
  return parts.join(" · ");
}

function header(answer) {
  return html`<p class="muted small">${formatDate(answer.generated_at)} · ${answer.model || ""} · ${answer.via === "connect" ? `Argus Connect${answer.credits ? `, ${answer.credits.charged} credits (${answer.credits.available} left)` : ""}` : "your own Anthropic key"} · ${materialNote(answer.material)}</p>
    ${answer.cut_off ? html`<p class="error-text">The answer was too long and stopped early.</p>` : ""}
    <p class="muted small">${ico("info")} Written by AI from this case's material. Check every finding against its sources before relying on it.</p>`;
}

function briefView(answer) {
  const r = answer.result;
  return html`${header(answer)}
    <h3>Summary</h3><p style="white-space:pre-wrap">${r.summary}</p>
    <h3>Key findings</h3>${r.key_findings.length ? r.key_findings.map((f) => html`<div class="note">
      <div><span class="pill ${CONFIDENCE[f.confidence] || ""}">${f.confidence}</span>${f.unsupported ? html` <span class="pill warn" title="The analyst cited no source in this case">no source</span>` : ""} ${f.finding}</div>
      <div style="margin-top:4px">${sourceChips(f.sources)}</div></div>`) : html`<p class="muted small">None yet.</p>`}
    <h3>Next steps</h3>${r.next_steps.length ? html`<ol>${r.next_steps.map((s) => html`<li style="margin-bottom:8px"><b>${s.action}</b><div class="small">${s.why}</div><div class="muted small">How: ${s.how}</div></li>`)}</ol>` : html`<p class="muted small">None suggested.</p>`}
    ${r.gaps.length ? html`<h3>Gaps and open questions</h3><ul>${r.gaps.map((g) => html`<li>${g}</li>`)}</ul>` : ""}
    ${r.cautions.length ? html`<h3>Cautions</h3><ul>${r.cautions.map((c) => html`<li>${c}</li>`)}</ul>` : ""}
    ${canEdit() ? html`<button class="btn sm" data-analyst="save-brief">${ico("plus")}Save as a note</button>` : ""}`;
}

function suggestionRow(kind, s, i) {
  const ticked = s.verified && !s.already_in_case;
  return html`<tr>
    <td>${canEdit() ? html`<input type="checkbox" data-pick="${kind}:${i}" aria-label="Add ${s.value || s.title}" ${ticked ? "checked" : ""}>` : ""}</td>
    <td>${kind === "entity" ? html`<span class="pill">${s.type}</span>` : html`${s.date}${s.approximate ? " (approx.)" : ""}`}</td>
    <td><b>${kind === "entity" ? s.value : s.title}</b>${s.details ? html`<div class="muted small">${s.details}</div>` : ""}
      <div class="small" style="margin-top:2px">“${s.quote}”</div></td>
    <td>${s.source ? sourceChips([s.source]) : html`<span class="pill warn">unknown source</span>`}</td>
    <td>${s.verified ? html`<span class="pill ok" title="These exact words were found in the source">checked</span>` : html`<span class="pill warn" title="The quoted words were not found in the source: check by hand">unverified</span>`}
      ${s.already_in_case ? html`<div class="muted small">already in case</div>` : ""}</td></tr>`;
}

function extractView(answer) {
  const r = answer.result;
  const table = (kind, rows, heads) => html`<div style="overflow-x:auto"><table class="table"><thead><tr><th></th>${heads.map((h) => html`<th>${h}</th>`)}</tr></thead>
    <tbody>${rows.map((s, i) => suggestionRow(kind, s, i))}</tbody></table></div>`;
  return html`${header(answer)}
    ${r.possible_minors_removed ? html`<p class="small">${ico("shield")} ${r.possible_minors_removed} person(s) who may be children were left out. Argus never profiles children.</p>` : ""}
    <h3>Entities (${r.entities.length})</h3>${r.entities.length ? table("entity", r.entities, ["Type", "Value and the words it came from", "Source", "Check"]) : html`<p class="muted small">None found.</p>`}
    <h3>Dated events (${r.events.length})</h3>${r.events.length ? table("event", r.events, ["Date", "Event and the words it came from", "Source", "Check"]) : html`<p class="muted small">None found.</p>`}
    ${canEdit() && (r.entities.length || r.events.length) ? html`<p class="muted small">Checked items whose words were found in their source are ticked. Unverified ones need checking by hand.</p>
      <button class="btn sm primary" data-analyst="add-picked">${ico("plus")}Add ticked to the case</button>` : ""}`;
}

function reportView(answer) {
  return html`${header(answer)}
    ${answer.result.unknown_references.length ? html`<p class="error-text">The draft cites ${answer.result.unknown_references.join(", ")}, which are not in this case: remove or correct them.</p>` : ""}
    <textarea class="input" id="analyst-report" rows="24" style="width:100%;font-family:var(--mono, monospace);font-size:13px" aria-label="Report draft">${answer.result.markdown}</textarea>
    <div style="display:flex;gap:8px;margin-top:8px">
      ${canEdit() ? html`<button class="btn sm" data-analyst="save-report">${ico("plus")}Save as a note</button>` : ""}
      <button class="btn sm" data-analyst="download-report">${ico("download")}Download (.md)</button></div>`;
}

const VIEWS = { brief: briefView, extract: extractView, report: reportView };

function draw() {
  if (!el) return;
  if (!status.available) {
    setHTML(el, html`<div class="card card-pad"><h2>${ico("sparkle")}AI analyst</h2>
      <p>The AI analyst reads this case (notes, entities, events and the text of its evidence) and briefs you, suggests next steps, finds names and dates in documents, and drafts reports.</p>
      <p class="muted">To use it, sign in to an Argus account (it is paid for with Argus credits) or set your own Claude API key: <code>ARGUS_ANTHROPIC_API_KEY</code>.</p></div>`);
    return;
  }
  const done = results.get(caseRef.id) || {};
  setHTML(el, html`<div class="card card-pad">
      <div class="card-head"><h2>${ico("sparkle")}AI analyst</h2><span class="muted small">${status.via === "connect" ? "Argus Connect (credits)" : "your own Anthropic key"} · ${status.model}</span></div>
      <p class="muted small">Reads this case and helps you think. It is sent to Anthropic, the company that makes Claude, only when you confirm. Its findings cite their sources; check them before relying on them.</p>
      <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-top:12px">
        ${Object.entries(TASKS).map(([task, [label, text]]) => html`<div class="note">
          <b>${label}</b><p class="muted small" style="margin:4px 0 8px">${text}</p>
          ${canEdit() ? html`<button class="btn sm ${done[task] ? "" : "primary"}" data-analyst="run" data-task="${task}" ${busy ? "disabled" : ""}>${busy === task ? "Working… (this can take a few minutes)" : done[task] ? "Run again" : label}</button>` : html`<span class="muted small">Analysts can run this.</span>`}</div>`)}
      </div></div>
    ${Object.keys(VIEWS).filter((t) => done[t]).map((t) => html`<div class="card card-pad" style="margin-top:16px"><div class="card-head"><h2>${TASKS[t][0]}</h2></div>${VIEWS[t](done[t])}</div>`)}`);
}

async function run(task) {
  const p = await api.get(`/api/cases/${enc(caseRef.id)}/analyst/preview?task=${enc(task)}`);
  const ok = await confirmDialog({
    title: `${TASKS[task][0]}: send this case to the AI analyst?`,
    message: html`<p>About <b>${size(p.characters)}</b> from <b>${p.sources}</b> source${p.sources === 1 ? "" : "s"} (notes, entities, events${p.documents.length ? ` and ${p.documents.length} document${p.documents.length === 1 ? "" : "s"}` : ""}) will be sent to <b>Anthropic</b>, the company that makes Claude${p.via === "connect" ? ", through the Argus account service, which keeps none of it" : ", using your own key"}.</p>
      ${p.shortened.length || p.left_out.length ? html`<p class="small">${p.shortened.length ? `Shortened to fit: ${p.shortened.join(", ")}. ` : ""}${p.left_out.length ? `Left out (too large): ${p.left_out.join(", ")}.` : ""}</p>` : ""}
      ${p.unreadable.length ? html`<p class="muted small">Not readable as text, so not sent: ${p.unreadable.join(", ")}.</p>` : ""}
      ${p.anonymous_case ? html`<p class="error-text">${ico("shield")} This is an anonymous case. Its material, including what you know about the subjects, will leave this computer. Only continue if that is safe.</p>` : ""}
      <p>${p.via === "connect" ? html`Cost: <b>${p.price} Argus credits</b> (refunded if it fails).` : "Billed to your Anthropic account."} Each document sent is recorded in its chain of custody.</p>`,
    confirm: p.via === "connect" ? `Send (${p.price} credits)` : "Send",
    danger: p.anonymous_case,
  });
  if (!ok) return;
  busy = task;
  draw();
  try {
    const answer = await api.post(`/api/cases/${enc(caseRef.id)}/analyst`, { task, acknowledged: true });
    results.set(caseRef.id, { ...(results.get(caseRef.id) || {}), [task]: answer });
  } finally {
    busy = null;
    draw();
  }
}

function briefNote(r) {
  const cite = (s) => s.map((x) => `[${x.ref}] ${x.title}`).join("; ");
  return [`Summary\n${r.summary}`,
    `Key findings\n${r.key_findings.map((f) => `- (${f.confidence}) ${f.finding}${f.sources.length ? ` (${cite(f.sources)})` : ""}`).join("\n")}`,
    `Next steps\n${r.next_steps.map((s, i) => `${i + 1}. ${s.action}: ${s.why} How: ${s.how}`).join("\n")}`,
    r.gaps.length ? `Gaps\n${r.gaps.map((g) => `- ${g}`).join("\n")}` : "",
    r.cautions.length ? `Cautions\n${r.cautions.map((c) => `- ${c}`).join("\n")}` : ""].filter(Boolean).join("\n\n");
}

async function addPicked(answer) {
  const picked = [...el.querySelectorAll("[data-pick]:checked")].map((b) => b.dataset.pick.split(":"));
  if (!picked.length) return toast("Tick the items to add", "error");
  let added = 0;
  for (const [kind, index] of picked) {
    const s = answer.result[kind === "entity" ? "entities" : "events"][Number(index)];
    const origin = `${s.source ? `[${s.source.ref}] ${s.source.title}` : "unknown source"}${s.verified ? "" : " (unverified)"}`;
    const body = kind === "entity"
      ? { kind: "entity", title: s.value, body: `Found by the AI analyst in ${origin}: “${s.quote}”`,
        data: { type: s.type, value: s.value, attributes: { ...(s.details ? { details: s.details } : {}), found_in: origin.slice(0, 900) } } }
      : { kind: "event", title: s.title, occurred_at: s.occurred_at,
        body: `${s.approximate ? `Date given as ${s.date}. ` : ""}Found by the AI analyst in ${origin}: “${s.quote}”` };
    await api.post(`/api/cases/${enc(caseRef.id)}/items`, body);
    added++;
  }
  toast(`${added} item${added === 1 ? "" : "s"} added to the case`, "success");
  onChanged();
}

export function initAnalyst(root, changed) {
  onChanged = changed;
  on(root, "click", "[data-analyst]", async (e, btn) => {
    e.preventDefault();
    const done = results.get(caseRef?.id) || {};
    try {
      const act = btn.dataset.analyst;
      if (act === "run") return await run(btn.dataset.task);
      if (act === "add-picked") return await addPicked(done.extract);
      if (act === "save-brief") {
        await api.post(`/api/cases/${enc(caseRef.id)}/items`, { kind: "note", title: `AI analyst briefing (${formatDate(done.brief.generated_at)})`, body: briefNote(done.brief.result).slice(0, 50000) });
        toast("Saved as a note", "success");
        return onChanged();
      }
      const text = $("#analyst-report")?.value || "";
      if (act === "save-report") {
        await api.post(`/api/cases/${enc(caseRef.id)}/items`, { kind: "note", title: "Report draft (AI analyst)", body: text.slice(0, 50000) });
        toast("Saved as a note", "success");
        return onChanged();
      }
      if (act === "download-report") {
        const a = document.createElement("a");
        a.href = URL.createObjectURL(new Blob([text], { type: "text/markdown" }));
        a.download = `argus-case-${caseRef.id}-report.md`;
        a.click();
        setTimeout(() => URL.revokeObjectURL(a.href), 5000);
      }
    } catch (err) {
      toast(err.message, "error", 8000);
    }
  });
}
