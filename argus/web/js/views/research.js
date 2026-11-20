// Research tools in a case: a page's history in the Internet Archive (any version can be captured
// as evidence), and where else an image appears (TinEye inside Argus; other engines in the browser).

import { api, enc } from "../api.js";
import { ico } from "../components.js";
import { $, formatDate, html, on, setHTML, toast } from "../dom.js";

const safe = (u) => /^https?:\/\//i.test(u || "");
const ext = (url, text) => html`<a href="${url}" target="_blank" rel="noopener noreferrer nofollow" referrerpolicy="no-referrer">${text} ↗</a>`;

/** One-click searches on other engines for an image's address (they open in the browser). */
export function imageSearchLinks(url) {
  if (!safe(url)) return "";
  const u = encodeURIComponent(url);
  const engines = [["Google Lens", `https://lens.google.com/uploadbyurl?url=${u}`], ["Bing", `https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:${u}`],
    ["Yandex", `https://yandex.com/images/search?rpt=imageview&url=${u}`], ["TinEye", `https://tineye.com/search?url=${u}`]];
  return html`<div class="small" style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">${ico("search")} Search this picture elsewhere:
    ${engines.map(([name, link]) => ext(link, name))}</div>
    <p class="muted small" style="margin:4px 0 0">These open the search engine in your browser: it sees the picture's address and your connection. In a case, Reverse image search goes through the case's route instead.</p>`;
}

function modal(title, intro, body) {
  document.querySelector(".research-modal")?.remove();
  const root = document.createElement("div");
  root.className = "modal-root open research-modal";
  setHTML(root, html`<div class="modal-backdrop" data-close-research></div>
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="research-title" style="max-width:760px;width:calc(100vw - 32px)">
      <div class="modal-head"><div><h2 id="research-title">${title}</h2><p class="muted small">${intro}</p></div>
        <button type="button" class="btn ghost sm icon" data-close-research aria-label="Close">${ico("x")}</button></div>
      <div class="modal-body" style="max-height:65vh;overflow:auto">${body}</div></div>`);
  document.body.append(root);
  root.addEventListener("click", (e) => { if (e.target.closest("[data-close-research]")) root.remove(); });
  root.addEventListener("keydown", (e) => { if (e.key === "Escape") root.remove(); });
  return root;
}

// ------------------------------------------------------------------ page history
export function openPageHistory(caseId, onCaptured, preset = "") {
  const root = modal("Page history", "Every different version of a web page that the Internet Archive holds. Open one to read it, or capture it into this case as evidence (with a fingerprint and a record of who handled it).",
    html`<form id="history-form" class="filters"><input class="input" id="history-url" placeholder="https://example.com/about" value="${preset}" style="flex:1;min-width:220px" aria-label="Web address" required>
      <button class="btn primary" type="submit">${ico("search")}Look up</button></form><div id="history-out" style="margin-top:12px"></div>`);
  const out = $("#history-out", root);
  $("#history-url", root).focus();
  $("#history-form", root).addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = $("#history-url", root).value.trim();
    setHTML(out, html`<p class="muted small">Asking the Internet Archive…</p>`);
    try {
      const h = await api.get(`/api/cases/${enc(caseId)}/page-history?url=${encodeURIComponent(url)}`);
      if (!h.versions.length) return setHTML(out, html`<p class="muted">The archive holds no copy of ${h.url}. Capture it now (Capture a page) to keep today's version.</p>`);
      setHTML(out, html`<p class="small"><b>${h.versions.length} different version${h.versions.length === 1 ? "" : "s"}</b> of ${h.url}, from ${formatDate(h.first_seen)} to ${formatDate(h.last_seen)}.</p>
        <table class="table"><tbody>${h.versions.slice().reverse().map((v) => html`<tr>
          <td>${formatDate(v.date)}${v.status && v.status !== "200" ? html` <span class="pill warn">${v.status}</span>` : ""}</td>
          <td class="small">${ext(v.archive_url, "Open")}</td>
          <td class="actions"><button class="btn sm" data-capture="${v.archive_url}" data-date="${v.date}">${ico("eye")}Capture as evidence</button></td></tr>`)}</tbody></table>`);
    } catch (err) {
      setHTML(out, html`<p class="error-text">${err.message}</p>`);
    }
  });
  on(root, "click", "[data-capture]", async (_e, btn) => {
    btn.disabled = true;
    btn.textContent = "Capturing…";
    try {
      await api.post(`/api/cases/${enc(caseId)}/captures`, { url: btn.dataset.capture, note: `Archived copy (Internet Archive) from ${formatDate(btn.dataset.date)} of ${$("#history-url", root).value.trim()}` });
      btn.textContent = "Captured";
      toast("The archived version is in the case's evidence", "success");
      onCaptured?.();
    } catch (err) {
      btn.disabled = false;
      btn.textContent = "Capture as evidence";
      toast(err.message, "error", 6000);
    }
  });
}

// ------------------------------------------------------------------ reverse image search
export async function openImageSearch(caseId, preset = "") {
  const status = await api.get("/api/image-search").catch(() => ({ tineye: false }));
  const root = modal("Reverse image search", "Where else a picture appears on the web: other profiles using the same photo, the site it was first published on, older copies.",
    html`<form id="image-form" class="filters"><input class="input" id="image-url" placeholder="The picture's web address: https://…/photo.jpg" value="${preset}" style="flex:1;min-width:220px" aria-label="Picture address" required>
      <button class="btn primary" type="submit">${ico("search")}${status.tineye ? "Search with TinEye" : "Show search links"}</button></form>
      ${status.tineye ? "" : html`<p class="muted small" style="margin-top:6px">TinEye results inside Argus need a TinEye key (in Argus Personal: Settings → Your own API keys; on a shared server, your administrator adds it) or an Argus account with credits. The links below work without one.</p>`}
      <div id="image-links" style="margin-top:10px"></div><div id="image-out" style="margin-top:12px"></div>`);
  const out = $("#image-out", root);
  $("#image-url", root).focus();
  $("#image-form", root).addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = $("#image-url", root).value.trim();
    if (!safe(url)) return setHTML(out, html`<p class="error-text">Give the picture's web address, starting with https://</p>`);
    setHTML($("#image-links", root), imageSearchLinks(url));
    if (!status.tineye) return setHTML(out, html``);
    setHTML(out, html`<p class="muted small">Asking TinEye…</p>`);
    try {
      const r = await api.post(`/api/cases/${enc(caseId)}/image-search`, { image_url: url });
      if (!r.matches.length) return setHTML(out, html`<p class="muted">TinEye has not seen this picture anywhere else. That can mean it's original, or only that it isn't indexed: try the other engines too.</p>`);
      setHTML(out, html`<p class="small"><b>Found on ${r.total} page${r.total === 1 ? "" : "s"}</b>${r.matches.length < r.total ? `; the ${r.matches.length} best matches below` : ""}. Capture any page as evidence with Capture a page.</p>
        <table class="table"><tbody>${r.matches.map((m) => html`<tr><td><b>${m.domain || "?"}</b>${m.size ? html`<div class="muted small">${m.size}</div>` : ""}</td>
          <td class="small">${m.pages.map((p) => html`<div>${safe(p.url) ? ext(p.url, p.url.length > 70 ? `${p.url.slice(0, 70)}…` : p.url) : p.url}${p.crawled ? html` <span class="muted">· seen ${p.crawled}</span>` : ""}</div>`)}</td>
          <td class="small">${m.first_seen ? `first seen ${m.first_seen}` : ""}</td></tr>`)}</tbody></table>`);
    } catch (err) {
      setHTML(out, html`<p class="error-text">${err.message}</p>`);
    }
  });
  if (preset) $("#image-form", root).requestSubmit();
}
