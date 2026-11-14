// DOM helpers. All HTML is built with the `html` tagged template, which escapes every
// interpolated value unless it is itself trusted markup (SafeHTML). Everything Argus
// displays comes from targets (DNS records, profile names, banners...) and must be
// treated as hostile; this makes forgetting to escape the hard thing to do.

class SafeHTML {
  constructor(value) { this.value = value; }
  toString() { return this.value; }
}

const ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" };

export function escape(value) {
  return String(value ?? "").replace(/[&<>"'`]/g, (c) => ESCAPES[c]);
}

function render(value) {
  if (value instanceof SafeHTML) return value.value;
  if (Array.isArray(value)) return value.map(render).join("");
  if (value === null || value === undefined || value === false) return "";
  return escape(value);
}

export function html(strings, ...values) {
  let out = strings[0];
  values.forEach((v, i) => { out += render(v) + strings[i + 1]; });
  return new SafeHTML(out);
}

/** Mark trusted, internally generated markup (e.g. icons) as safe. Never pass target data here. */
export function trusted(markup) {
  return new SafeHTML(markup);
}

export function setHTML(el, content) {
  if (!(content instanceof SafeHTML)) throw new TypeError("setHTML requires html`` output");
  el.innerHTML = content.value;
}

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

export function on(root, event, selector, handler) {
  root.addEventListener(event, (e) => {
    const target = e.target.closest(selector);
    if (target && root.contains(target)) handler(e, target);
  });
}

// ------------------------------------------------------------------ formatting
export function timeAgo(iso) {
  if (!iso) return "never";
  const secs = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (secs < 45) return "just now";
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.round(hours / 24);
  return days < 30 ? `${days} d ago` : new Date(iso).toLocaleDateString();
}

export function formatDate(iso) {
  return iso ? new Date(iso).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "—";
}

export function plural(n, word, pluralWord = `${word}s`) {
  return `${n} ${n === 1 ? word : pluralWord}`;
}

// ------------------------------------------------------------------ toasts
export function toast(message, kind = "info", ms = 4200) {
  const root = $("#toasts");
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.setAttribute("role", kind === "error" ? "alert" : "status");
  setHTML(el, html`<span class="dot"></span><span>${message}</span>`);
  root.append(el);
  setTimeout(() => {
    el.classList.add("leaving");
    setTimeout(() => el.remove(), 220);
  }, ms);
}

// ------------------------------------------------------------------ modals
let lastFocus = null;

export function openModal(id) {
  lastFocus = document.activeElement;
  const root = document.getElementById(id);
  root.classList.add("open");
  root.setAttribute("aria-hidden", "false");
  setTimeout(() => root.querySelector("[autofocus], input, textarea, select, button")?.focus(), 60);
}

export function closeModal(id) {
  const root = document.getElementById(id);
  if (!root.classList.contains("open")) return;
  root.classList.remove("open");
  root.setAttribute("aria-hidden", "true");
  root.dispatchEvent(new Event("modal-closed"));
  lastFocus?.focus?.();
}

export function closeTopModal() {
  const open = $$(".modal-root.open");
  if (open.length) closeModal(open[open.length - 1].id);
  return open.length > 0;
}

export function setupModals() {
  on(document, "click", "[data-close]", (_e, el) => closeModal(el.closest(".modal-root").id));
  $$(".modal-root").forEach((root) => {
    root.addEventListener("mousedown", (e) => { if (e.target === root) closeModal(root.id); });
  });
}

/** Promise-based confirmation dialog (replaces window.confirm). */
export function confirmDialog({ title, message, confirm = "Confirm", danger = false }) {
  return new Promise((resolve) => {
    setHTML($("#confirm-title"), html`${title}`);
    setHTML($("#confirm-message"), html`${message}`);
    const ok = $("#confirm-ok");
    ok.textContent = confirm;
    ok.className = `btn ${danger ? "danger" : "primary"}`;
    const root = $("#confirm-modal");
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      ok.removeEventListener("click", yes);
      root.removeEventListener("modal-closed", no);
      closeModal("confirm-modal");
      resolve(value);
    };
    const yes = () => finish(true);
    const no = () => finish(false); // cancel button, Esc or clicking outside
    ok.addEventListener("click", yes);
    root.addEventListener("modal-closed", no);
    openModal("confirm-modal");
  });
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Copied to clipboard", "success", 2000);
  } catch {
    toast("Copy failed — select the text and copy manually", "error");
  }
}
