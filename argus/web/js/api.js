// API access: API key handling, JSON helpers, consistent errors, authenticated downloads.
// The key lives in sessionStorage (cleared with the tab) and is sent as a Bearer header.

const KEY = "argus_api_key";

export function storedKey() {
  try { return sessionStorage.getItem(KEY) || ""; } catch { return ""; }
}

export function storeKey(key) {
  try { sessionStorage.setItem(KEY, key); } catch { /* storage blocked: key kept for this page only */ }
  memoryKey = key;
}

export function clearKey() {
  try { sessionStorage.removeItem(KEY); } catch { /* ignore */ }
  memoryKey = "";
}

let memoryKey = "";
const currentKey = () => storedKey() || memoryKey;

// ------------------------------------------------------------------ active workspace
const WS = "argus.workspace";
let memoryWorkspace = "";

export function activeWorkspace() {
  try { return localStorage.getItem(WS) || memoryWorkspace; } catch { return memoryWorkspace; }
}

export function setActiveWorkspace(id) {
  memoryWorkspace = id || "";
  try { if (id) localStorage.setItem(WS, id); else localStorage.removeItem(WS); } catch { /* ignore */ }
}

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function describe(body, status) {
  const d = body && body.detail;
  if (Array.isArray(d)) return d.map((e) => e.msg).join("; ");
  if (typeof d === "string") return d;
  if (d && typeof d === "object" && typeof d.message === "string") return d.message;
  return status === 429 ? "Too many requests — try again shortly" : `Request failed (${status})`;
}

// Phase 90: an action waiting for a second administrator's approval. The request is remembered per
// exact action, and sent again with its approval once someone else has approved it.
const APPROVALS = "argus_approvals";
function approvalStore() {
  try { return JSON.parse(sessionStorage.getItem(APPROVALS) || "{}"); } catch { return {}; }
}
function setApproval(key, id) {
  const all = approvalStore();
  if (id) all[key] = id; else delete all[key];
  try { sessionStorage.setItem(APPROVALS, JSON.stringify(all)); } catch { /* private mode: asked again next time */ }
}

export async function request(path, { method = "GET", body, raw = false } = {}) {
  const headers = {};
  const isFormBody = typeof FormData !== "undefined" && body instanceof FormData;
  const approvalKey = `${activeWorkspace() || ""} ${method} ${path} ${isFormBody || body === undefined ? "" : JSON.stringify(body)}`;
  const approval = approvalStore()[approvalKey];
  if (approval) headers["X-Argus-Approval"] = approval;
  if (currentKey()) headers.Authorization = `Bearer ${currentKey()}`;
  if (activeWorkspace()) headers["X-Argus-Workspace"] = activeWorkspace(); // every call is scoped to one team
  const isForm = typeof FormData !== "undefined" && body instanceof FormData; // file uploads
  if (body !== undefined && !isForm) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { method, headers, body: body === undefined ? undefined : isForm ? body : JSON.stringify(body) });
  if (res.status === 401) {
    window.dispatchEvent(new CustomEvent("argus:auth-required"));
    throw new ApiError(401, "Please sign in");
  }
  if (res.status === 402) {
    const info = await res.json().catch(() => null);
    window.dispatchEvent(new CustomEvent("argus:read-only", { detail: info?.detail || "" }));
    throw new ApiError(402, info?.detail || "Your subscription does not allow new work right now");
  }
  if (res.status === 423) {
    const info = await res.json().catch(() => null);
    if (info?.vault_locked) window.dispatchEvent(new CustomEvent("argus:vault-locked"));
    throw new ApiError(423, info?.detail || "The case vault is locked");
  }
  if (approval && (res.ok && res.status !== 202 || res.status === 403)) setApproval(approvalKey, null); // spent or refused
  if (res.status === 202 && res.headers.get("X-Argus-Approval-Request")) {
    const info = await res.json().catch(() => null);
    setApproval(approvalKey, info?.approval?.id);
    const error = new ApiError(202, "Sent for approval: another administrator must approve this. Do it again once they have.");
    error.approval = info?.approval;
    window.dispatchEvent(new CustomEvent("argus:approval-requested", { detail: info?.approval }));
    throw error;
  }
  if (raw) {
    if (!res.ok) throw new ApiError(res.status, describe(await res.json().catch(() => null), res.status));
    return res;
  }
  const data = res.status === 204 ? null : await res.json().catch(() => null);
  if (res.status === 403 && data?.terms) window.argusAskTerms?.(); // updated terms to accept first
  if (!res.ok) {
    const error = new ApiError(res.status, describe(data, res.status));
    if (data && typeof data.detail === "object") error.detail = data.detail; // structured errors (e.g. query position)
    throw error;
  }
  return data;
}

export const api = {
  get: (path) => request(path),
  post: (path, body) => request(path, { method: "POST", body: body ?? {} }),
  patch: (path, body) => request(path, { method: "PATCH", body }),
  put: (path, body) => request(path, { method: "PUT", body }),
  del: (path) => request(path, { method: "DELETE" }),
};

/** Check a key without storing it (sign-in); with no key, the session cookie (SSO) is used. */
export async function whoAmI(key = currentKey()) {
  const res = await fetch("/api/me", { headers: key ? { Authorization: `Bearer ${key}` } : {} });
  return res.ok ? res.json() : null;
}

/** Which sign-in methods the server offers (public). */
export async function authConfig() {
  try {
    const res = await fetch("/api/auth/config");
    return res.ok ? await res.json() : { sso: { enabled: false }, api_keys: true };
  } catch {
    return { sso: { enabled: false }, api_keys: true };
  }
}

/** Argus Personal: sign in (or create an account) with an Argus account; the server sets a session cookie. */
export async function personalSignIn(path, body) {
  const res = await fetch(`/api/personal/${path}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, describe(data, res.status));
  return data;
}

/** End an SSO session. Returns the provider's sign-out URL if it offers single logout. */
export async function endSession() {
  try {
    const res = await fetch("/api/auth/logout", { method: "POST" });
    return res.ok ? (await res.json()).end_session_url : null;
  } catch {
    return null;
  }
}

/** Plain <a href> links cannot carry the Authorization header, so download via fetch. */
export async function download(path, filename) {
  const res = await request(path, { raw: true });
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** POST that returns a file (e.g. a PDF report): saves it and returns the response headers. */
export async function downloadPost(path, body) {
  const res = await request(path, { method: "POST", body, raw: true });
  const name = /filename="([^"]+)"/.exec(res.headers.get("Content-Disposition") || "")?.[1] || "download";
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  return res.headers;
}

export const enc = encodeURIComponent;
