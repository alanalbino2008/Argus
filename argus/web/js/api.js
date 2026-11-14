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
  return status === 429 ? "Too many requests — try again shortly" : `Request failed (${status})`;
}

export async function request(path, { method = "GET", body, raw = false } = {}) {
  const headers = {};
  if (currentKey()) headers.Authorization = `Bearer ${currentKey()}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  if (res.status === 401) {
    window.dispatchEvent(new CustomEvent("argus:auth-required"));
    throw new ApiError(401, "Please sign in");
  }
  if (raw) {
    if (!res.ok) throw new ApiError(res.status, `Request failed (${res.status})`);
    return res;
  }
  const data = res.status === 204 ? null : await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, describe(data, res.status));
  return data;
}

export const api = {
  get: (path) => request(path),
  post: (path, body) => request(path, { method: "POST", body: body ?? {} }),
  patch: (path, body) => request(path, { method: "PATCH", body }),
  del: (path) => request(path, { method: "DELETE" }),
};

/** Check a key without storing it (sign-in). */
export async function whoAmI(key = currentKey()) {
  const res = await fetch("/api/me", { headers: key ? { Authorization: `Bearer ${key}` } : {} });
  return res.ok ? res.json() : null;
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

export const enc = encodeURIComponent;
