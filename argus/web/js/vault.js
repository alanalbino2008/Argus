// The case vault in the browser: the unlock screen, the lock button, and the vault's status.
//
// When any request answers 423 (vault locked), the unlock screen covers the app. Unlocking
// reloads the page, so every view is drawn again from decrypted data.

import { api } from "./api.js";
import { $, toast } from "./dom.js";

let usingCode = false;
export let vaultStatus = null;

function showLock() {
  $("#vault-lock").hidden = false;
  $("#btn-vault-lock").hidden = true;
  setTimeout(() => (usingCode ? $("#vault-code") : $("#vault-passphrase")).focus(), 50);
}

export async function refreshVault() {
  vaultStatus = await api.get("/api/vault/status").catch(() => null);
  $("#btn-vault-lock").hidden = !(vaultStatus?.enabled && !vaultStatus.locked);
  if (vaultStatus?.locked) showLock();
  return vaultStatus;
}

export function initVault() {
  window.addEventListener("argus:vault-locked", showLock);
  $("#vault-mode").addEventListener("click", (e) => {
    e.preventDefault();
    usingCode = !usingCode;
    $("#vault-pass-field").hidden = usingCode;
    $("#vault-code-field").hidden = !usingCode;
    $("#vault-mode").textContent = usingCode ? "Use the passphrase instead" : "Forgot the passphrase? Use the recovery code";
  });
  $("#vault-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const button = $("#vault-submit");
    $("#vault-error").textContent = "";
    button.disabled = true;
    button.textContent = "Unlocking…";
    try {
      await api.post("/api/vault/unlock", usingCode ? { recovery_code: $("#vault-code").value } : { passphrase: $("#vault-passphrase").value });
      $("#vault-passphrase").value = "";
      $("#vault-code").value = "";
      location.reload();
    } catch (err) {
      $("#vault-error").textContent = err.message;
    } finally {
      button.disabled = false;
      button.textContent = "Unlock";
    }
  });
  $("#btn-vault-lock").addEventListener("click", async () => {
    try {
      await api.post("/api/vault/lock");
      document.querySelectorAll(".page").forEach((p) => p.replaceChildren()); // nothing left on screen
      showLock();
    } catch (err) {
      toast(err.message, "error", 8000);
    }
  });
}
