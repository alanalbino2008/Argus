// The account service's "join a team" page. The invitation token travels in the URL fragment
// (#token=...), so it never reaches server logs; it is removed from the address bar at once.
(() => {
  const $ = (s) => document.querySelector(s);
  window.addEventListener("hashchange", () => location.reload());
  const token = new URLSearchParams(location.hash.slice(1)).get("token");
  if (token) history.replaceState(null, "", location.pathname);

  async function post(path, body) {
    const res = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Something went wrong; try again");
    return data;
  }

  function show(text) {
    $("#intro").textContent = text;
  }

  async function start() {
    if (!token) return show("This page needs the link from your invitation email.");
    let info;
    try {
      info = await post("/api/teams/join/info", { token });
    } catch (err) {
      return show(err.message);
    }
    show(info.has_account
      ? `${info.team} invited you to their team. Enter the password of your Argus account to join.`
      : `${info.team} invited you to their team. Choose a password to create your Argus account (at least 12 characters; a few unrelated words work well).`);
    $("#email").value = info.email;
    $("#name-field").hidden = info.has_account;
    $("#forgot").hidden = !info.has_account;
    $("#password").autocomplete = info.has_account ? "current-password" : "new-password";
    $("#password-label").textContent = info.has_account ? "Your password" : "Choose a password";
    const form = $("#join");
    form.hidden = false;
    $("#password").focus();
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const error = form.querySelector(".error-text");
      const button = form.querySelector("button");
      error.textContent = "";
      button.disabled = true;
      try {
        const r = await post("/api/teams/join", { token, password: $("#password").value, name: $("#name").value.trim() });
        form.hidden = true;
        $("#intro").hidden = true;
        const done = $("#done");
        done.textContent = r.detail;
        done.hidden = false;
      } catch (err) {
        error.textContent = err.message;
      } finally {
        button.disabled = false;
      }
    });
  }
  start();
})();
