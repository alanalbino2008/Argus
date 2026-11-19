// The account service's "Forgot password?" page. The reset token travels in the URL fragment
// (#token=...), so it never reaches server logs; it is removed from the address bar at once.
(() => {
  const $ = (s) => document.querySelector(s);
  // Opening a reset link while this page is already open only changes the fragment: start afresh.
  window.addEventListener("hashchange", () => location.reload());
  const token = new URLSearchParams(location.hash.slice(1)).get("token");
  if (token) history.replaceState(null, "", location.pathname);

  async function post(path, body) {
    const res = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Something went wrong; try again");
    return data;
  }

  function finish(text) {
    $("#ask").hidden = true;
    $("#choose").hidden = true;
    const done = $("#done");
    done.textContent = text;
    done.hidden = false;
  }

  function wire(form, handler) {
    form.hidden = false;
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const error = form.querySelector(".error-text");
      const button = form.querySelector("button");
      error.textContent = "";
      button.disabled = true;
      try {
        await handler();
      } catch (err) {
        error.textContent = err.message;
      } finally {
        button.disabled = false;
      }
    });
  }

  if (token) {
    wire($("#choose"), async () => {
      if ($("#password").value !== $("#again").value) throw new Error("The two passwords are different");
      const r = await post("/api/accounts/password-reset/confirm", { token, password: $("#password").value });
      finish(r.detail);
    });
    $("#password").focus();
  } else {
    wire($("#ask"), async () => {
      const r = await post("/api/accounts/password-reset", { email: $("#email").value.trim() });
      finish(r.detail);
    });
    $("#email").focus();
  }
})();
