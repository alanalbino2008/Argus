// Runs before first paint (classic script, no inline JS under the CSP): apply the saved theme,
// or follow the operating system until the user picks one.
(function () {
  var KEY = "argus_theme";
  var media = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

  function saved() {
    try { return localStorage.getItem(KEY) || "system"; } catch (e) { return "system"; }
  }
  function resolve(choice) {
    if (choice === "light" || choice === "dark") return choice;
    return media && media.matches ? "dark" : "light";
  }
  function apply(choice) {
    document.documentElement.setAttribute("data-theme", resolve(choice));
    document.dispatchEvent(new CustomEvent("argus:theme"));
  }

  window.argusTheme = {
    choice: saved,
    current: function () { return resolve(saved()); },
    set: function (choice) {
      try { localStorage.setItem(KEY, choice); } catch (e) { /* ignore */ }
      apply(choice);
    },
    toggle: function () { this.set(this.current() === "dark" ? "light" : "dark"); },
  };

  apply(saved());
  if (media && media.addEventListener) {
    media.addEventListener("change", function () { if (saved() === "system") apply("system"); });
  }
})();
