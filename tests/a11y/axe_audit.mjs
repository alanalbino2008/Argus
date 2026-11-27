// Accessibility audit: axe-core (WCAG 2.1 A + AA) over every page of a running Argus — desktop in light and
// dark, a phone, the command palette and the phone's "More" sheet. Prints every violation and exits 1 if
// there is any. Driven by tests/test_accessibility.py; CI runs it in the "Accessibility" job.
//
//   node tests/a11y/axe_audit.mjs <base-url> <api-key>
//
// axe-core comes from ARGUS_AXE_JS, or is resolved from the working directory (npm install axe-core).
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(`${process.cwd()}/`);
const { chromium } = require("playwright");
const AXE = readFileSync(process.env.ARGUS_AXE_JS || require.resolve("axe-core/axe.min.js"), "utf8");
const [base, key] = process.argv.slice(2);
const VIEWS = ["executive", "cases", "overview", "graph", "paths", "people", "monitoring", "suppliers", "exposure",
  "ransomware", "remediation", "compliance", "ratings", "history", "settings"];
const CONTEXTS = [
  ["desktop-light", { viewport: { width: 1440, height: 900 } }],
  ["desktop-dark", { viewport: { width: 1440, height: 900 }, colorScheme: "dark" }],
  ["phone", { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true }],
];

async function audit(page) {
  await page.addScriptTag({ content: AXE });
  return page.evaluate(async () => {
    const r = await window.axe.run(document, {
      runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"] }, resultTypes: ["violations"],
    });
    return r.violations.map((v) => ({ rule: v.id, impact: v.impact, help: v.help, url: v.helpUrl,
      nodes: v.nodes.slice(0, 5).map((n) => ({ target: n.target.join(" "), why: (n.failureSummary || "").replace(/\s+/g, " ").slice(0, 240) })) }));
  });
}

async function settle(page) {
  await page.waitForLoadState("networkidle").catch(() => {});
  await page.waitForTimeout(600);
}

const results = {};
const errors = [];
const browser = await chromium.launch();
try {
  for (const [label, options] of CONTEXTS) {
    // The page's Content-Security-Policy (script-src 'self') would block the injected axe script.
    const context = await browser.newContext({ ...options, bypassCSP: true });
    const page = await context.newPage();
    page.on("pageerror", (e) => errors.push(`${label}: ${e.message}`));
    await page.addInitScript((k) => sessionStorage.setItem("argus_api_key", k), key);
    await page.goto(`${base}/#/overview`);
    await settle(page);
    await page.keyboard.press("Escape"); // the first-visit tour
    for (const view of VIEWS) {
      await page.goto(`${base}/#/${view}`);
      await settle(page);
      results[`${label}:${view}`] = await audit(page);
    }
    if (label === "desktop-light") {
      await page.keyboard.press("Control+k");
      await page.waitForTimeout(400);
      results[`${label}:command-palette`] = await audit(page);
      await page.keyboard.press("Escape");
    }
    if (label === "phone") {
      await page.tap("#nav-more");
      await page.waitForTimeout(400);
      results[`${label}:more-sheet`] = await audit(page);
    }
    await context.close();
  }
} finally {
  await browser.close();
}

const failing = Object.entries(results).filter(([, v]) => v.length);
console.log(JSON.stringify({ scanned: Object.keys(results).length, failing: failing.length, errors, violations: Object.fromEntries(failing) }, null, 1));
process.exit(failing.length || errors.length ? 1 : 0);
