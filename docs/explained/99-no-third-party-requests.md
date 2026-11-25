# 99. No third-party requests from the browser

An OSINT tool should not tell anyone who is using it. Until now the web interface loaded its fonts
from Google Fonts, so every investigator's browser contacted Google each time it opened Argus,
revealing the address, time and the fact of using Argus to a third party.

## What changed

* **Fonts are served by Argus** (`/static/vendor/fonts`): Inter (variable) and JetBrains Mono, both
  under the SIL Open Font License (the licence files are next to them). They add about 200 KB and
  are cached by the browser.
* **The Content-Security-Policy allows Argus's own origin only**: no external host in any directive.
  Scripts, fonts, styles, images and connections can only come from Argus. A test fails if any page
  starts loading something from elsewhere.
* **Violations are reported.** The policy names `/api/csp-report` (both `report-uri` and the
  Reporting API's `Reporting-Endpoints`). Browsers send what they blocked; Argus counts it by
  directive (`argus_csp_violations_total`) and logs the blocked host and the page path, never the
  report itself. The endpoint is public (browsers report without credentials), reads at most 16 KB,
  is limited per address, and ignores anything it cannot parse.
* The `ArgusBlockedScriptsInBrowsers` alert fires when browsers block five or more scripts in 15
  minutes: usually a browser extension, possibly an attempt to inject a script into a page.

Inline styles are still allowed (`style-src 'unsafe-inline'`): the interface uses them, and a style
cannot run code. Scripts stay locked to Argus's own files, with no inline scripts and no `eval`.
