# 55 — The Argus Desktop App (Plain-English Guide)

> Purpose: explain how investigators install Argus Personal, and how you publish a new version.
> Useful for questions like:
> * "how does a customer get Argus onto their laptop?"
> * "how do I release an update?"
> * "why does Windows or macOS warn about the installer?"

## 1. What the investigator gets

One download, no technical steps:

* **Windows**: `Argus-Setup-<version>-windows-x64.exe`. Double-click, Next, done. No
  administrator rights needed (it installs just for that person). It adds Argus to the Start
  menu and, if they tick the box, to the desktop.
* **Mac** (Apple silicon): `Argus-<version>-macos-arm64.dmg`. Open it and drag Argus into
  Applications.
* **Linux**: `Argus-<version>-linux-x64.tar.gz`. Unpack it and run `Argus/Argus`.

Everything is inside: Python, Argus itself, and a private screenshot browser (Chrome's
"headless shell") for capturing web pages as evidence. If that browser is ever missing, Argus
uses Chrome or Edge if the computer has one.

Clicking the icon opens Argus in the person's web browser. Argus runs only for this computer
(address `127.0.0.1`): nobody else on the same wifi or office network can reach it.

* **Clicking the icon again** just brings up the copy that's already running.
* **Quit Argus** is in Settings → *Argus on this computer*. (Closing the browser tab leaves
  Argus running in the background, ready for the next tab.)
* **Cases are never in the program folder.** They live in the usual place for app data
  (Windows `%APPDATA%\Argus`, Mac `~/Library/Application Support/Argus`, Linux
  `~/.local/share/argus`). Updating, reinstalling or uninstalling never touches them.
* **Logs** for support are in the `logs` folder there.

## 2. What's built into the installer

So investigators have nothing to configure, each installer carries two **public** values:

| Setting | What it is | Where it comes from |
|---|---|---|
| `ARGUS_ACCOUNT_SERVER_URL` | your account service's address | GitHub repository variable |
| `ARGUS_LICENCE_PUBLIC_KEY` | the key that checks licences | your account service: `GET /api/accounts/public-key` |

Set both once in GitHub: **Settings → Secrets and variables → Actions → Variables**. They
are public by design (anyone can read an installer), so never put a secret there; the build
refuses to copy anything but these two.

## 3. Releasing a new version

1. Push a version tag (for example `v1.55.0`), as for every release.
2. GitHub builds the app on real Windows, Mac and Linux machines, **tests each one** (it
   starts, serves the app, takes a screenshot with the bundled browser, a second click hands
   over, Quit works; on Windows it also installs and uninstalls), and attaches the installers
   and a checksum file to the release.
3. In your **owner console → Desktop app**, enter the new version and the download page (your
   GitHub release page, or your website). Installed copies check once a day and show
   *"Argus 1.55.0 is available"* with a **Download the update** button. Running the new
   installer updates in place and keeps every case.

You can also build without releasing: **Actions → Desktop app → Run workflow**. The
installers appear under that run's *Artifacts*.

## 4. Signing (the security warnings)

Windows and macOS warn about programs from publishers they don't know:

* **Windows** SmartScreen: "Windows protected your PC" → *More info* → *Run anyway*.
* **macOS** Gatekeeper: "Argus can't be opened because Apple cannot check it" → open
  **System Settings → Privacy & Security** and click *Open Anyway*.

To remove the warnings, buy code-signing certificates and add them as GitHub secrets; the
build then signs (and on Mac, notarises) automatically:

| Platform | What to buy | GitHub secrets |
|---|---|---|
| Windows | a code-signing certificate (OV or EV) | `WINDOWS_CERT_PFX_BASE64`, `WINDOWS_CERT_PASSWORD` |
| macOS | Apple Developer Program (Developer ID Application certificate) | `APPLE_CERT_P12_BASE64`, `APPLE_CERT_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_APP_PASSWORD` |

## 5. Privacy

The desktop app talks to the account service for exactly what Argus Personal always did
(sign-in and licence renewal), plus once a day **the version number installed**, to offer
updates. Nothing about cases.

## 6. For developers

* Launcher: `argus/desktop.py` (one copy, port, bundled settings and browser, log file,
  `--self-test`).
* Build: `packaging/desktop/` (`argus.spec` for PyInstaller, `argus.iss` for Inno Setup, the
  icon, settings and browser scripts, and `smoke_test.py`), run by
  `.github/workflows/desktop.yml`.
* Build locally:

  ```bash
  pip install . pyinstaller==6.22.3
  python packaging/desktop/make_icons.py build/icons
  python packaging/desktop/write_config.py build/argus-desktop.json
  python packaging/desktop/fetch_browser.py build/browser
  pyinstaller packaging/desktop/argus.spec --noconfirm --distpath dist --workpath build/pyinstaller
  python packaging/desktop/smoke_test.py dist/Argus/Argus
  ```
