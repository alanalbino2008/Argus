# 04 — Engineering Quality & Delivery (Plain-English Guide)

> Purpose: explain how Argus is kept correct, secure and releasable — the "how do you know it
> works?" chapter.

## 1. The idea: make mistakes impossible to merge

Humans forget things. So every rule we care about is checked by a machine on every push
(**continuous integration**, CI). If any check fails, the change shows a red ✗ on GitHub.

| Tool | Catches | Analogy |
|---|---|---|
| **ruff** | Likely bugs, unused code, insecure patterns (its `S` rules are *bandit*, the Python security linter), asyncio mistakes | Spell- and grammar-checker |
| **ruff format** | Inconsistent style | Auto-formatting in Word |
| **mypy** | Passing the wrong *type* of thing between parts of the program | Checking plugs fit sockets before switching on |
| **pytest + coverage** | Broken behaviour; untested code | Crash tests, plus a map of which parts were crash-tested |
| **pip-audit** | Dependencies with known CVEs | Product-recall check |
| **CodeQL** | Deeper security flaws via data-flow analysis | A security auditor reading every line |
| **Dependabot** | Outdated dependencies | Automatic update reminders, as pull requests |

## 2. What the tools actually found (real bugs, not theory)

This is the best evidence that the effort was worth it — use these in interviews:

1. **The TLS analyzer never worked.** It disables certificate verification so it can inspect
   any certificate, but Python's `getpeercert()` returns an *empty dict* for unverified
   certificates. Result: "Unknown CA", no dates and **zero subdomains** for every target, while
   reporting success. Found while fixing a type error; proven with a local TLS server; fixed by
   parsing the raw certificate with the `cryptography` library.
2. **Undeclared dependency.** Alembic worked on my machine because it happened to be installed.
   Installing the built package into an *empty* environment crashed on startup. That check is
   now a permanent CI job ("package").
3. **Secrets could leak into the Docker image.** With no `.dockerignore`, `COPY . .` would copy
   `.env` (admin key), local databases and `.git` into the image. Now the image contains only
   the installed package, and CI verifies it.
4. **Shodan could receive internal IPs** — it relied on a flag set by another module running *at
   the same time* (a race condition).
5. **GitHub "blog" URLs with paths** became invalid domain entities (`site.com/blog`).
6. **An `assert` used for a runtime check** — Python deletes asserts under `python -O`. Bandit
   flagged it.

> **Interview line:** "Adding static analysis and offline tests for every collector surfaced six
> real defects, including one where the TLS module silently returned nothing for every target."

## 3. Testing without the internet

Tests that call real websites are slow and *flaky* (fail randomly when a site is down). Argus's
~150 tests run in seconds, fully offline:

* **Fake HTTP session** replaying realistic API responses (crt.sh, RDAP, Shodan, GitHub…).
* **Real DNS record objects** built from zone-file text, fed through a fake resolver.
* **Real local servers** for the HTTP client and a real TLS handshake.

**Coverage** (87%) is the share of code lines executed by tests. CI fails below 85%, so coverage
can't silently decay. Coverage isn't proof of correctness — it tells you what is *definitely*
untested.

## 4. Database migrations (Alembic)

When a new column is added, existing databases must be upgraded without losing data. Each change
is a numbered, reviewable **migration script**; Argus applies pending ones at startup. A test
compares the migrated schema with the code's models and **fails if someone changes a model but
forgets the migration**. Databases created before migrations existed are detected and adopted.

## 5. Releases

* The version lives in **one place** (`argus/__init__.py`); the package, API and User-Agent read it.
* Pushing a tag like `v1.4.0` triggers the release workflow: it refuses to run if the tag and
  version disagree, runs the tests, builds the package, creates a GitHub Release with notes taken
  from `CHANGELOG.md`, and publishes a Docker image to the GitHub Container Registry.
* **Supply-chain care:** workflows use only GitHub's and Docker's own actions plus the `gh` CLI,
  run with read-only permissions by default, and grant write access only to the release job.

## 6. Questions you might be asked

* **"What's the difference between linting and testing?"** Linting reads code without running it; tests run it.
* **"Why test on four Python versions?"** Users run different versions; a feature from 3.11 would break 3.10 users.
* **"Is 100% coverage the goal?"** No — it shows what *ran*, not that results were checked. The gate stops decay; good assertions matter more.
* **"What's a supply-chain attack?"** Compromising a dependency or CI action to reach everyone who uses it (e.g. the 2025 `tj-actions` incident) — hence pinned, first-party actions and least-privilege tokens.
