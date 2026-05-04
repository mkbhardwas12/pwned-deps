# pwned-deps — Complete Build Brief

One-paragraph summary for the agent that opens this file: Build a free, no-account CLI (and a static drag-drop web page later) that takes a developer's lockfile (package-lock.json, requirements.txt, pnpm-lock.yaml, poetry.lock, uv.lock, Cargo.lock, go.sum, Gemfile.lock, pom.xml) and instantly tells them whether they've installed any package version that is publicly flagged as compromised — supply-chain malware, abandoned-and-hijacked packages, retroactively-published malicious versions. Data source: OSV.dev (Google-maintained federation of GHSA, PyPI Advisory DB, RubySec, Go vuln DB, Cargo Advisory DB, etc.) plus a small repo-managed JSON feed for very-recent campaigns OSV hasn't yet ingested. Special treatment for malicious-package advisories (MAL-*) and the Shai-Hulud campaign family. Distribution: `npx pwned-deps@latest`, `pipx install pwned-deps`, `brew install pwned-deps`. Safety: never executes any code from any advisory or any package in the lockfile being scanned — text/JSON parsing only.

---

## 0. How to use this brief

This is the single source of truth for building pwned-deps end-to-end. Read it top to bottom before writing code. Each step has a test gate that must pass before advancing to the next step. Do not advance past a failed gate — fix and re-run.

The same author also produced `BUILD_PLAN.md` (for an earlier GGUF-scanner project) and `HANDOFF.md` (mid-build state of that project). Both are reference patterns — the safety-contract and Dockerfile/Makefile shape used here is intentionally a copy of that pattern. Reuse where applicable, but everything specific to pwned-deps is in this file.

---

## 1. What we are building & why now

**Problem.** When a supply-chain attack on npm/PyPI/Cargo/etc. is announced, the first thing every affected developer asks is "did I install one of those bad versions?" Today the answer is buried across 5+ sources (vendor blogs, GHSA advisories, OSV, Snyk DB, the package's own security advisories tab, the news article). There is no single tool that takes a lockfile and gives an instant, friendly red/green answer with the specific install timestamp from CI logs and a "what to rotate" list.

**The named near-term news peg.** Mini Shai-Hulud (April 29, 2026) — four `@cap-js/*` SAP-ecosystem packages and `mbt` (Cloud MTA Build Tool) were briefly compromised. Anyone whose CI ran `npm install` during the ~2-4 hour exposure window pulled a credential-stealing payload. ~1,800 victim repos exfiltrated GitHub/npm/AWS/Azure/GCP/K8s creds via attacker-created public GitHub repos. There is no easy way for a developer to confirm whether their pipeline ran during the exposure window without manual log-diving. Sources: SecurityBridge, Wiz, Sophos, The Hacker News, The Register, SecurityWeek, Aikido, Ox Security, SOCRadar, Upwind (all dated April–May 2026).

**Why this can spread.** Universal audience (tens of millions of devs across all major ecosystems). News-cycle native — every new supply-chain incident gives the tool a fresh launch moment. Mini Shai-Hulud is the launch one; XZ-Utils-style and other Shai-Hulud variants will keep coming. Zero friction: `npx pwned-deps@latest` and you have your answer in 5 seconds.

One-sentence value prop: **"Drop your lockfile in, find out if you're pwned."**

Comparable trajectory: Have I Been Pwned reached universal recognition because the answer to "did this affect me?" is the most viral question in security. We are building the supply-chain equivalent.

---

## 2. SAFETY CONTRACT — binding for every commit

These rules apply to every line of code, every dep, every test. They guarantee pwned-deps cannot itself become an attack surface.

1. **No execution of advisory or package content.** We never `npm install`, `pip install`, `cargo build`, or otherwise execute any package version that appears in a lockfile being scanned. Lockfile parsing is text/JSON parsing only.
2. **No `eval`, `exec`, `compile`, `subprocess.run` of user-controlled data.** A `make verify-safety` target greps `src/` and `tests/` for forbidden symbols and fails the build if any appear.
3. **Network calls are allow-listed.** The CLI only talks to `api.osv.dev` (and an opt-in self-hosted advisory feed URL the user configures). No crash-reporting, no telemetry, no analytics. The CLI must work fully offline against a cached database.
4. **Container-only dev.** All testing happens inside `python:3.12-slim` or `node:22-alpine` (whichever the chosen impl uses). Host runs `make` only.
5. **Container is locked down** — non-root user (`appuser`, UID 1000), `--network none --read-only --tmpfs /tmp -v $PWD:/work:ro --rm` on test runs. Source mounted read-only during tests.
6. **No code from compromised packages in our deps.** Pin all deps by exact version + hash (`uv pip compile --generate-hashes` or `npm shrinkwrap` + `--audit-signatures`). On every CI run, pwned-deps runs against its own lockfile (eats its own dogfood). Build fails if our own deps are flagged.
7. **Account hygiene before any publish.** Hardware-key 2FA on GitHub. PyPI 2FA + OIDC trusted publishing (no long-lived tokens). npm 2FA + provenance attestations on publish.
8. **Issue-attachment policy.** README explicitly forbids attaching malicious package tarballs to issues. PoC patterns shared in text only.
9. **No service mode.** CLI + static web page only. We never accept user lockfiles via a hosted backend that we control. The web page is fully client-side (lockfile parsing in WASM/JS, OSV calls direct from browser to api.osv.dev).
10. **Eat your own dog food.** Every release runs `pwned-deps check ./package-lock.json` (or whichever lockfiles we have) as a pre-publish gate. If we find a compromised version of one of our own deps, the release is blocked.

---

## 3. Goals & non-goals

### Goals (V1)

- Single command: `pwned-deps check [PATH]`
- Auto-detect lockfile format from filename or content.
- Aggregate advisories from OSV.dev (default) + a small repo-managed `extras.json` for ultra-recent campaigns.
- Pretty terminal output via `rich` — color-coded severity, install-date if present, MAL-* advisories prominently flagged.
- JSON output (`--format json`) for scripting.
- SARIF v2.1.0 output (`--format sarif`) for GitHub Code Scanning.
- Exit code: `0` = clean, `1` = at least one MAL-* hit, `2` = at least one HIGH/CRITICAL CVE hit, `3` = parse error.
- Offline mode (`--offline`) using a cached database (`~/.cache/pwned-deps/osv.sqlite`).
- Update command: `pwned-deps update` to refresh the local cache.
- One-line summary at the end: `"✗ 3 compromised packages found (1 MAL-*, 2 HIGH CVE)"` or `"✓ All 412 packages clean."`
- Web mode (after V1, see §10): drag-drop static page hosted on GitHub Pages.

### Non-goals (deliberately out of V1)

- No SBOM generation. Use `syft` for that. We consume lockfiles, we don't generate SBOMs.
- No reachability analysis. That's a different tool (`cve-reach`, mentioned in the gap report).
- No fixing. We don't auto-PR upgrades. We surface findings + recommended actions; users use Dependabot / Renovate / their own playbook.
- No license-compliance checking.
- No paid tier. Free, MIT or Apache-2.0, forever.
- No private/enterprise advisory feeds in V1. Add later as a `--feed-url` config.
- No telemetry, no anonymous usage stats, ever.

---

## 4. Architecture

```
┌────────────────────────────────────────────────────────────┐
│                       CLI entry point                      │
│         (Click — subcommands: check, update, version)      │
└──────────────────────────────┬─────────────────────────────┘
                               │
            ┌──────────────────┼──────────────────┐
            ▼                  ▼                  ▼
     ┌────────────┐     ┌────────────┐     ┌────────────┐
     │  Lockfile  │     │  Advisory  │     │  Reporter  │
     │  parsers   │     │  resolver  │     │ (rich/json/│
     │            │────▶│            │────▶│   sarif)   │
     │ npm,pip,   │     │ OSV API +  │     └────────────┘
     │ cargo,go,  │     │ extras.json│
     │ maven,gem  │     │ + cache    │
     └────────────┘     └────────────┘
                               │
                               ▼
                     ┌─────────────────┐
                     │ Local cache     │
                     │ ~/.cache/       │
                     │ pwned-deps/     │
                     │ osv.sqlite      │
                     └─────────────────┘
```

### Module layout

```
src/pwned_deps/
├── __init__.py              # version
├── cli.py                   # Click entry point
├── parsers/                 # one parser per ecosystem
│   ├── __init__.py
│   ├── base.py              # Lockfile, Package dataclasses
│   ├── npm.py               # package-lock.json v1/v2/v3, npm-shrinkwrap.json, pnpm-lock.yaml
│   ├── pypi.py              # requirements.txt, Pipfile.lock, poetry.lock, uv.lock
│   ├── cargo.py             # Cargo.lock
│   ├── go.py                # go.sum, go.mod
│   ├── maven.py             # pom.xml (with <dependencyManagement> resolution)
│   └── gem.py               # Gemfile.lock
├── advisory/
│   ├── __init__.py
│   ├── osv_client.py        # OSV REST client + batch query
│   ├── extras.py            # local repo-managed feed for very-recent campaigns
│   ├── cache.py             # SQLite cache layer
│   └── matcher.py           # (package,version,ecosystem) -> advisories
├── report/
│   ├── __init__.py
│   ├── text.py              # rich terminal output
│   ├── json_out.py
│   └── sarif.py             # SARIF v2.1.0
└── extras_data/
    └── extras.json          # bundled snapshot of very-recent campaigns
```

---

## 5. Tech stack

- **Language**: Python 3.10+ (broadest installation, runs on macOS/Linux/Windows). Distribution via `pipx` (preferred) and `pip install pwned-deps`.
- **CLI**: `click >=8.1,<9.0`
- **Terminal output**: `rich >=13.0,<14.0`
- **HTTP**: `httpx >=0.27,<1.0` (sync mode; async only if perf demands it later)
- **Lockfile parsing**: `tomli`/`tomllib` (stdlib for 3.11+, `tomli` for 3.10), `pyyaml`, stdlib `json`, `xml.etree.ElementTree` (no `lxml` — too heavy).
- **Cache**: stdlib `sqlite3`.
- **Tests**: `pytest >=8.0,<9.0`, `pytest-httpx` for HTTP mocking, `freezegun` for time-based tests.
- **Lint/type**: `ruff >=0.6,<1.0`, `mypy >=1.10,<2.0`.
- **Build**: `hatchling`.

Not in deps: anything that does eval/exec on user input. No subprocess calls in `src/`. No `pip-api`, no npm Python wrappers, no `pipenv` library — we parse lockfiles directly.

---

## 6. Data sources

### Primary: OSV.dev

- Public REST API: `https://api.osv.dev` — free, no key, generous rate limits.
- Endpoints we use:
  - `POST /v1/query` — single (package, version, ecosystem) → list of advisories.
  - `POST /v1/querybatch` — batch up to 1000 queries (use this).
  - `GET /v1/vulns/{id}` — full advisory details (only when user asks for `--explain`).
- OSV ecosystems map cleanly to ours: `npm`, `PyPI`, `crates.io`, `Go`, `Maven`, `RubyGems`.
- OSV advisory IDs we surface specially:
  - `MAL-YYYY-NNNN` — confirmed-malicious package versions. These get a 🚨 prefix and are always surfaced regardless of severity.
  - `GHSA-*`, `CVE-*`, `PYSEC-*`, `RUSTSEC-*`, `GO-*`, `RUBY-*` — standard advisories.
- Cache: store responses in `~/.cache/pwned-deps/osv.sqlite` keyed by (ecosystem, package, version) with a TTL (default 24h, override with `--cache-ttl`).

### Secondary: repo-managed `extras.json`

Bundled inside the package. Updated by maintainers when a campaign is announced and OSV hasn't ingested it yet. Format:

```json
{
  "version": 1,
  "updated_at": "2026-05-02T10:00:00Z",
  "campaigns": [
    {
      "id": "EXTRA-2026-0001",
      "name": "Mini Shai-Hulud (SAP CAP)",
      "summary": "April 29, 2026 — npm preinstall script credential stealer in SAP CAP packages.",
      "references": [
        "https://securitybridge.com/blog/a-mini-shai-hulud-has-appeared-when-the-npm-supply-chain-reaches-into-sap/",
        "https://www.wiz.io/blog/mini-shai-hulud-supply-chain-sap-npm",
        "https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html"
      ],
      "ecosystem": "npm",
      "packages": [
        { "name": "@cap-js/<TODO-exact-name>", "versions": ["<TODO-exact>"] },
        { "name": "mbt", "versions": ["<TODO-exact>"] }
      ],
      "exposure_window": ["2026-04-29T13:00:00Z", "2026-04-29T17:00:00Z"],
      "actions": [
        "Rotate npm tokens used by affected CI",
        "Rotate GitHub PATs",
        "Rotate GitHub Actions secrets",
        "Rotate AWS/Azure/GCP/K8s creds reachable from affected CI",
        "Audit your GitHub account for repos created with the description 'A Mini Shai-Hulud has Appeared'"
      ]
    }
  ]
}
```

The agent's first task in step 7 is to fill in the actual affected package names and versions from the cited sources.

### Refresh strategy

- `pwned-deps update` → fetches the latest `extras.json` from the project's GitHub raw URL (allow-listed), refreshes OSV cache for any (package, version, ecosystem) hits, writes to `~/.cache/pwned-deps/`.
- CI runs `pwned-deps update` on a daily schedule and opens an automatic PR if the bundled `extras.json` is stale (compared to the upstream raw URL).

---

## 7. Step-by-step build plan (with test gates)

> Test-gate rule: Each step lists what must be true before advancing. Do not advance until all gates are green. Run `make verify-safety && make test` after every step.

### Step 1 — Project skeleton + Docker dev env

Files: `pyproject.toml`, `src/pwned_deps/__init__.py`, `tests/__init__.py`, `tests/test_smoke.py`, `Dockerfile.dev`, `Makefile`, `requirements.lock`, `.gitignore`, `.dockerignore`, `LICENSE` (Apache-2.0), `README.md` (with `mkbhardwas12` placeholder), `CHANGELOG.md`. Reuse the exact pattern from the GGUF-scanner project's Step 1 (Dockerfile non-root `appuser`, locked-down Makefile flags, `verify-safety` grep target).

The forbidden-symbol regex for `verify-safety` for this project:

```
\.render\(|\beval\(|\bexec\(|\bcompile\(|\bos\.system\(|\bos\.popen\(|\bsubprocess\.|pickle\.load|pickle\.loads|__import__\(|getattr\(__builtins__|importlib\.import_module
```

(Note: we do allow `compile` if the agent later needs `re.compile` — handle that with a per-line `# noqa: S` ignore on the specific line, or refine the regex to `(?<!re\.)compile`.)

**Test gate:** `make build` succeeds; `make verify-safety` passes (and proves it would fail on a planted `eval()`); `make shell` drops into container as `appuser` (`id -u` returns 1000); `python -c "import pwned_deps"` works inside container; `pytest tests/` shows ≥1 smoke test passing.

### Step 2 — npm lockfile parser

Implement `parsers/npm.py` for `package-lock.json` (npm v1, v2, v3 schemas — the schema differs significantly between versions). Also handle `npm-shrinkwrap.json` (same schema as v3 lockfile). Defer `pnpm-lock.yaml` to Step 9 and `yarn.lock` (v1/v2 berry) to Step 9 — start with the most common format.

API:

```python
from pwned_deps.parsers.base import Lockfile, Package, Ecosystem
def parse(path: str | Path) -> Lockfile: ...
```

Package dataclass: `name: str`, `version: str`, `ecosystem: Ecosystem`, `lockfile_path: str`, `parents: list[str]` (for transitive). Ecosystem is a StrEnum matching OSV vocabulary: `npm`, `PyPI`, `crates.io`, `Go`, `Maven`, `RubyGems`.

**Test gate:** ≥6 unit tests:

- v1 lockfile (legacy, has `dependencies` only) → list of packages with correct names+versions.
- v2 lockfile (has both `packages` and `dependencies`, prefer `packages`) → ditto.
- v3 lockfile (`packages` only) → ditto.
- Missing/corrupted file → raises `ParseError` with friendly message.
- Empty `packages` block → returns empty Lockfile, no crash.
- Scoped packages (`@cap-js/cds`) parsed correctly with the leading `@`.

### Step 3 — pip / Python lockfile parsers

`parsers/pypi.py` covering:

- `requirements.txt` (pip-compile output, with `==` pins, hash-mode optional)
- `Pipfile.lock`
- `poetry.lock`
- `uv.lock` (TOML, the new standard)

For `requirements.txt`, only fully-pinned (`==`) entries count. Loose entries (`>=`, `~=`) are reported as `version_unspecified=True` and excluded from advisory matching with a clear note in the report.

**Test gate:** ≥4 unit tests, one per format. Edge cases: editable installs (`-e .`), VCS URLs (`git+https://...`), local paths (`./mylib`) — all should be ignored gracefully with a warning.

### Step 4 — OSV client + cache

`advisory/osv_client.py`:

- `class OsvClient: def query_batch(self, packages: list[Package]) -> dict[Package, list[Advisory]]`
- Uses `httpx.Client` with `timeout=30`, `User-Agent: pwned-deps/<version> (+https://github.com/<repo>)`.
- Batches queries up to 1000 per request.
- Retries idempotent failures (429, 5xx) with exponential backoff (max 3 attempts).
- Network is opt-in: `pwned-deps check --offline` skips OSV entirely and uses cache only.

`advisory/cache.py`:

- SQLite at `~/.cache/pwned-deps/osv.sqlite` (Windows: `%LOCALAPPDATA%\pwned-deps\`).
- Schema:

```sql
CREATE TABLE advisories (id TEXT PRIMARY KEY, ecosystem TEXT, package TEXT, version TEXT, payload_json TEXT, fetched_at INTEGER);
CREATE INDEX ix_pkg ON advisories(ecosystem, package, version);
```

- TTL: skip cache entries older than 24h by default.

**Test gate:** with `pytest-httpx` mocking the OSV API:

- Single-package query returns expected advisories.
- Batch of 50 returns expected per-package mapping.
- 429 retry succeeds on second attempt.
- Offline mode returns cached data, never calls network.
- Cache TTL: stale entries are re-fetched.
- Live integration test (opt-in `pytest -m network`): batch query for `lodash@4.17.20` (known multi-CVE) returns at least one advisory.

### Step 5 — Matcher + extras.json

`advisory/matcher.py`:

- `class Matcher: def match(self, lockfile: Lockfile) -> list[Finding]`
- Combines OSV results with `extras.json` campaigns.
- A `Finding` is `(package, version, advisory_id, severity, summary, references, special_flags)` where `special_flags` includes `is_malicious` (any MAL-* or extras.json campaign), `campaign_name` (e.g. "Mini Shai-Hulud (SAP CAP)").

`advisory/extras.py`:

- Parses bundled `extras.json` and any user-supplied feed URL (allow-listed at config time only).
- For each campaign, checks whether any (ecosystem, package, version) tuple in the lockfile matches an entry, including version-range matches (use `packaging.version` for PyPI, node-semver-equivalent logic for npm — implement minimal range check that handles `=`, `<`, `>`, `<=`, `>=`, `~`, `^`).

**Test gate:**

- Lockfile with `lodash@4.17.15` returns ≥1 OSV advisory.
- Lockfile with a fake `@cap-js/foo@1.2.3` matching the bundled extras campaign returns a `is_malicious=True`, `campaign_name="Mini Shai-Hulud (SAP CAP)"` finding.
- No false positives on benign packages.
- Range matching: `lodash@>=4.17.0,<4.17.21` campaign hits 4.17.15 but not 4.17.22.

### Step 6 — CLI

`cli.py`:

- `pwned-deps check [PATH]` — auto-detect lockfile if PATH is a directory; scan all lockfiles found if `--all` flag.
- `--format {text,json,sarif}` (default `text`)
- `--offline` (skip network, use cache only)
- `--ci` (suppress decorations, set exit code per spec in §3 Goals)
- `--cache-ttl HOURS` (default 24)
- `--explain ID` (print full advisory details for one ID)
- `--no-color` (force plain output)
- `pwned-deps update` — refresh local cache + bundled extras feed
- `pwned-deps version`

Output format (text mode, `rich`):

```
pwned-deps 0.1.0 — checking package-lock.json (npm)

🚨 COMPROMISED — 2 packages

  @cap-js/cds@1.2.3
    EXTRA-2026-0001  Mini Shai-Hulud (SAP CAP)
    Exposure window: 2026-04-29 13:00 UTC → 17:00 UTC
    → Rotate: npm tokens, GitHub PATs, GitHub Actions secrets, AWS/Azure/GCP/K8s creds
    → Audit your GitHub for repos titled 'A Mini Shai-Hulud has Appeared'
    refs: securitybridge.com, wiz.io, thehackernews.com (run with --explain EXTRA-2026-0001)

  mbt@5.6.7
    (same campaign — see above)

⚠ HIGH/CRITICAL — 0 packages
✓ Other findings — 3 LOW/MEDIUM (pass --verbose to see)

Summary: 412 packages scanned · 2 compromised · 0 high · 3 low/medium · runtime 1.2s
Exit code: 1
```

**Test gate:** Use `click.testing.CliRunner`:

- `check ./tests/fixtures/clean.lock.json` → exit 0, "All clean" output.
- `check ./tests/fixtures/mini-shaihulud.lock.json` → exit 1, "COMPROMISED" header, campaign name visible.
- `--format json` → valid JSON, schema-checked.
- `--ci --format text` → no color, deterministic exit code per spec.
- `--offline` with empty cache → friendly error: "no cache yet, run pwned-deps update".

### Step 7 — Bundled `extras.json` with Mini Shai-Hulud entry

Populate `src/pwned_deps/extras_data/extras.json` with the actual Mini Shai-Hulud campaign details. Source the affected package names + versions from the cited references (SecurityBridge, Wiz, Sophos, Aikido, Ox Security). Include the SHA256 of each affected `.tgz` if any source publishes them.

**Test gate:** running `pwned-deps check` against a fixture lockfile that pins one of the known-bad versions returns the campaign as a finding with the correct exposure window and remediation steps.

### Step 8 — JSON + SARIF output

`report/json_out.py` — straightforward dump of `Finding` list.

`report/sarif.py` — emit SARIF v2.1.0:

- `tool.driver.name = "pwned-deps"`
- `tool.driver.version = pwned_deps.__version__`
- `tool.driver.informationUri = "https://github.com/<repo>"`
- `tool.driver.rules` — one rule per advisory ID seen.
- `results[].level` mapped: MAL-* and CRITICAL → `error`; HIGH → `error`; MEDIUM → `warning`; LOW → `note`.
- `results[].locations[].physicalLocation.artifactLocation.uri` — the lockfile path.
- `results[].partialFingerprints` — for stable dedup across runs.

Bundle the SARIF v2.1.0 schema in `tests/fixtures/sarif-2.1.0-schema.json`.

**Test gate:** scan a known-malicious fixture, emit SARIF, validate against bundled schema (`jsonschema`), assert key fields. Upload to a sandbox GitHub repo and confirm the SARIF appears in Code Scanning alerts.

### Step 9 — Remaining ecosystem parsers

Add: `pnpm-lock.yaml`, `yarn.lock` (v1 + v2 berry), `Cargo.lock`, `go.sum` + `go.mod`, `pom.xml` (Maven), `Gemfile.lock`. Each must round-trip with ≥3 unit tests on real-world fixtures (commit small examples to `tests/fixtures/<ecosystem>/`).

**Test gate:** all parsers pass; full integration scan on a multi-ecosystem fixture lockfile pulls advisories for at least one package per ecosystem.

### Step 10 — CI/CD + dogfooding

`.github/workflows/ci.yml`:

- Trigger: push, PR, manual, daily cron.
- Jobs: `verify-safety` (host) → `lint` (container) → `test` (container, locked-down flags) → `dogfood` (`pwned-deps check ./pyproject.toml ./requirements.lock` against itself, must pass).
- Cron job: refresh cached `extras.json`, open auto-PR if upstream is newer.

`.github/workflows/release.yml`:

- Trigger: push of a `v*` tag.
- Build wheel + sdist.
- Publish to PyPI via OIDC trusted publishing (no token in repo secrets).
- Generate SLSA Level 3 provenance via the SLSA generator action.
- Create GitHub Release with auto-generated notes.

**Test gate:** CI green on a fresh PR. Dogfood job passes (we ourselves are not pwned).

### Step 11 — README + launch polish

README sections (in order): logo (TODO), one-line tagline, badges, "Why this exists" (cite Mini Shai-Hulud as motivating example), install, quick usage, supported ecosystems, output formats, threat model, FAQ, comparison table vs `npm audit`/`pip-audit`/`osv-scanner`/`socket`, contributing, license.

Comparison table must be honest:

- `npm audit` — npm-only, requires `node_modules` install, not always offline.
- `pip-audit` — Python-only.
- `osv-scanner` (Google) — multi-ecosystem, the most direct competitor. Differences: we add the supply-chain campaign extras feed + nicer UX + first-class MAL-* surfacing. `osv-scanner` is excellent and well-resourced; do not pretend we replace it.
- `socket` — commercial, deeper analysis, gated behind paid tier for some features.

Where `osv-scanner` is the right answer for someone, the README should say so.

**Test gate:** README renders correctly on GitHub. All install commands work end-to-end on a fresh macOS, fresh Ubuntu, fresh Windows (run on a CI matrix).

### Step 12 — Web frontend (post-V1, optional)

Static page (GitHub Pages) — drag-drop a lockfile onto the page; lockfile is parsed in browser via Pyodide or a JS port; OSV calls go direct from browser to `api.osv.dev` with CORS; results rendered with a small Tailwind UI. No backend. Lockfile contents never leave the user's browser.

Defer this to V1.1. V1 ships CLI only.

---

## 8. Distribution

- **PyPI**: `pip install pwned-deps`, `pipx install pwned-deps`. OIDC trusted publishing only.
- **Homebrew**: create a tap `<repo>/homebrew-tap` once V1.1 is out.
- **npx**: publish a tiny shim package on npm (`pwned-deps`) that downloads the Python wheel into a temp venv and runs it. Lets `npx pwned-deps@latest` work for the npm-native audience without a Python install. (Stretch goal — V1.2.)
- **Docker**: publish `ghcr.io/<repo>/pwned-deps:<version>` for CI users who want a fixed-base scanner.

---

## 9. Launch plan (after V1 is stable)

1. Tag V1.0.0, GitHub release with full changelog.
2. Personal post on Bluesky / X / Mastodon announcing it. Lead with: "Mini Shai-Hulud hit your CI? Check in 5 seconds: `npx pwned-deps@latest`".
3. Post to Hacker News with title "Show HN: pwned-deps – is your lockfile pwned by Mini Shai-Hulud?" — post on a Tuesday/Wednesday morning ET.
4. Post to r/devops, r/programming, r/cybersecurity, r/sysadmin, r/netsec.
5. Submit to awesome-lists (`awesome-security`, `awesome-supply-chain-security`).
6. Email maintainers of `osv-scanner`, `pip-audit`, `npm`, `socket` — let them know of the project. Don't ask for boost; ask for review.
7. One blog post — a writeup of how Mini Shai-Hulud was detectable retroactively from lockfile alone, with the CLI demo. Cross-post to dev.to / Medium / personal blog.

Do not buy ads. Do not buy stars. Do not run social bots. The launch hooks itself on the next supply-chain incident — every incident is a re-launch.

---

## 10. Known risks & what kills it

- **Google's `osv-scanner` adds a "campaigns" feed.** They have the resources; if they ship it, we ship deeper UX + faster updates and integrate (rather than compete). Not a fatal risk if we maintain the better-CLI angle.
- **OSV outages.** Our offline mode + cache mitigates this.
- **`extras.json` lag.** If we don't refresh fast after a campaign, we're useless on the news cycle. Mitigate with a daily auto-PR cron and a `CONTRIBUTING.md` that makes adding a new campaign a 5-minute PR.
- **Maintainer burnout.** Set a `MAINTENANCE.md` with explicit response-time expectations ("issues triaged within 7 days, not within 24 hours"). Solo OSS in security burns people out fast.
- **Compromised maintainer account.** Hardware-key 2FA, OIDC publishing, no long-lived tokens. If our own account is compromised and we ship a poisoned `pwned-deps`, the irony kills the project. This is the highest-impact risk; treat account hygiene as a tier-1 concern.

---

## 11. Open decisions for the user (must be answered before V1 release)

1. **GitHub username / org.** Currently `mkbhardwas12` placeholder. Single sed-replace before publish.
2. **Project name.** `pwned-deps` is the proposed name. Alternatives: `is-pwned`, `pwndep`, `lockcheck`, `pwn-check`. Pick before first PyPI publish — renaming on PyPI is painful.
3. **License.** Apache 2.0 is suggested (patent grant, common for security tooling). MIT is the alternative.
4. **PyPI account.** Set up before V1 release. Use OIDC trusted publishing from GitHub Actions.
5. **npm shim package name.** `pwned-deps` if available, else `pwneddeps`. Reserve before launch.
6. **Logo.** Optional but helps on social. Ship without if it slows you down.

---

## 12. Quick-start for the agent

When you (Claude Code or any other agent) open this folder:

```bash
# 0. Read this BUILD_BRIEF top to bottom.

# 1. Sanity-check the workspace.
ls
cat README.md 2>/dev/null || echo "(no readme yet — Step 1 creates one)"

# 2. Start at Step 1. Use the GGUF-scanner pattern for the project skeleton —
#    HANDOFF.md and BUILD_PLAN.md from the sibling project show the exact
#    Dockerfile / Makefile / safety-contract shape to copy.
#    The forbidden-symbol regex for verify-safety in THIS project is:
#    \.render\(|\beval\(|\bexec\(|\bcompile\(|\bos\.system\(|\bos\.popen\(|\bsubprocess\.|pickle\.load|pickle\.loads|__import__\(|getattr\(__builtins__|importlib\.import_module

# 3. After every step:
make verify-safety && make test
# Both must be green before moving to the next step.

# 4. Update CHANGELOG.md after each step. Conventional Commits style helps.

# 5. When V1 is ready, run pwned-deps against this project's own lockfile.
#    The build is not done until that returns 0.
```

---

## 13. Acceptance criteria for V1.0 (definition of done)

- [ ] All 11 steps complete; their test gates green.
- [ ] `pipx install pwned-deps` works on macOS, Ubuntu, Windows.
- [ ] `pwned-deps check` against a fixture pinning a Mini Shai-Hulud-affected version emits the campaign with correct exposure window and remediation list.
- [ ] `pwned-deps check ./pyproject.toml ./requirements.lock` (dogfood) returns exit 0.
- [ ] SARIF output validates against schema and uploads cleanly to a test repo's Code Scanning.
- [ ] README has a working install + usage section that matches the published CLI.
- [ ] CI is green on a fresh PR.
- [ ] Account hygiene checklist done (2FA hardware key on GitHub, OIDC publishing on PyPI).
- [ ] `extras.json` is current to within 7 days of the most recent public supply-chain campaign in any covered ecosystem.
- [ ] The maintainer (you) has typed `pwned-deps check` against at least one real customer/employer project, found nothing, and has the receipt.

---

## 14. License & attribution

Apache License 2.0. Threat-model assumptions are informed by published research from JFrog Security, Wiz, Sophos, Aikido, Ox Security, SecurityBridge, ReversingLabs, Snyk, the Sigstore project, OSV.dev, and the GitHub Advisory Database. No code or proprietary detection rules from those organizations are reused — all matching logic is written from primary sources (advisory IDs, CVE descriptions, public PoC writeups).
