# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Each commit
uses [Conventional Commits](https://www.conventionalcommits.org/).

## [Unreleased]

### Added

- `pwned-deps audit-repo PATH` — forensic on-disk file scanner.
  Walks a directory tree (skipping `node_modules`, `.git`, `.venv`,
  build outputs, symlinks; 50 MiB per-file size cap) and matches
  every file against the campaign feed's new `file_iocs[]` block by
  SHA-256 and/or path-hint. Three match levels: `sha256+path`
  (highest), `sha256` (confirmed payload, exit 1), `path` (suspect
  variant or modified content, exit 2). Text + JSON output. JSON
  carries `command: "audit-repo"` discriminator alongside
  `schema_version: "1.0"`. New module: `pwned_deps.audit.repo`. 11
  new tests using synthetic feeds + benign payloads (no real
  malicious bytes).
- `extras.json` schema gained two optional fields:
  - `iocs[]` (campaign-level free-text indicators — rogue-repo
    signatures, commit-message prefixes, C2 domains).
  - `file_iocs[]` (campaign-level structured on-disk IoCs:
    `{path_hint, sha256, size_bytes, description, source}`).
  Both are additive and backward-compatible — campaigns without
  them work unchanged.
- `EXTRA-2026-0001` (Mini Shai-Hulud SAP CAP) gained 6 IoC strings
  and 7 `file_iocs` entries (the shared `setup.mjs` dropper at both
  `.claude/` and `.vscode/` paths, three per-package
  `execution.js` SHA-256s, `.claude/settings.json` Claude Code
  SessionStart hook, `.vscode/tasks.json` `Environment Setup` task
  with `runOn: folderOpen`). Hashes sourced from
  [Wiz](https://www.wiz.io/blog/mini-shai-hulud-supply-chain-sap-npm).
- Per-package `ecosystem` override in `extras.json` campaigns —
  unblocks cross-ecosystem campaigns under one ID.
- `tarball_sha256` (per-package) and `iocs[]` (per-campaign) are now
  surfaced in both text and JSON reports next to every finding,
  closing the gap SecurityBridge flagged: "use these for forensic
  confirmation rather than relying on version strings alone."
- `.github/workflows/sign-feed.yml` — keyless OIDC signs
  `extras.json` on every push to `main` that touches it via
  `sigstore-python`. Bundle attached as a 90-day workflow artifact;
  the immutable Rekor log entry is the durable trust artifact. No
  commit-back, no PAT, no force-push survivability problem. Verify
  recipe: `python -m sigstore verify identity ...` documented in
  [SECURITY.md](SECURITY.md).
- `make release-rehearsal` target — chains verify-safety →
  self-test → lint → host pytest → build → fresh-venv install →
  dogfood. One command before tagging; refuses to print green if
  any gate fails.
- GitHub Action ([action.yml](action.yml)) — composite action with
  `path` / `version` / `fail-on` (`compromised`/`any`/`never`) /
  `output-sarif` / `upload-sarif` / `offline` inputs. SARIF →
  GitHub Code Scanning out of the box.
- pre-commit hook ([.pre-commit-hooks.yaml](.pre-commit-hooks.yaml))
  with online + offline variants covering 13 lockfile patterns.
- Repository hygiene: [SECURITY.md](SECURITY.md) (private vuln
  reporting + 90-day disclosure + feed-verification recipe),
  [CONTRIBUTING.md](CONTRIBUTING.md) (5-min add-a-campaign flow,
  PoC handling rules, OSV-vocabulary clarification),
  [.github/CODEOWNERS](.github/CODEOWNERS) (pins
  `extras_data/`, release.yml, action.yml, Dockerfile.dev,
  requirements.lock, base-image.lock to the maintainer),
  bug + campaign issue templates, PR template with release
  rehearsal checkbox.
- `demo.tape` ([demo.tape](demo.tape)) — `vhs` script for
  `docs/demo.gif`.
- README "Real-world scenarios" section keyed on Mini Shai-Hulud
  (5 victim-question framings + the `audit-repo` triage step).

### Fixed

- `lightning@2.6.2/2.6.3` (PyPI) was silently missed in
  `EXTRA-2026-0002` because the campaign-level `ecosystem` was
  `npm`. Per-package override now lets one campaign cover
  `intercom-client` (npm) + `lightning` (PyPI). Regression test:
  `test_lightning_pypi_is_caught_via_per_package_ecosystem_override`.
- CONTRIBUTING.md previously listed ecosystem strings in lowercase
  (`pypi`, `crates`, `go`, `maven`, `rubygems`) — these silently
  fail the case-sensitive matcher. Documented the OSV vocabulary
  explicitly to prevent future contributors hitting the same bug.

## [0.1.0] — initial release

- Project skeleton: `pyproject.toml` (Hatchling, Python ≥3.10,
  Apache-2.0), `src/pwned_deps/__init__.py` exposing `__version__`,
  smoke tests, `Dockerfile.dev` (non-root `appuser` UID 1000, base
  image to be pinned via `make pin-base`), `Makefile` (build, shell,
  test, verify-safety, verify-safety-self-test, lint, pin-base, clean),
  `requirements.lock` (pytest + pytest-httpx + ruff), `LICENSE`
  (Apache-2.0).
- npm lockfile parser. `parsers/base.py` shared dataclasses
  (`Package`, `Lockfile`, `Ecosystem` StrEnum matching OSV vocabulary,
  `ParseError`); `parsers/npm.py` handling `package-lock.json` v1
  (recursive `dependencies`), v2 (prefer `packages`, skip workspace
  links), v3 (`packages` only); 8 unit tests covering every shape and
  error path.
- Python lockfile parsers. `parsers/pypi.py` auto-dispatches by
  filename to handlers for `requirements*.txt` (pinned vs loose vs
  editable/VCS/local), `Pipfile.lock` (default + develop merge),
  `poetry.lock`, and `uv.lock` (workspace-root skip). Loose pins are
  emitted with `version_unspecified=True`. Names canonicalised to
  PEP 503 form. 9 unit tests on inert hand-crafted fixtures. `tomli`
  added as a dev dep for Python 3.10 fallback.
- OSV client + SQLite cache. `advisory/types.py` (`Advisory`,
  `Severity`); `advisory/osv_client.py` synchronous client using
  `httpx.Client(trust_env=False)` (host proxy isolation), batches up
  to 1000 packages via `POST /v1/querybatch`, fetches full details
  via `GET /v1/vulns/{id}`, exponential-backoff retry on 429/5xx;
  `advisory/cache.py` SQLite cache with two tables (queries +
  advisories) supporting negative caching and TTL. MAL-* IDs are
  promoted to severity CRITICAL. 13 unit tests + 1 opt-in live
  network test. `httpx==0.27.2` pinned.
- Matcher + extras.json. `advisory/version_match.py` minimal
  range matcher supporting `=`, `==`, `!=`, `<`, `<=`, `>`, `>=`,
  AND-joined; PEP 440 for PyPI, conservative SemVer-style for npm
  with prerelease ordering; `advisory/extras.py` loads bundled
  extras.json + optional user-supplied feed paths and produces
  `CampaignMatch` records; `advisory/matcher.py` combines extras
  campaigns with OSV findings into `Finding` records carrying
  `is_malicious` + `campaign_name`. Bundled `extras_data/extras.json`
  initial placeholder. 26 new tests. `packaging==26.2` pinned as a
  runtime dep.
- CLI. `cli.py` exposes `check`, `update`, and `version`
  subcommands via click. `check` accepts a file or directory (with
  filename-based autodetection for npm/PyPI lockfiles). Output
  formats: `text` (rich-rendered), `json` (preliminary; full schema
  in a follow-up), `sarif` (initial stub). Flags: `--offline`, `--ci`,
  `--no-color`, `--cache-ttl`, `--feed-file`, `--cache-path`,
  `--explain`. Exit codes: 0 (clean) / 1 (compromised) / 2 (suspect) / 3 (error).
  `report/text.py` rich renderer; `report/json_out.py` minimal
  reporter. `[project.scripts] pwned-deps = "pwned_deps.cli:main"`
  wired. 9 new CliRunner tests. `click==8.1.7` and `rich==13.9.4`
  pinned.
- Mini Shai-Hulud (SAP CAP) campaign in bundled
  `extras_data/extras.json`: all four affected packages
  (`@cap-js/sqlite@2.2.2`, `@cap-js/postgres@2.2.2`,
  `@cap-js/db-service@2.10.1`, `mbt@1.2.48`) with published SHA256
  digests, an exposure window of `2026-04-29T09:55:00Z →
  2026-04-29T14:00:00Z` (start cited from thehackernews.com; end is
  a conservative upper bound, marked `TODO(precise-end-time)`), and
  an 8-step remediation list. Sources: thehackernews.com,
  securitybridge.com, wiz.io. End-to-end test
  (`test_step7_mini_shaihulud.py`) drives the COMPROMISED branch on
  a fixture pinning `@cap-js/sqlite@2.2.2`.
- SARIF v2.1.0 output. `report/sarif.py` produces a
  schema-conforming SARIF log (driver name/version/informationUri,
  unique rules per advisory ID, results with level mapping,
  stable `partialFingerprints.primaryLocationLineHash` for
  GitHub Code Scanning dedup). `--format sarif` is now wired in
  the CLI. 5 new tests including end-to-end validation against the
  bundled OASIS schema (111 KB at
  `tests/fixtures/sarif/sarif-2.1.0-schema.json`). `jsonschema`
  added as a dev-only dep.
- Six additional ecosystem parsers wired into the CLI's
  autodetect list: `parsers/cargo.py` (`Cargo.lock`),
  `parsers/go.py` (`go.sum`), `parsers/pnpm.py` (`pnpm-lock.yaml`,
  v5 + v6 key styles), `parsers/yarn.py` (`yarn.lock` v1 classic +
  v2/Berry YAML), `parsers/maven.py` (`pom.xml`,
  `<dependencies>` + `<dependencyManagement>`, property-variable
  versions surfaced as `version_unspecified=True`),
  `parsers/gem.py` (`Gemfile.lock` GEM block). 18 new unit tests
  (3 per ecosystem). Multi-ecosystem directory scan dogfooded
  end-to-end and the bundled Mini Shai-Hulud campaign matched
  across both pnpm and yarn fixtures. `pyyaml==6.0.2` pinned.
- CLI now accepts multiple PATH arguments (so the dogfood
  `pwned-deps check ./pyproject.toml ./requirements.lock`
  works); unrecognised files are warn-skipped rather than
  failing. `.github/workflows/ci.yml` (verify-safety → lint →
  test 3.10/3.11/3.12 matrix → dogfood) and
  `.github/workflows/release.yml` (verify + lint + test + dogfood
  → build → SLSA Level 3 provenance via slsa-framework generator
  → PyPI OIDC trusted publish → GitHub Release).
- README polish. Added badges (CI, PyPI, Python versions,
  license), expanded threat model section (network allow-list,
  container dev, OIDC, dogfood), added FAQ, fleshed out the
  comparison table with a license column and explicit "where
  osv-scanner is the right answer" honesty, expanded the
  contributing flow with the 5-minute campaign-PR procedure, and
  added a maintenance-cadence section.
- Replaced `YOUR_GH_USERNAME` placeholder with `mkbhardwas12`
  across the repo.
- Hash-pinned `requirements.lock` per safety contract
  (`requirements.in` + `pip-compile --generate-hashes`,
  `Dockerfile.dev` enforces `--require-hashes`, `make pin-deps`
  regenerates). Version bumps with regeneration: click 8.1.7→8.3.3,
  httpx 0.27.2→0.28.1, jsonschema 4.23.0→4.26.0, pytest 8.3.3→8.4.2,
  pytest-httpx 0.32.0→0.35.0, pyyaml 6.0.2→6.0.3, rich 13.9.4→14.3.4,
  ruff 0.7.4→0.15.12. One test updated for the click 8.3
  `CliRunner(mix_stderr=...)` removal.
- Added `EXTRA-2026-0002` "Mini Shai-Hulud follow-on
  (intercom-client + lightning)" to the bundled extras feed.
  Sourced from Wiz: `intercom-client@7.0.5`, `lightning@2.6.2`,
  `lightning@2.6.3` poisoned April 30 2026 by the same operator
  (shared C2 `zero.masscan.cloud`, fallback via GitHub commits
  keyed `beautifulcastle`). Payload evolved to target Kubernetes
  + HashiCorp Vault. Two new tests + one fixture
  (`mini-shaihulud-followon.lock.json`).
