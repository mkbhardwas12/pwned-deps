# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Each commit
uses [Conventional Commits](https://www.conventionalcommits.org/).

## [Unreleased]

### Added

- Step 0 — bootstrap. Imported `BUILD_BRIEF.md` as the single source of
  truth, `BUILD_LOG.md` for per-step plan + gate evidence, host-side
  ignore files (`.gitignore`, `.dockerignore`).
- Step 1 — project skeleton. `pyproject.toml` (Hatchling, Python ≥3.10,
  Apache-2.0), `src/pwned_deps/__init__.py` exposing `__version__`,
  smoke tests, `Dockerfile.dev` (non-root `appuser` UID 1000, base
  image to be pinned via `make pin-base`), `Makefile` (build, shell,
  test, verify-safety, verify-safety-self-test, lint, pin-base, clean),
  `requirements.lock` (pytest + pytest-httpx + ruff), `LICENSE`
  (Apache-2.0).
- Step 2 — npm lockfile parser. `parsers/base.py` shared dataclasses
  (`Package`, `Lockfile`, `Ecosystem` StrEnum matching OSV vocabulary,
  `ParseError`); `parsers/npm.py` handling `package-lock.json` v1
  (recursive `dependencies`), v2 (prefer `packages`, skip workspace
  links), v3 (`packages` only); 8 unit tests covering every shape and
  error path.
- Step 3 — Python lockfile parsers. `parsers/pypi.py` auto-dispatches by
  filename to handlers for `requirements*.txt` (pinned vs loose vs
  editable/VCS/local), `Pipfile.lock` (default + develop merge),
  `poetry.lock`, and `uv.lock` (workspace-root skip). Loose pins are
  emitted with `version_unspecified=True`. Names canonicalised to
  PEP 503 form. 9 unit tests on inert hand-crafted fixtures. `tomli`
  added as a dev dep for Python 3.10 fallback.
- Step 4 — OSV client + SQLite cache. `advisory/types.py` (`Advisory`,
  `Severity`); `advisory/osv_client.py` synchronous client using
  `httpx.Client(trust_env=False)` (host proxy isolation), batches up
  to 1000 packages via `POST /v1/querybatch`, fetches full details
  via `GET /v1/vulns/{id}`, exponential-backoff retry on 429/5xx;
  `advisory/cache.py` SQLite cache with two tables (queries +
  advisories) supporting negative caching and TTL. MAL-* IDs are
  promoted to severity CRITICAL. 13 unit tests + 1 opt-in live
  network test. `httpx==0.27.2` pinned.
- Step 5 — Matcher + extras.json. `advisory/version_match.py` minimal
  range matcher supporting `=`, `==`, `!=`, `<`, `<=`, `>`, `>=`,
  AND-joined; PEP 440 for PyPI, conservative SemVer-style for npm
  with prerelease ordering; `advisory/extras.py` loads bundled
  extras.json + optional user-supplied feed paths and produces
  `CampaignMatch` records; `advisory/matcher.py` combines extras
  campaigns with OSV findings into `Finding` records carrying
  `is_malicious` + `campaign_name`. Bundled `extras_data/extras.json`
  is a placeholder pending Step 7 Mini Shai-Hulud research. 26 new
  tests. `packaging==26.2` pinned as a runtime dep.
- Step 6 — CLI. `cli.py` exposes `check`, `update`, and `version`
  subcommands via click. `check` accepts a file or directory (with
  filename-based autodetection for npm/PyPI lockfiles). Output
  formats: `text` (rich-rendered), `json` (preliminary; full schema
  in Step 8), `sarif` (stub for Step 8). Flags: `--offline`, `--ci`,
  `--no-color`, `--cache-ttl`, `--feed-file`, `--cache-path`,
  `--explain`. Exit codes follow BUILD_BRIEF §3 (0 / 1 / 2 / 3).
  `report/text.py` rich renderer; `report/json_out.py` minimal
  reporter. `[project.scripts] pwned-deps = "pwned_deps.cli:main"`
  wired. 9 new CliRunner tests. `click==8.1.7` and `rich==13.9.4`
  pinned.
- Step 7 — Mini Shai-Hulud (SAP CAP) campaign in bundled
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
- Step 8 — SARIF v2.1.0 output. `report/sarif.py` produces a
  schema-conforming SARIF log (driver name/version/informationUri,
  unique rules per advisory ID, results with level mapping per the
  brief, stable `partialFingerprints.primaryLocationLineHash` for
  GitHub Code Scanning dedup). `--format sarif` is now wired in
  the CLI. 5 new tests including end-to-end validation against the
  bundled OASIS schema (111 KB at
  `tests/fixtures/sarif/sarif-2.1.0-schema.json`). `jsonschema`
  added as a dev-only dep.
