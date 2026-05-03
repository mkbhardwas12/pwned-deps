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
