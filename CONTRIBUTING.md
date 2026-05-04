# Contributing to pwned-deps

Thanks for your interest. The fastest contribution path is adding
a new compromised-package campaign to the bundled `extras.json`
feed; that's a 5-minute PR and it's the moat of the project.

## Ground rules

1. **No malicious package archives in this repo.** Never attach
   `.tgz`, `.whl`, `.zip`, or any other package artifact that
   contains a real malicious payload to issues, PRs, comments, or
   commits. Patterns and hashes only, in text.
2. **No `eval` / `exec` / `subprocess` / `pickle.load` of input
   content.** This is enforced by `make verify-safety`. The
   negative self-test plants `eval("1+1")` and proves the scanner
   catches it. Don't try to disable it.
3. **The CLI talks only to `api.osv.dev`** plus user-supplied
   `--feed-file` paths. No telemetry, no analytics. New network
   destinations require explicit discussion in an issue first.
4. **Lockfile parsers are text/JSON/TOML/XML/YAML only.** No
   `npm install`, no `pip install -r`, no `cargo build`. Ever.

## Local development

```bash
# Build the locked-down dev container (Debian slim, pinned digest)
make build

# Interactive shell (writable mount, network on — for dep updates)
make shell

# Pre-commit gate: safety self-test + lint + 96-test pytest +
# build wheel + dogfood the wheel in a fresh venv
make release-rehearsal
```

You should run `make release-rehearsal` before opening a PR. If
it goes red locally, CI will go red the same way.

Direct host runs (`pytest`, `ruff`, `pwned-deps check`) work too
once you `pip install -e . -r requirements.lock`, but the
container is the production-equivalent run.

## Adding a new compromised-package campaign

This is the highest-leverage contribution.

1. Edit [`src/pwned_deps/extras_data/extras.json`](src/pwned_deps/extras_data/extras.json).
   Append an entry to `campaigns`. Required fields:
   - `id` — `EXTRA-<year>-<NNNN>`, monotonically increasing.
   - `name` — short human-readable campaign name.
   - `summary` — 2–4 sentences. Plain English, no marketing.
   - `references` — **at least one** named research blog or
     advisory (Wiz, SecurityBridge, Sophos, Snyk, GHSA, OSV).
     Name the source. Do not cite Twitter/X threads.
   - `ecosystem` — one of `npm`, `pypi`, `crates`, `go`, `maven`,
     `rubygems`.
   - `packages` — list of `{name, versions, source}` entries.
     **Do not fabricate version numbers.** If a source doesn't
     pin the version, use `TODO(precise-version)` and document
     which sources you checked.
   - `exposure_window` — `[start_iso, end_iso]`. Conservative
     bounds are fine; document the basis in
     `_exposure_window_note`.
   - `actions` — remediation list. Concrete, imperative,
     credential-rotation-first.
2. Add a fixture lockfile that pins one of the affected versions
   under `tests/fixtures/<ecosystem>/`.
3. Add or extend a test in `tests/` that scans the fixture and
   asserts exit code `1` and the campaign name in output.
4. Run `make release-rehearsal`.
5. Open the PR with the citation links in the description.

Existing entries (`EXTRA-2026-0001`, `EXTRA-2026-0002`) are good
reference shapes.

## PoC handling

If you're filing a security report or referencing a real-world
compromise:

- **Hashes are fine.** SHA-256 of an affected `.tgz` is data,
  not malware.
- **Names + versions are fine.** That's literally the database.
- **Code excerpts are fine in text** if minimised and clearly
  marked as the malicious payload.
- **Compiled or packed archives are not.** No `.tgz`, `.whl`,
  `.zip`, `.tar.gz`, `.exe`, or anything that could be
  double-clicked into execution.

Issues that violate this will be closed and the attachment
removed.

## Code style

- Python 3.10+. Type-annotated. `ruff check` must pass.
- No new runtime dependencies without an issue discussion. The
  current set (`click`, `httpx`, `packaging`, `pyyaml`, `rich`,
  `tomli`) is deliberately small.
- Prefer standard library where reasonable.
- Tests live in `tests/`. Network-bound tests are marked
  `@pytest.mark.network` and excluded from the default run.

## Releasing (maintainers only)

1. Bump `version` in `pyproject.toml` and `src/pwned_deps/__init__.py`.
2. Update `CHANGELOG.md`.
3. `make release-rehearsal` — must end with the green line.
4. `git tag -s v<version> -m "v<version>"` (signed tag).
5. `git push origin v<version>`.
6. CI runs `release.yml`: pre-publish gates → build →
   SLSA L3 provenance → PyPI OIDC publish → GitHub Release.

No manual `twine upload` or local `python -m build` upload.
Ever.
