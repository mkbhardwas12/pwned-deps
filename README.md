# pwned-deps

> **Drop your lockfile in, find out if you're pwned.**

<!-- TODO(logo): place a 256x256 PNG at docs/logo.png and reference it here. -->
<!-- TODO(demo): record with `vhs demo.tape`, commit the resulting docs/demo.gif. -->
<!-- ![pwned-deps demo](docs/demo.gif) -->

[![CI](https://github.com/mkbhardwas12/pwned-deps/actions/workflows/ci.yml/badge.svg)](https://github.com/mkbhardwas12/pwned-deps/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/pwned-deps.svg)](https://pypi.org/project/pwned-deps/)
[![Python versions](https://img.shields.io/pypi/pyversions/pwned-deps.svg)](https://pypi.org/project/pwned-deps/)
[![SLSA Level 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

`pwned-deps` is a Python CLI that takes one or more developer lockfiles
(`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `requirements.txt`,
`Pipfile.lock`, `poetry.lock`, `uv.lock`, `Cargo.lock`, `go.sum`,
`pom.xml`, `Gemfile.lock`) and tells you, in seconds, whether you've
installed a package version that's publicly flagged as compromised —
supply-chain malware, abandoned-and-hijacked packages, retroactively
published malicious versions.

## Why this exists

When a supply-chain attack on npm/PyPI/Cargo lands, the first thing
every developer asks is _"did I install one of those bad versions?"_
Today the answer is buried across vendor blogs, GHSA, OSV, the
package's own security tab, and the news article. There is no single
tool that takes a lockfile and gives an instant red/green answer with
the install timestamp.

The launch peg is **Mini Shai-Hulud (April 29, 2026)** — four
SAP-ecosystem npm packages (`@cap-js/sqlite@2.2.2`,
`@cap-js/postgres@2.2.2`, `@cap-js/db-service@2.10.1`, `mbt@1.2.48`)
were briefly poisoned with a credential-stealing preinstall script.
Anyone whose CI ran `npm install` during the ~2–4 h window pulled a
payload that exfiltrated GitHub/npm/AWS/Azure/GCP/K8s creds. Confirming
whether _your_ pipeline ran during that window today requires
manual log-diving. `pwned-deps` is the 5-second answer.

Sources for the launch campaign data, all named research blogs:
[The Hacker News](https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html),
[SecurityBridge](https://securitybridge.com/blog/a-mini-shai-hulud-has-appeared-when-the-npm-supply-chain-reaches-into-sap/),
[Wiz](https://www.wiz.io/blog/mini-shai-hulud-supply-chain-sap-npm).

## Install

```bash
pipx install pwned-deps          # recommended
# or:
pip install --user pwned-deps
```

Python 3.10+ on macOS, Linux, or Windows.

## Quick usage

```bash
# Single file
pwned-deps check ./package-lock.json

# Multiple files / autodetect every supported lockfile in cwd
pwned-deps check .
pwned-deps check ./pyproject.toml ./requirements.lock ./package-lock.json

# Skip network — use cached database only
pwned-deps check . --offline

# Refresh the local cache
pwned-deps update

# JSON for scripting
pwned-deps check . --format json

# SARIF for GitHub Code Scanning
pwned-deps check . --format sarif > pwned-deps.sarif
```

Exit codes:

| Code | Meaning                                |
|------|----------------------------------------|
| `0`  | All clean                              |
| `1`  | At least one MAL-* / EXTRA-* hit (compromised package) |
| `2`  | At least one HIGH/CRITICAL CVE hit (no malicious hits) |
| `3`  | Parse error                            |

## Supported ecosystems

| Ecosystem | Lockfiles                                                 |
|-----------|-----------------------------------------------------------|
| npm       | `package-lock.json` (v1/v2/v3), `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` (v1 + Berry) |
| PyPI      | `requirements*.txt` / `requirements*.lock`, `Pipfile.lock`, `poetry.lock`, `uv.lock` |
| crates.io | `Cargo.lock`                                              |
| Go        | `go.sum`                                                  |
| Maven     | `pom.xml` (`<dependencies>` + `<dependencyManagement>`)   |
| RubyGems  | `Gemfile.lock`                                            |

Loose pins in `requirements.txt` (`>=`, `~=`, `<`) and Maven property-
variable versions (`${spring.version}`) are scanned but reported as
`version_unspecified` — we cannot match an advisory without an exact
version, so they're surfaced as a warning rather than skipped silently.

## Real-world scenarios this is built for

These are the questions developers and security teams actually ask
in the first hour of a published supply-chain incident. The launch
campaign — [Mini Shai-Hulud (Apr 29, 2026)](https://securitybridge.com/blog/a-mini-shai-hulud-has-appeared-when-the-npm-supply-chain-reaches-into-sap/) — is the worked example, but the pattern
recurs every few months.

**"Did *we* run `npm install` during the 2-hour window?"**
Pipe every lockfile in the org through `pwned-deps check`. Exit 1
is the receipt that something matched. The bundled campaign feed
(`extras.json`) covers the four SAP CAP packages the day of the
incident — you don't have to wait for OSV.dev ingestion.

**"Where in our artifact stores are the bad tarballs?"**
For campaigns where a primary source publishes the malicious
`.tgz` SHA-256 (Wiz did for Mini Shai-Hulud), the CLI now prints
the hash next to every flagged version:

```
  @cap-js/sqlite@2.2.2
    EXTRA-2026-0001  Mini Shai-Hulud (SAP CAP)
    tarball sha256: a1da198bb4e883d077a0e13351bf2c3acdea10497152292e873d79d4f7420211
```

Feed that into `find . -name '*.tgz' -exec sha256sum {} +` against
your npm cache, container image layers, and artifact registries
for forensic confirmation — SecurityBridge's recommended approach
rather than relying on version strings alone.

**"What else should we hunt for beyond the lockfile?"**
Most real campaigns leave non-lockfile traces: rogue GitHub repos
on the victim's own account, IDE-config persistence files
(`.claude/execution.js`, `.vscode/setup.mjs`), known C2 domains.
Each campaign in `extras.json` carries an `iocs` list and the CLI
surfaces it next to every finding:

```
  additional indicators to hunt for:
    • GitHub repos with description 'A Mini Shai-Hulud has Appeared' …
    • Commits whose message starts with 'OhNoWhatsGoingOnWithGitHub:' …
    • Files dropped into other repos: .claude/execution.js, .vscode/setup.mjs …
```

No more cross-referencing three vendor blogs to assemble the
remediation list.

**"Did the second-stage payload actually land on a developer
laptop or build runner?"**
After the lockfile match, run the forensic file scanner:

```bash
pwned-deps audit-repo .
pwned-deps audit-repo /path/to/checkout --format json
```

It walks the tree (skipping `node_modules`, `.git`, `.venv`, etc.),
hashes every file under 50 MiB, and matches against the bundled
file IoCs — SAP CAP `.claude/execution.js`, `.vscode/setup.mjs`,
the shared `setup.mjs` dropper, and the IDE-persistence
`settings.json` / `tasks.json` configurations. Exit codes:

| Exit | Meaning                                                       |
|-----:|---------------------------------------------------------------|
|    0 | Clean                                                         |
|    1 | At least one file's SHA-256 matches a known payload (CONFIRMED) |
|    2 | A file sits at a known-persistence path but the bytes differ (SUSPECT — variant or modified) |

**"What about the follow-on packages? They were on a different
ecosystem."**
`extras.json` supports per-package ecosystem overrides so a single
campaign can span npm, PyPI, crates.io, etc. EXTRA-2026-0002
covers `intercom-client@7.0.5` (npm) and `lightning@2.6.2/2.6.3`
(PyPI) under one campaign — the same operator, the same shared
C2, distinct package registries.

**"How do we trust the campaign feed itself?"**
Every change to `extras.json` on `main` is signed with sigstore
keyless OIDC and logged to the public Rekor transparency log. See
[SECURITY.md](SECURITY.md) §"Verifying the campaign feed" for the
verification recipe. Force-pushes and silent removals can't escape
the append-only log.

## CI integration

### GitHub Actions (one line)

```yaml
- uses: mkbhardwas12/pwned-deps@v0.1.0
  with:
    path: .
    fail-on: compromised   # also: `any` (HIGH/CRITICAL too) or `never`
    upload-sarif: true     # writes to GitHub Code Scanning
```

The action installs `pwned-deps` from PyPI, scans every recognised
lockfile under `path`, and uploads SARIF to Code Scanning. Step fails
the build on exit `1` (compromised package) by default. See
[action.yml](action.yml) for all inputs.

### Plain workflow step (no action wrapper)

```yaml
- run: pip install pwned-deps && pwned-deps check . --ci
```

Exit `1` fails the build. Exit `2` is HIGH/CRITICAL CVEs (no
malicious hits) — you decide whether that fails or warns.

### pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/mkbhardwas12/pwned-deps
    rev: v0.1.0
    hooks:
      - id: pwned-deps           # online (api.osv.dev)
      # or:
      # - id: pwned-deps-offline # cache only, no network
```

The hook only fires when a recognised lockfile changes — unrelated
commits skip the network entirely.

### GitLab CI

```yaml
pwned-deps:
  image: python:3.12-slim
  script:
    - pip install pwned-deps
    - pwned-deps check . --ci
  allow_failure: false
```


## Output formats

* **`text`** (default) — colourful terminal output via `rich`,
  MAL-*/EXTRA-* findings prominently flagged.
* **`json`** — machine-readable. Stable schema (top-level: `version`,
  `summary`, `lockfiles[]`, each lockfile carries `findings[]` with
  `id`, `severity`, `package`, `version`, `references`).
* **`sarif`** — SARIF v2.1.0 for GitHub Code Scanning upload. Validates
  against the OASIS schema; `partialFingerprints.primaryLocationLineHash`
  is set so the same finding dedups across runs.

## Threat model

`pwned-deps` is itself a piece of supply-chain software. The brief
`BUILD_BRIEF.md` §2 contains the full safety contract; the highlights:

* **No execution of advisory or package content.** We never run
  `npm install`, `pip install -r`, `cargo build`, `go get`, `mvn`,
  `gem install`, or any other package-manager command on inputs.
  Lockfile parsing is text/JSON/TOML/XML/YAML only.
* **No `eval` / `exec` / `subprocess` / `pickle.load` of user input.**
  A `make verify-safety` target enforces this with a Python regex
  scanner; the negative self-test plants `eval("1+1")` and proves the
  scanner catches it.
* **Network allow-list.** The CLI talks only to `api.osv.dev` (and an
  opt-in `--feed-file PATH` you explicitly hand to it). No telemetry,
  no analytics, no crash reporting.
* **Container-only dev** with non-root `appuser` UID 1000, network
  denied during tests, source mounted read-only, base image pinned
  to a SHA-256 digest.
* **Pinned deps.** Production runtime dependencies are pinned by
  exact version in `requirements.lock`; `--require-hashes` enforcement
  before the first PyPI release is a TODO recorded in
  `requirements.lock`.
* **OIDC publishing only.** The `release.yml` workflow publishes to
  PyPI through the Trusted Publishers OIDC flow — no long-lived
  tokens in repository secrets.
* **No service mode.** We never accept lockfiles via a hosted
  backend we control. The future drag-drop web UI (V1.1) will be
  fully client-side; lockfile contents never leave the browser.
* **Eat your own dog food.** Every CI run executes
  `pwned-deps check ./pyproject.toml ./requirements.lock`. If a
  malicious version of one of our own deps appears, the release is
  blocked.

If `pwned-deps` itself were compromised, the irony would kill the
project. We treat account hygiene as tier-1: hardware-key 2FA on
GitHub, OIDC trusted publishing on PyPI, no shared maintainer
credentials.

### Verify a release with SLSA provenance

Every published wheel and sdist ships with SLSA Level 3 build
provenance generated by [`slsa-github-generator`](https://github.com/slsa-framework/slsa-github-generator).
Verify before installing if you're paranoid (or in a regulated
environment):

```bash
pip download --no-deps pwned-deps
# Grab the matching *.intoto.jsonl from the GitHub Release page,
# then:
slsa-verifier verify-artifact pwned_deps-*.whl \
    --provenance-path pwned_deps-*.intoto.jsonl \
    --source-uri github.com/mkbhardwas12/pwned-deps
```

A passing `slsa-verifier` run cryptographically proves the wheel
was built by [release.yml](.github/workflows/release.yml) on this
repository, by the tagged commit, with no human-in-the-middle.

## Comparison

| Tool             | Multi-ecosystem | Offline cache | MAL-* surfacing  | Open campaign feed | License |
|------------------|-----------------|---------------|------------------|--------------------|---------|
| `npm audit`      | npm only        | no            | partial          | no                 | open    |
| `pip-audit`      | PyPI only       | partial       | partial          | no                 | open    |
| `osv-scanner`    | yes (the bar)   | yes           | partial          | no                 | open    |
| `socket` (paid)  | yes             | n/a           | yes              | yes (paid)         | mixed   |
| **pwned-deps**   | yes             | yes           | first-class      | yes (open)         | Apache-2.0 |

`osv-scanner` (Google) is excellent and well-resourced. If your
priority is breadth of ecosystems and zero project bias, it remains a
strong default. `pwned-deps` adds: a friendlier red/green CLI UX, MAL-*
as a first-class concept (always surfaced regardless of CVSS), and an
open `extras.json` feed for incidents OSV has not yet ingested. We do
not pretend to replace `osv-scanner`.

## FAQ

**Q. What happens if `api.osv.dev` is down?**
The CLI uses `~/.cache/pwned-deps/osv.sqlite` (24 h TTL by default).
Run `--offline` to skip the network entirely; whatever's cached is
what you get. The exit code is identical — no network availability is
silently treated as "all clean".

**Q. How do I add a new campaign before OSV ingests it?**
Send a PR adding an entry to `src/pwned_deps/extras_data/extras.json`.
Each campaign needs an ID, a name, a summary, ≥1 named-blog citation,
the affected ecosystem + (name, version) tuples, an exposure window,
and a remediation list. Five-minute review target.

**Q. Why does `pyproject.toml` print "skipping … not a recognised
lockfile shape"?**
`pwned-deps` audits *lockfiles* (resolved, exact versions). A
`pyproject.toml` is a manifest with declared ranges — there's nothing
deterministic to match against an advisory. Pass it alongside your
real lockfile and it will be skipped with a warning rather than
crashing the run.

**Q. Will you accept attached `.tgz`/`.whl` files in issues to "look
at the malware"?**
No. The repo's contributing rules (and the brief's §2.8) explicitly
forbid attaching compromised package tarballs. PoC patterns are
shared in text only.

**Q. Can I scan Docker images / SBOMs?**
Not in V1. SBOM generation is `syft`'s job; reachability analysis is
out of scope. We consume lockfiles, full stop.

## Contributing

Issues that include attack PoCs must share patterns in text only —
never attach malicious package tarballs to issues.

Adding a new campaign is intentionally a 5-minute PR:

1. Add an entry to `src/pwned_deps/extras_data/extras.json`. Cite at
   least one named research blog (SecurityBridge, Wiz, Sophos, GHSA,
   etc.). Do NOT fabricate version numbers; if a source doesn't pin
   a version, use a `TODO(precise-version)` marker and document the
   sources you checked.
2. Add a fixture lockfile pinning one of the affected versions under
   `tests/fixtures/<ecosystem>/`.
3. Run `make verify-safety && make test` (the dev container does the
   rest).
4. Open the PR.

See [`BUILD_BRIEF.md`](BUILD_BRIEF.md) for the complete architectural
plan and safety contract.

## Maintenance

Issues are triaged within 7 days, not 24 hours. The project is
deliberately solo-OSS-friendly — we'd rather acknowledge slowly than
burn out a single maintainer.

## License

Apache License 2.0 — see [LICENSE](./LICENSE).

## Maintainer

`mkbhardwas12`

Issues: <https://github.com/mkbhardwas12/pwned-deps/issues>
