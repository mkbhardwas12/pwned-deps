# pwned-deps

> **Drop your lockfile in, find out if you're pwned.**

<!-- TODO(logo): place a 256x256 PNG at docs/logo.png and reference it here. -->

[![CI](https://github.com/mkbhardwas12/pwned-deps/actions/workflows/ci.yml/badge.svg)](https://github.com/mkbhardwas12/pwned-deps/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/pwned-deps.svg)](https://pypi.org/project/pwned-deps/)
[![Python versions](https://img.shields.io/pypi/pyversions/pwned-deps.svg)](https://pypi.org/project/pwned-deps/)
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

## Output formats

* **`text`** (default) — colourful terminal output via `rich`,
  MAL-*/EXTRA-* findings prominently flagged.
* **`json`** — machine-readable; stable schema documented in
  [docs/json-schema.md](docs/json-schema.md) (placeholder).
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
