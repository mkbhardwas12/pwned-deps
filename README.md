# pwned-deps

> **Drop your lockfile in, find out if you're pwned.**

`pwned-deps` is a Python CLI that takes a developer's lockfile
(`package-lock.json`, `requirements.txt`, `pnpm-lock.yaml`,
`poetry.lock`, `uv.lock`, `Cargo.lock`, `go.sum`, `Gemfile.lock`,
`pom.xml`) and instantly tells you whether you've installed a package
version that's publicly flagged as compromised — supply-chain malware,
abandoned-and-hijacked packages, retroactively-published malicious
versions.

> ⚠️ **Status:** Pre-V1, under active build. Not yet on PyPI. README
> commands below describe the V1 target; substitute your local clone +
> `make` for now.

## Why this exists

Every supply-chain attack on npm/PyPI/Cargo provokes the same question:
"did I install one of those bad versions?" Today the answer is buried
across vendor blogs, GHSA advisories, OSV, the package's own
security tab, and the news article. There's no single tool that takes a
lockfile and gives an instant red/green answer with the install
timestamp.

The launch peg is **Mini Shai-Hulud (April 29, 2026)** — four
`@cap-js/*` SAP-ecosystem packages and `mbt` (Cloud MTA Build Tool)
were briefly compromised. Anyone whose CI ran `npm install` during the
~2-4h window pulled a credential-stealing payload. ~1,800 victim repos
exfiltrated GitHub/npm/AWS/Azure/GCP/K8s creds. Confirming whether
*your* pipeline ran during that window today requires manual log-diving.
`pwned-deps` is the 5-second answer.

## Install

```bash
pipx install pwned-deps
```

(Coming soon — V1 not yet shipped.)

## Quick usage

```bash
pwned-deps check ./package-lock.json
pwned-deps check .                    # auto-detect lockfiles in cwd
pwned-deps check . --format sarif > pwned-deps.sarif
pwned-deps check --offline .          # use cached database, no network
pwned-deps update                     # refresh the local cache
```

Exit codes:

| Code | Meaning                                |
|------|----------------------------------------|
| `0`  | All clean                              |
| `1`  | At least one MAL-* hit (compromised)   |
| `2`  | At least one HIGH/CRITICAL CVE hit     |
| `3`  | Parse error                            |

## Supported ecosystems (V1 target)

- npm — `package-lock.json` (v1/v2/v3), `npm-shrinkwrap.json`,
  `pnpm-lock.yaml`, `yarn.lock` (v1 + berry)
- PyPI — `requirements.txt` (pinned), `Pipfile.lock`, `poetry.lock`,
  `uv.lock`
- crates.io — `Cargo.lock`
- Go — `go.sum`, `go.mod`
- Maven — `pom.xml`
- RubyGems — `Gemfile.lock`

## Output formats

- `--format text` (default) — colorful terminal output via `rich`,
  MAL-* advisories prominently flagged with 🚨.
- `--format json` — for scripting.
- `--format sarif` — SARIF v2.1.0 for GitHub Code Scanning upload.

## Threat model

`pwned-deps` is itself a piece of supply-chain software. The brief's
safety contract (§2) treats the project as if it were a target: no
execution of advisory or package content; no `eval`/`exec`/`subprocess`
on user-controlled data; container-only dev with non-root `appuser`,
network-denied test runs, read-only source mount; pinned deps with
hashes; OIDC publishing only. See `BUILD_BRIEF.md` §2 for the binding
list and `make verify-safety` for the host-side enforcement check.

We never accept lockfiles via a hosted backend we control. The web
front-end (planned for V1.1) is fully client-side; lockfile contents
never leave the user's browser.

## Comparison

| Tool             | Multi-ecosystem | Offline cache | MAL-* surfacing | Campaign feed |
|------------------|-----------------|---------------|-----------------|---------------|
| `npm audit`      | npm only        | no            | partial         | no            |
| `pip-audit`      | PyPI only       | partial       | partial         | no            |
| `osv-scanner`    | yes (the bar)   | yes           | partial         | no            |
| `socket` (paid)  | yes             | n/a           | yes             | yes (paid)    |
| **pwned-deps**   | yes             | yes           | first-class     | yes (open)    |

Where `osv-scanner` is the right answer for someone, this README will
say so. We add: nicer UX, MAL-* as a first-class concept, an open
campaigns feed (`extras.json`) for incidents OSV hasn't yet ingested.

## Contributing

See `BUILD_BRIEF.md` for the full architectural plan. Issues that
include attack PoCs must share patterns in text only — never attach
malicious package tarballs to issues. The contributing flow for adding
a new campaign to the bundled feed is intentionally a 5-minute PR.

## License

Apache License 2.0 — see [LICENSE](./LICENSE).

## Maintainer

`YOUR_GH_USERNAME` (placeholder — sed-replace before publish).

Issues: <https://github.com/YOUR_GH_USERNAME/pwned-deps/issues>
