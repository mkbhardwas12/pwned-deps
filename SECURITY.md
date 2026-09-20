# Security policy

`pwned-deps` is itself a piece of supply-chain security software.
The same hygiene we ask of our users, we apply to ourselves.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security reports.

Use one of the following private channels:

- **GitHub private vulnerability reporting** — preferred:
  <https://github.com/mkbhardwas12/pwned-deps/security/advisories/new>
- **Email** — `mkbhardwas12@users.noreply.github.com` (GitHub-routed
  noreply; messages are forwarded to the maintainer).

Please include:

- A description of the issue and its impact.
- A minimal reproducer **as text** — never as an attached
  package archive (`.tgz`, `.whl`, `.zip`). See
  [CONTRIBUTING.md](CONTRIBUTING.md) §"PoC handling".
- Your assessment of severity (low / medium / high / critical).
- The version of `pwned-deps` you tested against (`pwned-deps
  version`).

## Disclosure timeline

We aim for the following timeline. Solo-OSS-friendly: triage may
take up to 7 days, not 24 hours.

| Step                         | Target                  |
|------------------------------|-------------------------|
| Acknowledgement              | within 7 days           |
| Triage + reproduction        | within 14 days          |
| Fix + release on PyPI        | within 90 days of triage |
| Public advisory + GHSA       | concurrent with release |

If a coordinated disclosure window other than 90 days suits the
reporter (e.g. embargoed industry coordination), please say so in
the report and we will negotiate.

## Scope

In scope:

- The published PyPI package `pwned-deps`.
- The repository at <https://github.com/mkbhardwas12/pwned-deps>,
  including `release.yml` / `ci.yml`, `action.yml` and the dev
  container.
- The bundled `extras.json` campaign feed (false positives,
  fabricated entries, signature bypass) and the publish-timestamp
  resolution logic that promotes SUSPECT hits to CONFIRMED (a way to
  make it clear a genuinely compromised version would be in scope).

Out of scope (please don't report):

- Vulnerabilities in upstream dependencies that we already pin
  (`requirements.lock`) — report those upstream. We surface them
  via dogfooding (`pwned-deps check ./requirements.lock`).
- The accuracy of OSV.dev advisories themselves — report those to
  <https://github.com/google/osv.dev>.
- Social-engineering of the maintainer's GitHub or PyPI accounts —
  hardware-key 2FA + OIDC trusted publishing is in place; please
  report account-takeover concerns to GitHub / PyPI directly.

## Hardening commitments

- **No long-lived publishing tokens.** PyPI publishes via OIDC
  trusted publishers. There is no `PYPI_API_TOKEN` in repository
  secrets.
- **Hardware-key 2FA** on the maintainer's GitHub and PyPI accounts.
- **SLSA Level 3 build provenance** on every released artifact via
  the `slsa-github-generator` workflow. Provenance generation is a
  hard gate (the release fails if it cannot be produced) and the
  release workflow runs `slsa-verifier` against every artifact
  *before* the PyPI upload. Verify yourself with:

  ```bash
  pip download --no-deps pwned-deps
  slsa-verifier verify-artifact pwned_deps-*.whl \
      --provenance-path pwned-deps-vX.Y.Z.intoto.jsonl \
      --source-uri github.com/mkbhardwas12/pwned-deps \
      --source-tag vX.Y.Z
  ```

- **SHA-pinned GitHub Actions.** Every third-party action in
  `.github/workflows/` and `action.yml` is pinned to a full commit
  SHA (Dependabot keeps them current). The one exception is the SLSA
  reusable workflow, which must be referenced by tag for
  `slsa-verifier` to accept the builder ID.
- **Composite action hardening.** `action.yml` passes every input to
  the shell through `env:`, never by interpolating `${{ inputs.* }}`
  into a script, and installs the exact `pwned-deps` release that
  matches the action tag rather than an unpinned "latest".
- **No `eval` / `exec` / `subprocess` / `pickle.load` of input
  content.** Enforced by `make verify-safety` (negative self-test
  proves the regex catches a planted `eval()`).
- **Locked-down dev container.** `make test` runs with
  `--network none --read-only`, source mounted read-only, base image
  pinned by SHA-256 digest.
- **Pinned + hashed dependencies** (`requirements.lock` generated
  with `pip-compile --generate-hashes`).
- **Dogfood gate on release.** `release.yml` runs `pwned-deps check
  ./pyproject.toml ./requirements.lock` against the *built wheel*
  before publishing. Exit 1 (malicious) blocks the release; so do
  exit 3 (parse error) and exit 4 (incomplete scan) — an unchecked
  dependency is not a clean dependency.
- **Signed campaign feed (Sigstore + Rekor).** Two signing events:
  1. Every push to `main` that changes
     `src/pwned_deps/extras_data/extras.json` triggers
     [`.github/workflows/sign-feed.yml`](.github/workflows/sign-feed.yml)
     (interim bundle kept as a 90-day workflow artifact).
  2. Every tagged release re-signs the exact feed that ships in the
     wheel and attaches `extras-vX.Y.Z.json`, `.sha256` and the
     sigstore bundle to the GitHub Release — the durable copy.

  Both are keyless (GitHub Actions OIDC identity) and logged to the
  public Rekor transparency log; nobody can silently rewrite the
  project's campaign history without leaving an auditable trail.

## Verifying the campaign feed

The bundled feed (`src/pwned_deps/extras_data/extras.json`, also
shipped inside the wheel at `pwned_deps/extras_data/extras.json`) is
signed at every release. Verify with `sigstore-python`:

```bash
pip install "sigstore>=3.6,<4"

# 1. From the GitHub Release for the version you installed, download
#    extras-vX.Y.Z.json.sigstore.json (the bundle). Compare the feed
#    you actually have against the one that was signed:
python -c 'import pwned_deps.extras_data, pathlib, hashlib; p = pathlib.Path(pwned_deps.extras_data.__file__).with_name("extras.json"); print(hashlib.sha256(p.read_bytes()).hexdigest())'
#    ...must equal the digest in extras-vX.Y.Z.json.sha256.

# 2. Verify the bundle was produced by THIS repository's release
#    workflow, at THAT tag, via GitHub's OIDC issuer:
python -m sigstore verify identity \
    --bundle extras-vX.Y.Z.json.sigstore.json \
    --cert-identity 'https://github.com/mkbhardwas12/pwned-deps/.github/workflows/release.yml@refs/tags/vX.Y.Z' \
    --cert-oidc-issuer 'https://token.actions.githubusercontent.com' \
    <path-to-your-installed-extras.json>
```

For an unreleased commit on `main`, the interim bundle from the
matching `sign-feed.yml` run (Actions → "Sign feed" → Artifacts →
`extras-json-sigstore-bundle`) verifies the same way with
`--cert-identity '…/.github/workflows/sign-feed.yml@refs/heads/main'`.

A passing run proves the file content was signed by this repo's
GitHub Actions identity. To audit the full history of feed changes
(including any silently-removed campaigns), query the Rekor
transparency log directly:

```bash
# Install rekor-cli once: https://docs.sigstore.dev/system_config/installation/
rekor-cli search --sha $(sha256sum src/pwned_deps/extras_data/extras.json | awk '{print $1}')
```

Rekor is append-only. Force-pushes, account takeovers, and
revisionist history cannot remove a Rekor entry — only add new ones
that anyone can spot.

## Known non-issues

- `pyproject.toml` printing `skipping … not a recognised lockfile
  shape` is intentional. Manifests are not lockfiles.
- The dogfood scan currently surfaces 1 LOW/MEDIUM informational
  finding (pytest GHSA-6w46-j5rx-g56g). Tracked, non-blocking.
