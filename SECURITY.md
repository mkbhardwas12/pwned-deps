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
  including `release.yml` / `ci.yml` and the dev container.
- The bundled `extras.json` campaign feed (false positives,
  fabricated entries, signature bypass).

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
  the `slsa-github-generator` workflow. Verify with:

  ```bash
  pip download --no-deps pwned-deps
  slsa-verifier verify-artifact pwned_deps-*.whl \
      --provenance-path *.intoto.jsonl \
      --source-uri github.com/mkbhardwas12/pwned-deps
  ```

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
  before publishing. Exit 1 blocks the release.
- **Signed campaign feed (Sigstore + Rekor).** Every push to `main`
  that changes `src/pwned_deps/extras_data/extras.json` triggers
  [`.github/workflows/sign-feed.yml`](.github/workflows/sign-feed.yml),
  which keyless-signs the file with sigstore-python. The signature
  event is logged to the public Rekor transparency log; nobody can
  silently rewrite the project's campaign history without leaving an
  auditable trail.

## Verifying the campaign feed

The bundled feed (`src/pwned_deps/extras_data/extras.json`, also
shipped inside the wheel at `pwned_deps/extras_data/extras.json`) is
signed on every change. Verify with `sigstore-python`:

```bash
pip install "sigstore>=3.6,<4"

# 1. Download the .sigstore bundle from the matching `sign-feed.yml`
#    workflow run on GitHub (Actions → "Sign feed" → the run for the
#    commit you trust → Artifacts → extras-json-sigstore-bundle).

# 2. Verify the file you have matches the bundle, signed by this
#    repository's GitHub Actions OIDC identity.
python -m sigstore verify identity \
    --bundle extras.json.sigstore \
    --cert-identity 'https://github.com/mkbhardwas12/pwned-deps/.github/workflows/sign-feed.yml@refs/heads/main' \
    --cert-oidc-issuer 'https://token.actions.githubusercontent.com' \
    src/pwned_deps/extras_data/extras.json
```

A passing run proves the file content was signed by the
`sign-feed.yml` workflow on `main` of this repo. To audit the full
history of feed changes (including any silently-removed campaigns),
query the Rekor transparency log directly:

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
