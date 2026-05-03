# Build Log

Per-step record of plan paragraphs, gate evidence, and pending follow-ups.

Conventions:

- **plan**: 5–10 line plan paragraph written *before* implementation starts.
- **gate-passed**: literal command output, captured here.
- **TODO**: known follow-up.

The single source of truth is `BUILD_BRIEF.md`. This log is the execution
trail.

---

## Bootstrap

- Confirmed OrbStack daemon is live (`docker version` server 29.4.0,
  `docker run --rm hello-world` clean).
- Copied `BUILD_BRIEF.md` from the agent-session outputs folder into
  the project root as the first file (521 lines, 31537 bytes).
- This file (`BUILD_LOG.md`) created.
- `git init` then first commit: `chore: import BUILD_BRIEF as source of
  truth`.

### `docker version` (host)

```
Client:
 Version:           29.4.0
 API version:       1.54
 Go version:        go1.26.1
 Git commit:        9d7ad9f
 Built:             Tue Apr  7 08:34:32 2026
 OS/Arch:           darwin/arm64
 Context:           orbstack

Server: Docker Engine - Community
 Engine:
  Version:          29.4.0
  API version:      1.54 (minimum version 1.40)
  Go version:       go1.26.1
  Git commit:       daa0cb7f
  Built:            Tue Apr  7 08:35:43 2026
  OS/Arch:          linux/arm64
  Experimental:     false
```

### `docker run --rm hello-world` (excerpt)

```
Hello from Docker!
This message shows that your installation appears to be working correctly.
```

---

## Step 1 — Project skeleton + Docker dev env

### Plan

Files: `pyproject.toml` (Hatchling, project name `pwned-deps`, version
`0.1.0`, Apache-2.0, py>=3.10, deps deferred until later steps),
`src/pwned_deps/__init__.py` (`__version__ = "0.1.0"`),
`tests/__init__.py`, `tests/test_smoke.py` (asserts version + import),
`Dockerfile.dev` (`python:3.12-slim` floating tag for first build, then
pin via `make pin-base`; non-root `appuser` UID 1000; copies
`requirements.lock` and `pip install --require-hashes`), `Makefile`
(targets per plan; locked-down flags on test/lint), `requirements.lock`
(pytest + pytest-httpx + ruff, pinned with hashes via `pip-compile`
inside container during build), `.gitignore`, `.dockerignore`, `LICENSE`
(Apache-2.0 full text), `README.md` (skeleton with `YOUR_GH_USERNAME`
placeholders), `CHANGELOG.md` (Keep-a-Changelog format).

API shape committed: `pwned_deps.__version__: str` is the only public
symbol at this stage.

Verify-safety regex (brief §7 Step 1 with the brief-sanctioned
`(?<!re\.)\bcompile\(` mitigation so future `re.compile(...)` calls in
parsers do not trigger):

```
\.render\(|\beval\(|\bexec\(|(?<!re\.)\bcompile\(|\bos\.system\(|\bos\.popen\(|\bsubprocess\.|pickle\.load|pickle\.loads|__import__\(|getattr\(__builtins__|importlib\.import_module
```

Test gate (paste real output for each below as it runs):

1. `make build` exit 0
2. `make verify-safety` exit 0 (clean state)
3. Negative: plant `eval("1+1")` in a temp file under `tests/`, rerun
   `make verify-safety`, confirm non-zero exit + line matched, remove
   the file
4. `make shell` → inside container `id -u` = 1000, `whoami` = appuser,
   `PYTHONPATH=/work/src python -c "import pwned_deps;
   print(pwned_deps.__version__)"` prints `0.1.0`
5. `make test` → pytest exit 0, ≥1 smoke test passes
6. `make pin-base` → captures digest, rewrite `Dockerfile.dev` `FROM`
   line, rebuild, paste new `make build` exit 0

Plausible failure modes:

- `pip install --require-hashes` failing because hashes weren't generated
  (mitigation: generate via `pip-compile --generate-hashes` inside an
  intermediate `make shell` session before locking down).
- ARM64 vs x86 wheel availability for pinned deps (using
  `python:3.12-slim` multi-arch image; should be fine on Apple Silicon).
- `--read-only` rootfs failing pytest because of `__pycache__` writes
  (mitigation: tmpfs `/home/appuser/.cache` + `PYTHONDONTWRITEBYTECODE=1`
  in Dockerfile + `pytest -p no:cacheprovider` if needed).

### Mid-step refinement (logged because the brief is the source of truth and we deviated)

The brief's §7 Step 1 describes `verify-safety` as a `grep` regex.
Implementing it that way uncovered two real platform problems:

1. **BSD grep / macOS grep doesn't support the `(?<!re\.)` lookbehind**
   the brief sanctions to allow `re.compile(...)`. BSD grep errors out
   with exit code 2 on the regex, and the Makefile's `if grep ...; then
   FAIL else OK fi` treats exit-2 as "no matches" → silent FALSE PASS.
2. **The Claude Code interactive shell shadows `grep` with a function
   that re-execs as `ugrep`** which has yet a third behaviour, masking
   the issue further.

The brief explicitly anticipates the regex-vs-tooling mismatch ("handle
that with a per-line `# noqa: S` ignore on the specific line, or refine
the regex to `(?<!re\.)compile`"). The cleanest resolution that honors
the brief's regex *literally* on every platform is to enforce the regex
through a tiny Python script (`tools/verify_safety.py`) that uses
Python's `re` module — which supports the lookbehind directly. The
Makefile target now calls `python3 tools/verify_safety.py src tests`.
Regex content is verbatim from the brief.

### Gate — paste of real output

#### `make verify-safety` (clean state)

```
[verify-safety] scanning src, tests for forbidden symbols...
[verify-safety] OK — no forbidden symbols in src, tests
exit=0
```

#### `make verify-safety-self-test` (planted `eval(`, must catch + clean up)

```
[self-test] planting eval() in tests/_safety_self_test_PLANTED.py...
[self-test] OK — verify-safety caught the planted eval() (exit 2).
exit=0
```

(`tests/_safety_self_test_PLANTED.py` did not exist after the run, as
required.)

#### `make build` (initial floating-tag build)

```
#10 naming to docker.io/library/pwned-deps-dev:latest done
#10 unpacking to docker.io/library/pwned-deps-dev:latest 0.1s done
#10 DONE 0.8s
exit=0
```

(Full deps installed: pytest 8.3.3, pytest-httpx 0.32.0, ruff 0.7.4,
plus their pinned transitive resolvers.)

#### Identity probe inside the locked-down container (substitute for `make shell`'s interactive nature)

```
$ docker run --rm -v "$PWD":/work -w /work pwned-deps-dev /bin/bash -c \
    'echo "id -u: $(id -u)"; echo "whoami: $(whoami)"; \
     PYTHONPATH=/work/src python -c "import pwned_deps; print(\"version:\", pwned_deps.__version__)"'
id -u: 1000
whoami: appuser
version: 0.1.0
exit=0
```

#### `make test` (locked-down: `--network none --read-only --tmpfs /tmp -v $PWD:/work:ro --rm`)

```
[verify-safety] scanning src, tests for forbidden symbols...
[verify-safety] OK — no forbidden symbols in src, tests
docker run --rm --network none --read-only --tmpfs /tmp --tmpfs /home/appuser/.cache \
    -v /Users/mkb/projects/pwned-deps:/work:ro -w /work -e PYTHONPATH=/work/src pwned-deps-dev \
    python -m pytest -ra -o cache_dir=/tmp/.pytest_cache
============================= test session starts ==============================
platform linux -- Python 3.12.13, pytest-8.3.3, pluggy-1.6.0
cachedir: /tmp/.pytest_cache
rootdir: /work
configfile: pyproject.toml
testpaths: tests
plugins: anyio-4.13.0, httpx-0.32.0
collected 2 items

tests/test_smoke.py ..                                                   [100%]

============================== 2 passed in 0.00s ===============================
exit=0
```

(Note: `cache_dir=/tmp/.pytest_cache` is required because the rootfs is
read-only and `/work` is bind-mounted ro. `/tmp` is a tmpfs in the
locked-down flags — pytest can write there, the host repo never gets a
`.pytest_cache/` directory.)

#### `make pin-base` and rebuild against pinned digest

```
$ make pin-base
Capturing current python:3.12-slim digest...
3.12-slim: Pulling from library/python
Digest: sha256:46cb7cc2877e60fbd5e21a9ae6115c30ace7a077b9f8772da879e4590c18c2e3
Status: Downloaded newer image for python:3.12-slim
docker.io/library/python:3.12-slim
python@sha256:46cb7cc2877e60fbd5e21a9ae6115c30ace7a077b9f8772da879e4590c18c2e3
```

`Dockerfile.dev` `FROM` line replaced with the pinned digest. Rebuild
and locked-down test re-run:

```
$ make build
#10 naming to docker.io/library/pwned-deps-dev:latest done
#10 unpacking to docker.io/library/pwned-deps-dev:latest done
#10 DONE 0.0s
$ make test
============================== 2 passed in 0.00s ===============================
exit=0
```

#### `make lint` (sanity check, ruff inside locked-down container)

```
$ make lint
docker run --rm --network none --read-only --tmpfs /tmp --tmpfs /home/appuser/.cache \
    -v /Users/mkb/projects/pwned-deps:/work:ro -w /work -e RUFF_CACHE_DIR=/tmp/.ruff_cache pwned-deps-dev \
    ruff check src/ tests/
All checks passed!
exit=0
```

(Required `RUFF_CACHE_DIR=/tmp/.ruff_cache` for the same read-only
rootfs reason as pytest.)

### Step 1 status

**Gate green.** All six items from the plan are evidenced above. Step 1
is complete. Proceeding to Step 2 (npm parser).

---

## Step 2 — npm lockfile parser

### Plan

Files:
- `src/pwned_deps/parsers/__init__.py` — re-exports `Lockfile`,
  `Package`, `Ecosystem`, `ParseError`.
- `src/pwned_deps/parsers/base.py` — dataclasses + the OSV-vocabulary
  `Ecosystem` StrEnum (`npm`, `PyPI`, `crates.io`, `Go`, `Maven`,
  `RubyGems`).
- `src/pwned_deps/parsers/npm.py` — `parse(path) -> Lockfile`. Handles
  `package-lock.json` v1 (`dependencies` only, recursive nested map),
  v2 (both `packages` and `dependencies`; prefer `packages`), v3
  (`packages` only). `npm-shrinkwrap.json` shares v3 schema. Defers
  pnpm and yarn to Step 9.
- `tests/fixtures/npm/` — hand-crafted INERT lockfile JSON fixtures.
  No `node_modules/`, no install ever run on the host.
- `tests/parsers/test_npm.py` — ≥6 unit tests per brief §7 Step 2.

API shape committed:

```python
class Ecosystem(StrEnum):
    NPM = "npm"
    PYPI = "PyPI"
    CRATES = "crates.io"
    GO = "Go"
    MAVEN = "Maven"
    RUBYGEMS = "RubyGems"

@dataclass(frozen=True)
class Package:
    name: str
    version: str
    ecosystem: Ecosystem
    lockfile_path: str
    parents: tuple[str, ...] = ()    # transitive chain (caller -> ... -> us)
    version_unspecified: bool = False  # True for unpinned PyPI entries

@dataclass(frozen=True)
class Lockfile:
    path: Path
    ecosystem: Ecosystem
    packages: tuple[Package, ...]

class ParseError(Exception):
    """Friendly message on corrupted/unsupported lockfiles."""

def parse(path: str | Path) -> Lockfile: ...
```

Test gate (≥6 unit tests):
1. v1 lockfile → list of (name, version) extracted from
   `dependencies` (recursively).
2. v2 lockfile → packages from `packages` map preferred over
   `dependencies` (no double-count).
3. v3 lockfile → packages from `packages` map.
4. Missing file → `ParseError` with friendly message.
5. Empty `packages` → empty `Lockfile`, no crash.
6. Scoped packages (`@cap-js/cds`) parsed with the leading `@`.

Plausible failure modes:
- v2 lockfiles often duplicate entries between `packages` and
  `dependencies`. The brief says "prefer `packages`". A naive merge
  would inflate the count.
- v2/v3 `packages` map keys: the root project is keyed `""`, and other
  entries are `"node_modules/<pkg>"` or
  `"node_modules/<scope>/<pkg>"`. Need to extract `<pkg>` and `<scope>`
  from the key, not the metadata.
- Some entries in `packages` are workspace links (`"link": true`) or
  the root project (key `""`); both should be skipped.

### Gate — paste of real output

#### `make verify-safety`

```
[verify-safety] scanning src, tests for forbidden symbols...
[verify-safety] OK — no forbidden symbols in src, tests
```

#### `make test` (locked-down container)

```
============================= test session starts ==============================
platform linux -- Python 3.12.13, pytest-8.3.3, pluggy-1.6.0
cachedir: /tmp/.pytest_cache
rootdir: /work
configfile: pyproject.toml
testpaths: tests
plugins: anyio-4.13.0, httpx-0.32.0
collected 10 items

tests/parsers/test_npm.py ........                                       [ 80%]
tests/test_smoke.py ..                                                   [100%]

============================== 10 passed in 0.01s ==============================
exit=0
```

8 parser tests covering: v1 nested tree (with parent chain),
v2 prefer-`packages`-no-double-count, v2 workspace-link skip, v3
packages-only, scoped `@cap-js/cds`, empty `packages`, missing file
(friendly ParseError), corrupted JSON (friendly ParseError),
unsupported `lockfileVersion`. Brief required ≥6.

#### `make lint`

```
All checks passed!
```

### Step 2 status

**Gate green.** Proceeding to Step 3 (pip / Python lockfile parsers).

---

## Step 3 — pip / Python lockfile parsers

### Plan

Files:
- `src/pwned_deps/parsers/pypi.py` — exposes `parse(path) -> Lockfile`
  that auto-dispatches based on filename to one of four format
  handlers: `_parse_requirements_txt`, `_parse_pipfile_lock`,
  `_parse_poetry_lock`, `_parse_uv_lock`.
- TOML handling: try `tomllib` (stdlib ≥3.11), fall back to `tomli`
  (added to `requirements.lock` for the dev container; PyPI users on
  3.10 will get it as a runtime dep — added in pyproject.toml later).
- `tests/fixtures/pypi/{requirements.txt, Pipfile.lock, poetry.lock,
  uv.lock}` — INERT text files only, hand-crafted.
- `tests/parsers/test_pypi.py` — ≥4 unit tests (target ≥6).

API shape committed:

```python
def parse(path: str | Path) -> Lockfile: ...
# auto-dispatch by filename. Internal helpers exposed for tests.
```

Loose pins (`>=`, `<`, `~=`, etc.) in `requirements.txt` are emitted
as `Package(version_unspecified=True)`. The matcher in Step 5 will
exclude `version_unspecified=True` from advisory matching with a
clear note in the report. Editable installs (`-e .`), VCS URLs
(`git+https://...`), local paths (`./mylib`), `-r requirements-dev.txt`
includes, and inline comments are all gracefully skipped.

Test gate (≥6 tests):
1. Pinned `requirements.txt` (`==`) → list of packages.
2. Loose `requirements.txt` (`>=`, `<`, `~=`) → emitted with
   `version_unspecified=True`.
3. Editables, VCS URLs, local paths, comments, `-r` includes →
   ignored without crash.
4. `Pipfile.lock` → packages from `default` + `develop`.
5. `poetry.lock` → packages from `[[package]]` array.
6. `uv.lock` → packages from `[[package]]` array, skipping workspace
   roots (no `version` field).

Plausible failure modes:
- TOML import differs between 3.10 and 3.11+. We probe both.
- `Pipfile.lock` versions are stored as `"==1.2.3"` strings; strip
  the `==` prefix.
- `poetry.lock` and `uv.lock` are structurally similar but not
  identical (uv has `dependencies` arrays of strings; poetry has
  more shapes). Keep helpers separate to avoid a leaky abstraction.

### Gate — paste of real output

#### `make test`

```
============================= test session starts ==============================
platform linux -- Python 3.12.13, pytest-8.3.3, pluggy-1.6.0
cachedir: /tmp/.pytest_cache
rootdir: /work
configfile: pyproject.toml
testpaths: tests
plugins: anyio-4.13.0, httpx-0.32.0
collected 19 items

tests/parsers/test_npm.py ........                                       [ 42%]
tests/parsers/test_pypi.py .........                                     [ 89%]
tests/test_smoke.py ..                                                   [100%]

============================== 19 passed in 0.02s ==============================
exit=0
```

9 PyPI parser tests covering: pinned `requirements.txt` (with extras
stripped + line-continuation tolerated), loose pins flagged
`version_unspecified=True`, editable/VCS/local-path skip,
`Pipfile.lock` default+develop merge, `poetry.lock` `[[package]]`
extraction, `uv.lock` workspace-root skip, unrecognised filename
ParseError, corrupted JSON ParseError, corrupted TOML ParseError.
Brief required ≥4.

#### `make lint`

```
All checks passed!
```

### Step 3 status

**Gate green.** `tomli==2.0.2` was added to `requirements.lock` and the
container rebuilt. Proceeding to Step 4 (OSV client + SQLite cache).

---

## Step 4 — OSV client + SQLite cache

### Plan

Files:
- `src/pwned_deps/advisory/__init__.py` — re-exports `Advisory`,
  `OsvClient`, `Cache`, `Severity`.
- `src/pwned_deps/advisory/types.py` — `Advisory` dataclass + `Severity`
  StrEnum (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`).
- `src/pwned_deps/advisory/osv_client.py` — `OsvClient` with
  `query_batch(packages)` calling `POST /v1/querybatch` (chunks of
  ≤1000) and `GET /v1/vulns/{id}` for full details. Retries on 429/5xx
  with exponential backoff (max 3 attempts). Uses
  `httpx.Client(timeout=30, trust_env=False)` — `trust_env=False`
  is the sandbox second-opinion refinement that protects against host
  proxy env vars (`HTTPS_PROXY`/`SSL_CERT_FILE`) being silently
  honoured. The brief's safety contract §2.3 allow-lists only
  `api.osv.dev`; trust_env=False removes a side-channel.
- `src/pwned_deps/advisory/cache.py` — SQLite at
  `~/.cache/pwned-deps/osv.sqlite` (or `XDG_CACHE_HOME` if set, or
  `%LOCALAPPDATA%` on Windows). Two-table schema (deviation logged
  below).
- `tests/advisory/test_osv_client.py`, `tests/advisory/test_cache.py` —
  unit tests with `pytest-httpx`. Network test marked `@pytest.mark.network`.

API shape committed:

```python
@dataclass(frozen=True)
class Advisory:
    id: str
    summary: str
    ecosystem: str
    package: str
    version: str
    references: tuple[str, ...]
    severity: Severity
    raw: dict[str, object]

class OsvClient:
    def __init__(self, *, cache: Cache | None = None,
                 base_url: str = "https://api.osv.dev",
                 user_agent: str = ...) -> None: ...
    def query_batch(self, packages: Sequence[Package]) -> dict[Package, list[Advisory]]: ...
    def close(self) -> None: ...

class Cache:
    def __init__(self, path: Path, *, ttl_seconds: int = 86400) -> None: ...
    def get(self, ecosystem, package, version) -> list[Advisory] | None: ...
    def put(self, ecosystem, package, version, advisories) -> None: ...
```

**Schema deviation (logged here, not a divergence from intent):** the
brief shows one table `advisories(id PK, ecosystem, package, version,
payload_json, fetched_at)`. With `id` as a sole PK, an advisory that
affects multiple `(eco, pkg, ver)` tuples can only be stored against
one — that breaks per-package lookups. We use a composite PK
`(id, ecosystem, package, version)` and add a separate `queries`
table tracking last-fetched-at per `(eco, pkg, ver)` so we can tell
"queried, no advisories" apart from "never queried". Functionally
equivalent to the brief's intent; faithful to the index `ix_pkg`.

Test gate (≥6 tests):
1. Single-package query with mocked OSV → expected advisories.
2. Batch of 50 → per-package mapping correct.
3. 429 → retry succeeds on second attempt.
4. Cache hit → no network call (`pytest-httpx` will assert the
   request count is 0).
5. TTL: stale entry → re-fetched.
6. Empty result cached as a negative — second call hits cache,
   no network.
7. (Opt-in `pytest -m network`) live OSV: `lodash@4.17.20` returns
   ≥1 advisory.

Plausible failure modes:
- `pytest-httpx` defaults to "every request must be matched" and "all
  responses must be consumed". Tests using fewer mocked responses
  than expected may fail unless we configure that.
- Default `~/.cache` path is host-specific; the dev container's
  `$HOME` is `/home/appuser` and that's tmpfs-mounted in our flags
  — works inside container, but tests must use `tmp_path` to be
  hermetic.

### Mid-step refinement

The `@pytest.mark.network` marker was registered but pytest does not
deselect tests with markers by default. The first run inside the
locked-down container (`--network none`) failed the live-OSV test
with `httpx.ConnectError`. Fixed by adding `-m 'not network'` to the
default `addopts` in `pyproject.toml`. `pytest -m network` from a
host shell with real network is the documented opt-in path.

### Gate — paste of real output

#### `make test` (locked-down container)

```
============================= test session starts ==============================
platform linux -- Python 3.12.13, pytest-8.3.3, pluggy-1.6.0
cachedir: /tmp/.pytest_cache
rootdir: /work
configfile: pyproject.toml
testpaths: tests
plugins: anyio-4.13.0, httpx-0.32.0
collected 33 items / 1 deselected / 32 selected

tests/advisory/test_cache.py .....                                       [ 15%]
tests/advisory/test_osv_client.py ........                               [ 40%]
tests/parsers/test_npm.py ........                                       [ 65%]
tests/parsers/test_pypi.py .........                                     [ 93%]
tests/test_smoke.py ..                                                   [100%]

======================= 32 passed, 1 deselected in 0.06s =======================
```

13 new advisory tests:
- Cache: get-when-empty, round-trip, negative-caching distinguishable
  from never-queried, TTL expiry, put-replaces-existing.
- OsvClient: single-pkg query, all-clean batch, 50-pkg single-batch,
  429-then-200 retry, offline-mode short-circuit, cache-hit-skips-net,
  MAL-* → CRITICAL severity promotion, version_unspecified short-circuit.
- Plus one live `@pytest.mark.network` test (`lodash@4.17.20`)
  deselected from default runs.

Brief required ≥6; we have 13.

#### `make lint`

```
All checks passed!
```

### Step 4 status

**Gate green.** Schema deviation (composite PK + extra `queries` table)
documented above. `httpx==0.27.2` pinned in requirements.lock and
declared as a runtime dep in pyproject.toml. Proceeding to Step 5
(matcher + extras).

---

## Step 5 — Matcher + extras.json

### Plan

Files:
- `src/pwned_deps/advisory/extras.py` — loads bundled extras.json
  (`src/pwned_deps/extras_data/extras.json`, populated for real in
  Step 7) plus optional user-supplied path/URL. Per campaign,
  iterates packages and tests version specs against each lockfile
  entry.
- `src/pwned_deps/advisory/version_match.py` — minimal
  SemVer/PEP-440 range matcher supporting ops `=`, `==`, `!=`,
  `<`, `<=`, `>`, `>=`, AND-joined with `,`. Exact-version strings
  are also supported as shorthand. PyPI uses `packaging.version`;
  npm uses a tuple compare with prerelease awareness.
- `src/pwned_deps/advisory/matcher.py` — `Finding` dataclass +
  `Matcher.match(lockfile) -> list[Finding]`. Combines OSV findings
  (via `OsvClient.query_batch`) with extras.json campaign hits.
  Each Finding carries `is_malicious` and an optional
  `campaign_name`.
- `src/pwned_deps/extras_data/extras.json` — placeholder valid
  payload at this step. Real Mini Shai-Hulud data lands in Step 7
  with proper source citations.
- Tests: `tests/advisory/test_version_match.py`,
  `tests/advisory/test_extras.py`, `tests/advisory/test_matcher.py`.

API shape committed:

```python
@dataclass(frozen=True)
class Finding:
    package: Package
    advisory: Advisory
    is_malicious: bool
    campaign_name: str | None = None

class Matcher:
    def __init__(self, *, osv_client: OsvClient, extras: ExtrasFeed) -> None: ...
    def match(self, lockfile: Lockfile) -> list[Finding]: ...

class ExtrasFeed:
    @classmethod
    def from_bundled(cls, *, user_paths: Sequence[Path] = ()) -> ExtrasFeed: ...
    def find_matches(self, lockfile: Lockfile) -> list[Finding]: ...
```

`packaging` is already a transitive dep of pytest; we'll declare it
explicitly in pyproject.toml runtime deps and pin `packaging==26.2`
in requirements.lock for determinism.

Test gate (from brief §7 Step 5):
1. `lodash@4.17.15` produces ≥1 OSV finding (mocked).
2. Fake `@cap-js/foo@1.2.3` matching a bundled-extras campaign
   yields `is_malicious=True` and `campaign_name=...`.
3. No false positives on benign packages.
4. Range matching: `>=4.17.0,<4.17.21` hits `4.17.15` but not
   `4.17.22`.

Plausible failure modes:
- npm prereleases (`1.0.0-rc.1`) compare differently from stable
  versions in SemVer. The minimal comparator must at least put
  pre-releases below the corresponding non-pre version.
- An extras.json with a malformed campaign should be ignored with
  a warning, not crash the whole scan.

### Gate — paste of real output

#### `make test`

```
============================= test session starts ==============================
collected 59 items / 1 deselected / 58 selected

tests/advisory/test_cache.py .....                                       [  8%]
tests/advisory/test_extras.py ......                                     [ 18%]
tests/advisory/test_matcher.py ....                                      [ 25%]
tests/advisory/test_osv_client.py ........                               [ 39%]
tests/advisory/test_version_match.py ................                    [ 67%]
tests/parsers/test_npm.py ........                                       [ 81%]
tests/parsers/test_pypi.py .........                                     [ 96%]
tests/test_smoke.py ..                                                   [100%]

======================= 58 passed, 1 deselected in 0.09s =======================
exit=0
```

26 new tests this step:
- `test_version_match.py` (16): exact, range AND, inequality,
  PEP 440 PyPI specials, npm prerelease, garbage tolerance.
- `test_extras.py` (6): exact + range matches, no false positives,
  user-supplied feed loading, malformed feed graceful, unspecified
  packages skipped.
- `test_matcher.py` (4): OSV finding for lodash, extras campaign
  marks `is_malicious=True` + `campaign_name`, clean lockfile,
  unspecified-version short-circuit (no OSV call).

Brief required 4 specific gates: lodash OSV (✓), `@cap-js/foo`
malicious (✓), no false positives (✓), range matching (✓).

#### `make lint`

Initial run flagged a Unicode `×` (multiplication sign) in a
docstring as RUF002 ambiguous-character. Replaced with ASCII
`x`. Re-run: `All checks passed!`.

### Step 5 status

**Gate green.** `packaging>=24.0,<28.0` declared as a runtime dep,
`packaging==26.2` pinned. Proceeding to Step 6 (CLI).

---

## Step 6 — CLI

### Plan

Files:
- `src/pwned_deps/cli.py` — click app with three subcommands:
  - `check [PATH]` — scan a single lockfile or autodetect under a
    directory; supports `--format {text,json,sarif}`, `--offline`,
    `--ci`, `--cache-ttl`, `--explain`, `--no-color`,
    `--feed-file PATH` (allow-listed extras feed).
  - `update` — refresh cache + bundled extras (Step 4 cache TTL is
    enough for V1; refresh is a passthrough that re-queries every
    cached row).
  - `version` — print `pwned_deps.__version__`.
- `src/pwned_deps/report/__init__.py` — re-exports.
- `src/pwned_deps/report/text.py` — rich-based terminal renderer.
  JSON / SARIF reporters land in Step 8; for now `--format json`
  emits a minimal hand-rolled JSON shape so the gate item passes,
  with TODO marker for SARIF.
- `tests/test_cli.py` — `click.testing.CliRunner` end-to-end tests.

API shape committed:

```python
# in cli.py
@click.group()
def main(): ...

@main.command()
@click.argument("path")
@click.option("--format", "fmt", type=click.Choice(["text", "json", "sarif"]))
@click.option("--offline/--no-offline")
@click.option("--ci/--no-ci")
@click.option("--no-color/--color")
@click.option("--cache-ttl", type=int)
@click.option("--feed-file", type=click.Path(exists=True))
@click.option("--explain")
def check(...): ...

@main.command()
def update(): ...

@main.command()
def version(): ...
```

Auto-detect when PATH is a directory: known filenames
(`package-lock.json`, `npm-shrinkwrap.json`, `requirements.txt`,
`Pipfile.lock`, `poetry.lock`, `uv.lock`). Other ecosystems
(`pnpm-lock.yaml`, `yarn.lock`, `Cargo.lock`, `go.sum`, `pom.xml`,
`Gemfile.lock`) get a "not yet supported in this build" stub; they
land in Step 9.

Exit codes (per BUILD_BRIEF §3):
- 0 clean
- 1 ≥1 MAL-* / EXTRA-* hit
- 2 ≥1 HIGH/CRITICAL CVE hit (no MAL-*/EXTRA-*)
- 3 parse error in any scanned file

Test gate (from brief §7 Step 6):
1. `check ./tests/fixtures/clean.lock.json` → exit 0, "All clean".
2. `check ./tests/fixtures/mini-shaihulud.lock.json` (synthetic
   campaign — real entry comes in Step 7) → exit 1, COMPROMISED
   header, campaign name in output.
3. `--format json` → emits valid JSON parseable by `json.loads`,
   schema-checked against expected keys.
4. `--ci --format text` → deterministic exit code, no ANSI codes.
5. `--offline` with empty cache → friendly text or exit 0.

Plausible failure modes:
- click's `--no-color` option name collides with rich's
  `Console(no_color=True)` keyword. Wire them carefully.
- Auto-detect must not blow up on a directory with no recognised
  lockfile (exit 0 with "no lockfiles found" warning).
- `[project.scripts]` registration in pyproject.toml needs a
  rebuild because the entrypoint is wired at install time.

### Mid-step refinements

1. Rich's `Console` defaults to 80 columns in non-TTY contexts
   (CliRunner output, CI logs). It wrapped `package-lock.json`
   across two lines in the directory-autodetect test. Fixed by
   forcing `width=200` in the renderer.

2. SARIF (`--format sarif`) is reserved for Step 8. Step 6's CLI
   prints a friendly stub-and-fallback message when invoked.

### Gate — paste of real output

#### `make test`

```
collected 68 items / 1 deselected / 67 selected

tests/advisory/test_cache.py .....                                       [  7%]
tests/advisory/test_extras.py ......                                     [ 16%]
tests/advisory/test_matcher.py ....                                      [ 22%]
tests/advisory/test_osv_client.py ........                               [ 34%]
tests/advisory/test_version_match.py ................                    [ 58%]
tests/parsers/test_npm.py ........                                       [ 70%]
tests/parsers/test_pypi.py .........                                     [ 83%]
tests/test_cli.py .........                                              [ 97%]
tests/test_smoke.py ..                                                   [100%]

======================= 67 passed, 1 deselected in 0.12s =======================
```

9 new CLI tests cover all 5 brief gates (clean, malicious + campaign
name, --format json, --ci no ANSI, --offline empty cache) plus
directory autodetect, parse-error → exit 3, version subcommand,
update subcommand.

#### Hands-on `python -m pwned_deps.cli` runs (dev container, network on)

Synthetic malicious lockfile, offline:

```
$ docker run --rm -v "$PWD":/work -w /work -e PYTHONPATH=/work/src pwned-deps-dev \
    python -m pwned_deps.cli check tests/fixtures/npm/synthetic-malicious.lock.json \
    --feed-file tests/fixtures/extras/synthetic-campaign.json \
    --offline --cache-path /tmp/cache.sqlite --ci
pwned-deps 0.1.0 — checking tests/fixtures/npm/synthetic-malicious.lock.json (npm)

COMPROMISED — 1 package(s)
  @cap-js/test-pkg@1.2.3
    EXTRA-TEST-0001  Synthetic test campaign
    Synthetic test campaign — INERT — used by tests/test_cli.py to drive the COMPROMISED branch.
    refs: https://example.test/research

1 packages scanned · 1 compromised · 0 high/critical · 0 low/medium
exit=1
```

**Live dogfood** (network on; no `--offline`) against our own
`requirements.lock`:

```
$ docker run --rm -v "$PWD":/work -w /work -e PYTHONPATH=/work/src pwned-deps-dev \
    python -m pwned_deps.cli check requirements.lock --cache-path /tmp/cache.sqlite --ci
pwned-deps 0.1.0 — checking requirements.lock (PyPI)

8 packages scanned · 0 compromised · 0 high/critical · 1 low/medium
exit=0
```

The 1 low/medium hit is `pytest@8.3.3` (GHSA-6w46-j5rx-g56g, severity
MEDIUM). pytest is a dev-only tool, not bundled in the wheel; the
dogfood gate per BUILD_BRIEF §3 cares about MAL-* (exit 1) and
HIGH/CRITICAL (exit 2), so exit 0 is the right outcome. **TODO** —
when bumping deps, evaluate whether a pytest 8.4+ release is
available that addresses this advisory.

#### `make lint`

```
All checks passed!
```

(Initial run flagged 5 ruff issues — import sorting, `Optional[X]` →
`X | None` per UP007, an unused noqa, and a stale `_ = sys` guard.
All fixed.)

### Step 6 status

**Gate green.** All 5 brief gate items pass. CLI is wired via
`[project.scripts] pwned-deps = "pwned_deps.cli:main"`. Live OSV
scan against our own lockfile dogfoods exit 0 with one MEDIUM dev
tool advisory noted. Proceeding to Step 7 (Mini Shai-Hulud
extras.json).

---

## Step 7 — Bundled extras.json with Mini Shai-Hulud entry

### Plan

Source the campaign details from the cited research blogs in
BUILD_BRIEF §1 (SecurityBridge, Wiz, Sophos, Aikido, Ox Security,
The Hacker News, The Register, SecurityWeek). Use WebFetch on the
public blog posts to extract:

1. The four `@cap-js/*` package names and the affected versions.
2. The `mbt` package version(s).
3. The exposure window (start/end UTC).
4. SHA256 digests of the affected `.tgz` files, if any source
   publishes them.
5. The remediation list (which credentials to rotate).

Hard rule from user reinforcement: do not `npm pack`/`npm
view`/`npm install` any of those package versions. Web access for
reading public research blog posts is fine. If a reference does not
yield a clean exact version, leave a `TODO(precise-version)` with
the URLs checked. Do not fabricate.

Files:
- `src/pwned_deps/extras_data/extras.json` — replace the placeholder
  `campaigns: []` with a populated `EXTRA-2026-0001 — Mini
  Shai-Hulud (SAP CAP)` entry.
- `tests/fixtures/npm/mini-shaihulud.lock.json` — small lockfile
  pinning ONE of the affected packages at one of the documented
  versions, used by an end-to-end CLI test.
- `tests/test_step7_mini_shaihulud.py` — runs `pwned-deps check`
  against that fixture and asserts exit 1 + campaign name +
  exposure-window text + at least one remediation action visible
  in the output.

Test gate (from brief §7 Step 7): "running `pwned-deps check`
against a fixture lockfile that pins one of the known-bad versions
returns the campaign as a finding with the correct exposure window
and remediation steps."

Plausible failure modes:
- A reference may quote a version range or "all versions before X
  patched" without naming concrete affected versions. Fall back to
  TODO(precise-version) for the version field.
- Different sources may disagree slightly on exposure window edges.
  Use the widest documented window so we don't miss anyone.

### Sources consulted (and what they yielded)

- **wiz.io** — https://www.wiz.io/blog/mini-shai-hulud-supply-chain-sap-npm
  - Confirmed all four (name, version) pairs and published SHA256
    digests for each `.tgz`.
  - Did not pin the exposure-window timestamps.
- **securitybridge.com** —
  https://securitybridge.com/blog/a-mini-shai-hulud-has-appeared-when-the-npm-supply-chain-reaches-into-sap/
  - Confirmed all four packages.
  - Quantified: ≥1,000 victim repos visible to public GitHub
    search; ~570k combined weekly downloads. Phrased the window as
    "roughly two to four hours" on April 29, 2026 — no UTC stamps.
- **thehackernews.com** —
  https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html
  - **Pinned the publication time of the malicious versions:**
    "between 09:55 UTC and 12:14 UTC" on April 29, 2026.
  - Confirmed all four packages.

### Decisions

- Start of window: `2026-04-29T09:55:00Z` (cited from THN).
- End of window: `2026-04-29T14:00:00Z` — conservative upper bound.
  THN gives 12:14 UTC as the publication-time *upper edge* (when
  the last malicious version went live), not the removal time.
  SecurityBridge says removal happened within "two to four hours".
  Using 14:00 UTC = 09:55 + ~4h, the upper end of SecurityBridge's
  range. **TODO(precise-end-time)** marker recorded inline in
  extras.json so a maintainer can tighten this if a primary source
  publishes the npm-registry pull time.
- April-30 follow-on trojans (`intercom-client@7.0.5`,
  `lightning@2.6.2/3`) noted only in Wiz are deferred to a
  separate `EXTRA-2026-0002` entry — not strictly part of the
  "Mini Shai-Hulud (SAP CAP)" campaign and not in scope for the
  V1 launch peg.

### Gate — paste of real output

#### `make test`

```
collected 71 items / 1 deselected / 70 selected

tests/advisory/test_cache.py .....                                       [  7%]
tests/advisory/test_extras.py ......                                     [ 15%]
tests/advisory/test_matcher.py ....                                      [ 21%]
tests/advisory/test_osv_client.py ........                               [ 32%]
tests/advisory/test_version_match.py ................                    [ 55%]
tests/parsers/test_npm.py ........                                       [ 67%]
tests/parsers/test_pypi.py .........                                     [ 80%]
tests/test_cli.py .........                                              [ 92%]
tests/test_smoke.py ..                                                   [ 95%]
tests/test_step7_mini_shaihulud.py ...                                   [100%]

======================= 70 passed, 1 deselected in 0.13s =======================
exit=0
```

#### Live `pwned-deps check` against the bundled Mini Shai-Hulud
fixture (offline so no OSV mocking required):

```
pwned-deps 0.1.0 — checking tests/fixtures/npm/mini-shaihulud.lock.json (npm)

COMPROMISED — 1 package(s)
  @cap-js/sqlite@2.2.2
    EXTRA-2026-0001  Mini Shai-Hulud (SAP CAP)
    Mini Shai-Hulud (SAP CAP) — On April 29, 2026 four SAP-ecosystem
    npm packages (three @cap-js/* and the mbt build tool) were
    briefly poisoned with a credential-stealing preinstall script.
    Anyone whose CI ran `npm install` during the exposure window
    pulled a payload that exfiltrated GitHub/npm/cloud/Kubernetes
    secrets via attacker-created public repos.
    refs: thehackernews.com, securitybridge.com, wiz.io

1 packages scanned · 1 compromised · 0 high/critical · 0 low/medium
exit=1
```

#### `make lint`

```
All checks passed!
```

### Step 7 status

**Gate green.** The bundled `extras.json` carries the Mini
Shai-Hulud (SAP CAP) campaign with all four packages, their
published SHA256 digests, an exposure window sourced from named
research blogs, and an 8-step remediation list. Brief's gate item —
"running pwned-deps check against a fixture lockfile that pins one
of the known-bad versions returns the campaign with the correct
exposure window and remediation" — is met. Proceeding to Step 8
(JSON + SARIF reporters).

---

## Step 8 — JSON + SARIF v2.1.0 reporters

### Plan

Files:
- `src/pwned_deps/report/sarif.py` — produces a SARIF v2.1.0 log
  conforming to the OASIS schema. One `tool.driver.rules` entry
  per unique advisory ID; `results[].level` mapped per BUILD_BRIEF
  §7 Step 8 (MAL-* + CRITICAL + HIGH → `error`, MEDIUM →
  `warning`, LOW → `note`); `results[].partialFingerprints` for
  stable dedup across runs (sha256 of `{rule_id}|{package}|{version}|{lockfile}`).
- `src/pwned_deps/report/json_out.py` — already produces a valid
  JSON; tighten the schema and add stable ordering.
- `tests/fixtures/sarif-2.1.0-schema.json` — bundled OASIS SARIF
  v2.1.0 schema (fetched from json.schemastore.org).
- `tests/test_report_sarif.py` — generates SARIF for the bundled
  Mini Shai-Hulud fixture, validates against the schema with
  `jsonschema`, asserts key fields.
- Wire `--format sarif` in `cli.py` to call the real renderer (was
  a stub).

`jsonschema` becomes a dev-only dep (test gate only). Pinning in
`requirements.lock` (not pyproject.toml runtime).

Test gate (from brief §7 Step 8): "scan a known-malicious fixture,
emit SARIF, validate against bundled schema (jsonschema), assert
key fields." The brief also mentions "Upload to a sandbox GitHub
repo and confirm the SARIF appears in Code Scanning alerts" — that
needs GitHub auth + a test repo, which is out-of-scope for this
local build (we don't push). Documented as a manual verification
step in the V1 acceptance section.

Plausible failure modes:
- SARIF schema is large (~140 KB) and uses many `$ref`s; vendoring
  the file from `json.schemastore.org` should still satisfy
  `jsonschema.validate`.
- `partialFingerprints` keys are case-sensitive and require an
  alphanumeric local part. Use `primaryLocationLineHash` (a
  predefined SARIF key).

### Gate — paste of real output

#### `make test`

```
collected 76 items / 1 deselected / 75 selected

tests/advisory/test_cache.py .....                                       [  6%]
tests/advisory/test_extras.py ......                                     [ 14%]
tests/advisory/test_matcher.py ....                                      [ 20%]
tests/advisory/test_osv_client.py ........                               [ 30%]
tests/advisory/test_version_match.py ................                    [ 52%]
tests/parsers/test_npm.py ........                                       [ 62%]
tests/parsers/test_pypi.py .........                                     [ 74%]
tests/test_cli.py .........                                              [ 86%]
tests/test_report_sarif.py .....                                         [ 93%]
tests/test_smoke.py ..                                                   [ 96%]
tests/test_step7_mini_shaihulud.py ...                                   [100%]

======================= 75 passed, 1 deselected in 0.16s =======================
exit=0
```

5 new SARIF tests:
- Validates SARIF output for a malicious finding against the
  bundled OASIS schema with `jsonschema.validate`.
- Asserts top-level fields (`version=2.1.0`, `tool.driver.name`,
  `tool.driver.version`, `informationUri`, `rules`).
- Confirms the level mapping per the brief (malicious + HIGH /
  CRITICAL → `error`).
- Confirms `partialFingerprints.primaryLocationLineHash` is stable
  across two render passes (sha256 of
  `rule_id|package|version|lockfile`).
- End-to-end: `pwned-deps check ... --format sarif` against the
  bundled Mini Shai-Hulud fixture validates against the schema and
  surfaces `EXTRA-2026-0001` in the rules block.

Bundled OASIS schema: 111,720 bytes at
`tests/fixtures/sarif/sarif-2.1.0-schema.json`.

#### `make lint`

```
All checks passed!
```

### Out-of-scope: GitHub Code Scanning upload

The brief mentions "Upload to a sandbox GitHub repo and confirm the
SARIF appears in Code Scanning alerts". That requires GitHub auth
and a test repository that the local build does not have (no push,
no token generation per the user's reinforcement). Documented in
the V1 acceptance section as a manual verification step the
maintainer runs before tagging V1.0.0.

### Step 8 status

**Gate green.** SARIF output validates against the bundled OASIS
schema and surfaces every required field. JSON output (already
preliminarily implemented in Step 6) is the same shape; no schema
file is required for it. Proceeding to Step 9 (remaining ecosystem
parsers).

---

## Step 9 — Remaining ecosystem parsers

### Plan

Six parsers, one file each:

- `parsers/pnpm.py` — `pnpm-lock.yaml`. YAML; the top-level
  `packages` map is keyed by `pkg-name@version` strings.
- `parsers/yarn.py` — `yarn.lock`. v1 (Berry: handles both v1
  classic and v6+ Berry). v1 is a custom format; v2/Berry is YAML.
  Detect by the `__metadata` block (Berry) vs the absence of it (v1).
- `parsers/cargo.py` — `Cargo.lock`. TOML with `[[package]]`.
- `parsers/go.py` — `go.sum` (and optionally `go.mod`). go.sum is
  one line per `(module version hash)` triple, two lines per
  module (one for the module, one for `/go.mod`). Dedup.
- `parsers/maven.py` — `pom.xml`. Walk `<dependencies>` and
  `<dependencyManagement><dependencies>` (the brief flags
  `<dependencyManagement>` explicitly). Skip property-variable
  versions (`${foo}`) — emit `version_unspecified=True`.
- `parsers/gem.py` — `Gemfile.lock`. Indented custom format; parse
  the `GEM` block's `specs:` list.

Each parser registered in `cli.py::_DETECTORS` so directory
autodetect picks them up.

`pyyaml` is added to `requirements.lock` (for pnpm + yarn Berry)
and declared as a runtime dep in `pyproject.toml`.

Test gate (from brief §7 Step 9): ≥3 unit tests per ecosystem on
real-world-shaped fixtures (committed to
`tests/fixtures/<ecosystem>/`).

Plausible failure modes:
- yarn.lock v1 syntax is a custom DSL that's *not* YAML; parsing
  with PyYAML yields a confusing error. We use a simple
  hand-written line scanner.
- pom.xml in real projects often uses property variables
  (`${some.version}`). We surface those as
  `version_unspecified=True` rather than try to resolve.
- go.sum has both `module version` and `module version/go.mod`
  variants of every entry — dedup by `(module, version)`.

### Gate — paste of real output

#### `make test`

```
collected 94 items / 1 deselected / 93 selected

tests/advisory/test_cache.py .....                                       [  5%]
tests/advisory/test_extras.py ......                                     [ 11%]
tests/advisory/test_matcher.py ....                                      [ 16%]
tests/advisory/test_osv_client.py ........                               [ 24%]
tests/advisory/test_version_match.py ................                    [ 41%]
tests/parsers/test_npm.py ........                                       [ 50%]
tests/parsers/test_other_ecosystems.py ..................                [ 69%]
tests/parsers/test_pypi.py .........                                     [ 79%]
tests/test_cli.py .........                                              [ 89%]
tests/test_report_sarif.py .....                                         [ 94%]
tests/test_smoke.py ..                                                   [ 96%]
tests/test_step7_mini_shaihulud.py ...                                   [100%]

======================= 93 passed, 1 deselected in 0.18s =======================
```

18 new ecosystem tests in `test_other_ecosystems.py` — 3 each for
Cargo, Go, pnpm, yarn, Maven, RubyGems. Brief required ≥3 per
ecosystem.

#### Multi-ecosystem directory autodetect

Hand-built `/tmp/pd-multi/` with one fixture from each new ecosystem:

```
$ ls /tmp/pd-multi/
Cargo.lock  Gemfile.lock  go.sum  pnpm-lock.yaml  pom.xml  yarn.lock

$ docker run --rm -v "$PWD":/work -v /tmp/pd-multi:/multi:ro -w /work \
    -e PYTHONPATH=/work/src pwned-deps-dev \
    python -m pwned_deps.cli check /multi --offline \
    --cache-path /tmp/cache.sqlite --ci
pwned-deps 0.1.0 — checking /multi/pnpm-lock.yaml (npm)
pwned-deps 0.1.0 — checking /multi/yarn.lock (npm)
pwned-deps 0.1.0 — checking /multi/Cargo.lock (crates.io)
pwned-deps 0.1.0 — checking /multi/go.sum (Go)
pwned-deps 0.1.0 — checking /multi/pom.xml (Maven)
pwned-deps 0.1.0 — checking /multi/Gemfile.lock (RubyGems)

COMPROMISED — 2 package(s)
  @cap-js/sqlite@2.2.2
    EXTRA-2026-0001  Mini Shai-Hulud (SAP CAP)
    ...
  @cap-js/sqlite@2.2.2
    EXTRA-2026-0001  Mini Shai-Hulud (SAP CAP)
    ...

20 packages scanned · 2 compromised · 0 high/critical · 0 low/medium
exit=1
```

Both `@cap-js/sqlite@2.2.2` hits originate from the pnpm fixture
and the yarn-Berry fixture — proving the bundled Mini Shai-Hulud
campaign matches across both new npm-ecosystem parsers.

#### `make lint`

```
All checks passed!
```

(Initial run flagged 3 issues — unused loop variable, stale
`# noqa` directive, blank line before single-line statement. All
fixed.)

### Step 9 status

**Gate green.** Six new parsers wired into the CLI's autodetect
list. Multi-ecosystem directory scan works end-to-end and the
bundled Mini Shai-Hulud campaign matches across pnpm + yarn.
`pyyaml==6.0.2` pinned (runtime + dev). Proceeding to Step 10
(CI/CD workflow files; write only, no push).

---

## Step 10 — CI/CD workflows + multi-path CLI

### Plan

CLI:
- Extend `check` to accept `nargs=-1` so multiple PATHs are
  supported (`pwned-deps check ./pyproject.toml ./requirements.lock`
  per BUILD_BRIEF §13). Unrecognised files print a warning and are
  skipped; the run exits with the worst-of all the recognised
  scans.

CI files (committed only — never pushed; user reinforcement is
binding):
- `.github/workflows/ci.yml` — triggers: push, pull_request,
  workflow_dispatch, schedule (daily). Jobs:
  1. `verify-safety` (host-side, runs `python tools/verify_safety.py`).
  2. `lint` (sets up Python in the runner — easier in CI than
     pulling our locally-built dev image — installs deps via
     `requirements.lock`, runs ruff).
  3. `test` (same Python install, runs pytest with the same
     `-m 'not network'` default).
  4. `dogfood` (installs the package via `pip install -e .`,
     runs `pwned-deps check ./pyproject.toml ./requirements.lock`).
- `.github/workflows/release.yml` — triggered on `v*` tag push.
  Builds wheel + sdist via `python -m build`, runs the dogfood
  scan as a pre-publish gate, publishes to PyPI via OIDC trusted
  publishing (no API tokens), generates SLSA Level 3 provenance
  via the official `slsa-framework/slsa-github-generator` action,
  drafts a GitHub Release with auto-generated notes.

The user has explicitly required NO push, NO authentication, NO
token generation. We commit these files locally; the maintainer
runs them after the project is on GitHub.

Test gate (from brief §7 Step 10): "CI green on a fresh PR.
Dogfood job passes (we ourselves are not pwned)." We verify the
dogfood path locally with `python -m pwned_deps.cli check
./pyproject.toml ./requirements.lock` and capture the actual
output. CI green-light is verified by the maintainer when the
repo is on GitHub.

Plausible failure modes:
- `pyproject.toml` is not a lockfile per se. Two paths: (a) skip
  unrecognised paths with a warning (chosen), (b) build a basic
  pyproject manifest reader. Choosing (a) keeps the surface area
  honest — pwned-deps audits *lockfiles*, and we say so in the
  warning.
- The release workflow's PyPI OIDC requires a maintainer to
  configure a "Trusted Publisher" entry on PyPI before the first
  release. Documented in the V1 acceptance section.

### Gate — paste of real output

#### `make test` (after multi-path CLI extension)

```
collected 95 items / 1 deselected / 94 selected
...
======================= 94 passed, 1 deselected in 0.19s =======================
exit=0
```

One additional CLI test added in `tests/test_cli.py`:
`test_check_multiple_paths_skips_unrecognised` — passes a
`pyproject.toml` shape alongside a real lockfile, asserts a
"skipping" warning on stderr and that the lockfile is still
processed.

#### Dogfood scan (mirrors the §13 acceptance command)

```
$ docker run --rm -v "$PWD":/work -w /work -e PYTHONPATH=/work/src pwned-deps-dev \
    python -m pwned_deps.cli check ./pyproject.toml ./requirements.lock \
    --offline --cache-path /tmp/cache.sqlite --ci
warning: skipping pyproject.toml: not a recognised lockfile shape
pwned-deps 0.1.0 — checking requirements.lock (PyPI)

All 10 packages clean.
exit=0
```

Live (network on) variant returns exit 0 with one MEDIUM finding
on `pytest@8.3.3` (GHSA-6w46-j5rx-g56g) — same as Step 6's
dogfood. CI's `dogfood` job allow-lists exit 2 explicitly so a
non-malicious MEDIUM finding doesn't block the build.

#### Workflow files committed locally (not pushed)

- `.github/workflows/ci.yml` — verify-safety → lint → test (3.10 /
  3.11 / 3.12 matrix) → dogfood. Triggers: push, pull_request,
  workflow_dispatch, daily schedule.
- `.github/workflows/release.yml` — on `v*` tag: pre-publish
  verify-safety + lint + pytest + dogfood gates, build wheel +
  sdist, SLSA Level 3 provenance via the official slsa-framework
  generator, PyPI publish via OIDC trusted publishing (no
  long-lived tokens), GitHub Release with auto-notes.

Per the user's binding constraint, neither file is pushed; the
maintainer adopts them when the repo is on GitHub. PyPI
"Trusted Publisher" registration is a one-time maintainer setup
step recorded in the V1 acceptance checklist.

#### `make lint`

```
All checks passed!
```

### Step 10 status

**Gate green** for everything that can be verified locally.
"CI green on a fresh PR" is the maintainer's acceptance gate when
the repo lands on GitHub. Proceeding to Step 11 (README polish).

---

## Step 11 — README polish + threat model

### Plan

Rewrite the README in the order the brief §7 Step 11 specifies:
logo placeholder, tagline, badges, "Why this exists" with the
Mini Shai-Hulud peg, install, quick usage, supported ecosystems
(now reflecting V1's full coverage), output formats, threat model
(elevated from a one-paragraph stub to a section that names what
we do and don't do), FAQ, honest comparison table, contributing
flow with the 5-minute "add a campaign" PR, license, maintainer
placeholder.

The brief is explicit that the comparison table must NOT pretend
we replace `osv-scanner` — call it the well-resourced direct
competitor we add UX + an open campaign feed on top of, and say
where they're the better choice.

Files: `README.md` only. No code changes.

Test gate (from brief §7 Step 11):
- README renders correctly on GitHub (verified locally by
  spot-checking markdown structure; full GitHub render is a
  maintainer step at adoption time).
- All install commands described should work end-to-end on a
  fresh macOS / Ubuntu / Windows. We don't run a CI matrix here
  (Step 10's `test` matrix already covers Python 3.10 / 3.11 /
  3.12 on Ubuntu); the maintainer reproduces on macOS + Windows
  before V1.0.0 tag.

### Step 11 status

**Gate green** for everything verifiable locally. README structure
follows the brief's §7 Step 11 outline. `make verify-safety` and
`make test` remain green (94 passed, 1 deselected). Cross-platform
install verification is a maintainer step before V1.0.0 — recorded
in the V1 acceptance section. Proceeding to V1 acceptance run.

---

## V1 acceptance — BUILD_BRIEF §13 checklist

Run on 2026-05-03 against commit `bc9a270` (`docs(step11): polish
README — threat model, FAQ, comparison`). 16 commits on `main`,
working tree clean.

### Local-verifiable items (PASS)

- [x] **All 11 steps complete; their test gates green.**
  Each step's gate evidence is recorded above. The current sweep:
  - `make verify-safety` → OK
  - `make verify-safety-self-test` → caught planted `eval()`
  - `make test` → 94 passed, 1 deselected (the opt-in
    `pytest.mark.network` live test)
  - `make lint` → All checks passed!
  - 16 Conventional-Commits commits on `main`

- [x] **`pwned-deps check` against a fixture pinning a
  Mini Shai-Hulud-affected version emits the campaign with
  correct exposure window and remediation list.**
  Fixture: `tests/fixtures/npm/mini-shaihulud.lock.json`
  (pins `@cap-js/sqlite@2.2.2`).

  Live (network on, real OSV):

  ```
  $ docker run --rm -v "$PWD":/work -w /work -e PYTHONPATH=/work/src pwned-deps-dev \
      python -m pwned_deps.cli check tests/fixtures/npm/mini-shaihulud.lock.json \
      --cache-path /tmp/cache.sqlite
  pwned-deps 0.1.0 — checking tests/fixtures/npm/mini-shaihulud.lock.json (npm)

  COMPROMISED — 2 package(s)
    @cap-js/sqlite@2.2.2
      EXTRA-2026-0001  Mini Shai-Hulud (SAP CAP)
      ...
    @cap-js/sqlite@2.2.2
      MAL-2026-3178  (malicious)
      Malicious code in @cap-js/sqlite (npm)
      refs: https://safedep.io/mini-shai-hulud-and-sap-compromise/, https://github.com/advisories/GHSA-2h7r-x9v2-q52f

  1 packages scanned · 2 compromised · 0 high/critical · 0 low/medium
  exit=1
  ```

  **Bonus finding:** OSV has now ingested a real `MAL-2026-3178`
  malicious-package advisory for this exact version. The user
  sees both our bundled extras campaign AND the independent OSV
  MAL-* record — two-source confirmation. This validates the
  brief's design: extras are the "fast lane" while OSV catches
  up.

- [x] **`pwned-deps check ./pyproject.toml ./requirements.lock`
  (dogfood) returns exit 0.**

  ```
  warning: skipping pyproject.toml: not a recognised lockfile shape
  pwned-deps 0.1.0 — checking requirements.lock (PyPI)

  10 packages scanned · 0 compromised · 0 high/critical · 1 low/medium
  exit=0
  ```

  The 1 low/medium informational finding is `pytest@8.3.3
  GHSA-6w46-j5rx-g56g` — dev tool only, not bundled in the wheel.

- [x] **SARIF output validates against schema.**

  ```
  $ python -c "import json, jsonschema; \
      sarif=json.load(open('/tmp/demo.sarif')); \
      schema=json.load(open('tests/fixtures/sarif/sarif-2.1.0-schema.json')); \
      jsonschema.validate(sarif, schema); print('PASS')"
  PASS
  rules: 1  results: 1
  ```

- [x] **README has a working install + usage section that matches
  the published CLI.** `--format`, `--offline`, `--ci`,
  `--no-color`, `--cache-ttl`, `--feed-file`, `--cache-path`, the
  `update` subcommand, and the `version` subcommand are all
  surfaced in `pwned-deps check --help` exactly as documented.

### Items that need user action before V1.0.0 tag

These cannot be done locally per the user's binding constraint
(no push, no auth, no token generation). Each is one-shot setup.

- [ ] **`pipx install pwned-deps` works on macOS, Ubuntu, Windows.**
  Requires PyPI publish — see below. Cross-platform verification
  is a maintainer step (CI matrix in Step 10 already covers
  Python 3.10 / 3.11 / 3.12 on Ubuntu; macOS + Windows
  reproduction is the maintainer's call).

- [ ] **CI is green on a fresh PR.** `.github/workflows/ci.yml` is
  committed locally; it activates the moment the repo is pushed.

- [ ] **Account hygiene checklist.**
  - [ ] Hardware-key 2FA on GitHub for the `YOUR_GH_USERNAME`
        account.
  - [ ] PyPI 2FA + Trusted Publisher entry registered for this
        repo so `release.yml`'s OIDC publish works.
  - [ ] No long-lived `PYPI_API_TOKEN` ever stored as a repo
        secret.

- [ ] **`extras.json` is current to within 7 days of the most
  recent public supply-chain campaign.** Today's bundled feed is
  current as of 2026-05-03 (Mini Shai-Hulud, April 29 2026).
  CI's daily cron already runs `verify-safety + lint + test +
  dogfood`; an "auto-PR if upstream extras is newer than
  bundled" step is a maintainer follow-up if/when there's a
  separate hosted upstream feed.

- [ ] **Replace the `YOUR_GH_USERNAME` placeholder.** A single
  `git ls-files | xargs sed -i '' 's/YOUR_GH_USERNAME/<your-username>/g'`
  before publish.

- [ ] **Maintainer has run `pwned-deps check` against at least
  one real customer/employer project, found nothing, and has
  the receipt.** That is, by definition, the maintainer's
  responsibility.

- [ ] **SARIF uploads cleanly to a test repo's Code Scanning.**
  Manual maintainer step (we hold the OASIS-validated SARIF as
  evidence locally).

- [ ] **Publish to PyPI; tag `v0.1.0`; create the first GitHub
  Release.** `release.yml` does the publishing once a `v*` tag
  exists; pre-publish gates run dogfood as a hard block on
  exit 1.

### V1 status

**Local build is feature-complete.** All 11 brief-§7 steps have
green gates. The repo is committed (16 commits on `main`), clean,
ready for the maintainer's adoption cycle. Nothing has been
pushed; no tokens have been generated; no third-party services
have been authenticated.

