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

