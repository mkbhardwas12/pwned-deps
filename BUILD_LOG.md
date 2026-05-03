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

