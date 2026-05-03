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

