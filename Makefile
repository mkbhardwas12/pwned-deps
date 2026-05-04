# pwned-deps — developer Makefile
#
# Hard rule: the host runs `make` only — never `pytest` or the scanner
# directly. All build/test/lint happens inside the locked-down dev
# container. The brief's safety contract §2 binds this.
#
# Targets:
#   make build                Build the dev image (tag: pwned-deps-dev)
#   make shell                Interactive shell in dev container (rw, network on)
#   make test                 Run pytest in locked-down container (no net, ro fs)
#   make verify-safety        Grep src/ + tests/ for forbidden symbols (host-side)
#   make verify-safety-self-test  Prove the regex catches a planted eval()
#   make lint                 Ruff lint inside container (locked-down)
#   make release-rehearsal    Run the exact pre-publish gate chain release.yml runs
#   make pin-base             Capture current python:3.12-slim digest into base-image.lock
#   make pin-deps             Regenerate requirements.lock from requirements.in with hashes
#   make clean                Remove the dev image
#
# Locked-down container flags applied to test/lint targets:
#   --rm                      no state survives
#   --network none            no outbound network during the run
#   --read-only               rootfs read-only
#   --tmpfs /tmp              scratch space for any tooling that insists
#   --tmpfs /home/appuser/.cache  pip/pytest scratch (read-only home else)
#   -v $(PWD):/work:ro        source mounted read-only
#   -w /work                  work in the project root
#
# `make shell` deliberately allows network + writable mount — for
# regenerating `requirements.lock --generate-hashes` and exploratory
# debugging. Production-equivalent runs use the locked flags above.

IMAGE := pwned-deps-dev
PWD := $(shell pwd)

# Forbidden-symbol enforcement is delegated to tools/verify_safety.py.
# Why a Python script instead of plain `grep -E`? The brief's regex
# uses a negative lookbehind (`(?<!re\.)`) so that bare `compile(` is
# caught while `re.compile(...)` is allowed. POSIX ERE does not support
# lookbehinds; on macOS, BSD grep errors out (exit 2) which a Makefile
# `if` treats as "no matches found" and silently passes. Python's `re`
# honors the regex literally on every platform.
#
# The regex itself lives in tools/verify_safety.py and is verbatim from
# BUILD_BRIEF §7 Step 1.

# Container run flags for test/lint (locked down).
RUN_FLAGS_LOCKED := --rm --network none --read-only \
                    --tmpfs /tmp --tmpfs /home/appuser/.cache \
                    -v $(PWD):/work:ro \
                    -w /work

# Container run flags for interactive shell (writable, network for
# regenerating the lockfile and adding deps).
RUN_FLAGS_DEV := --rm -it -v $(PWD):/work -w /work

.PHONY: help build shell test verify-safety verify-safety-self-test lint release-rehearsal pin-base pin-deps clean

help:
	@echo "pwned-deps Makefile targets:"
	@grep -E '^#   make' Makefile | sed 's/^#   /  /'

build:
	docker build -f Dockerfile.dev -t $(IMAGE) .

shell:
	docker run $(RUN_FLAGS_DEV) $(IMAGE)

test: verify-safety
	docker run $(RUN_FLAGS_LOCKED) -e PYTHONPATH=/work/src $(IMAGE) \
		python -m pytest -ra -o cache_dir=/tmp/.pytest_cache

# Pure host-side check — no docker daemon required. Returns nonzero if
# any forbidden symbol is found in src/ or tests/.
verify-safety:
	@python3 tools/verify_safety.py src tests

# Negative test: prove the regex actually catches an `eval(` planted in
# tests/. Self-cleans on success or failure.
verify-safety-self-test:
	@echo "[self-test] planting eval() in tests/_safety_self_test_PLANTED.py..."
	@printf 'eval("1+1")\n' > tests/_safety_self_test_PLANTED.py
	@RC=0; $(MAKE) verify-safety > /tmp/pwned-deps-self-test.out 2>&1 || RC=$$?; \
		rm -f tests/_safety_self_test_PLANTED.py; \
		if [ $$RC -eq 0 ]; then \
			echo "FAIL: verify-safety did not catch the planted eval()."; \
			cat /tmp/pwned-deps-self-test.out; \
			exit 1; \
		else \
			echo "[self-test] OK — verify-safety caught the planted eval() (exit $$RC)."; \
		fi

lint:
	docker run $(RUN_FLAGS_LOCKED) -e RUFF_CACHE_DIR=/tmp/.ruff_cache $(IMAGE) \
		ruff check src/ tests/

# Mirror of .github/workflows/release.yml `build` job. Run this before
# `git tag v*` — if it goes red here, the tag push will go red in CI.
# Steps: safety self-test (host) → lint (locked) → test (locked) →
# build wheel+sdist (host venv) → install wheel into a FRESH venv →
# dogfood scan our own pyproject.toml + requirements.lock.
# Exit-1 from the dogfood scan blocks the rehearsal (matches release.yml).
release-rehearsal: verify-safety verify-safety-self-test lint test
	@echo "[rehearsal] building wheel + sdist..."
	@rm -rf dist build *.egg-info
	@python3 -m venv .rehearsal-venv
	@. .rehearsal-venv/bin/activate && \
		pip install --quiet --upgrade pip build && \
		python -m build >/dev/null && \
		echo "[rehearsal] wheel: $$(ls dist/*.whl)"
	@echo "[rehearsal] installing wheel into clean venv + dogfooding..."
	@python3 -m venv .rehearsal-install-venv
	@. .rehearsal-install-venv/bin/activate && \
		pip install --quiet dist/*.whl && \
		set +e; pwned-deps check ./pyproject.toml ./requirements.lock --ci; rc=$$?; set -e; \
		rm -rf ../.rehearsal-install-venv 2>/dev/null || true; \
		if [ $$rc -eq 1 ]; then \
			echo "[rehearsal] FAIL: dogfood found a malicious package in our own deps (exit 1)"; \
			exit 1; \
		fi; \
		echo "[rehearsal] dogfood exit $$rc (0=clean, 2=informational HIGH/CRITICAL)"
	@rm -rf .rehearsal-venv .rehearsal-install-venv
	@echo "[rehearsal] OK — safe to 'git tag v0.1.0 && git push origin v0.1.0'."

pin-base:
	@echo "Capturing current python:3.12-slim digest..."
	@docker pull python:3.12-slim
	@docker inspect --format='{{index .RepoDigests 0}}' python:3.12-slim | tee base-image.lock
	@echo ""
	@echo "Now update the FROM line in Dockerfile.dev to:"
	@echo "  FROM $$(cat base-image.lock)"
	@echo "and rerun 'make build'."

pin-deps:
	@echo "Regenerating requirements.lock from requirements.in (with hashes)..."
	docker run --rm -v $(PWD):/work -w /work $(IMAGE) /bin/bash -c '\
		export PATH=/home/appuser/.local/bin:$$PATH && \
		pip install --quiet --user pip-tools==7.4.1 && \
		pip-compile --generate-hashes --quiet \
			--output-file=/tmp/requirements.lock requirements.in && \
		cp /tmp/requirements.lock /work/requirements.lock'
	@echo "Wrote $$(wc -l < requirements.lock) lines to requirements.lock"
	@echo "Now: rerun 'make build' to verify the hashes install cleanly."

clean:
	-docker image rm $(IMAGE) 2>/dev/null || true
