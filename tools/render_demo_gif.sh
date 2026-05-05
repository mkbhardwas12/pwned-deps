#!/usr/bin/env bash
#
# Render docs/demo.gif from demo.tape using the official Charmbracelet
# vhs Docker image plus a thin pwned-deps install layer. No host
# installs required (Docker / OrbStack is the only prerequisite).
#
# Usage: bash tools/render_demo_gif.sh
#        — or —
#        make demo-gif
#
# What it does:
#   1. Builds a tiny image that extends ghcr.io/charmbracelet/vhs with
#      python3 + pip + a local install of pwned-deps from this checkout.
#   2. Runs `vhs demo.tape` inside that image, writing docs/demo.gif on
#      the host via a bind-mount.
#
# Output:  docs/demo.gif  (Catppuccin Mocha theme, 1100x680, ~5s).
#
# If you'd rather not use Docker:
#   brew install vhs
#   vhs demo.tape
#
# (vhs needs ttyd + ffmpeg under the hood; the brew formula installs
# those.)

set -euo pipefail

cd "$(dirname "$0")/.."

VHS_IMAGE="${VHS_IMAGE:-ghcr.io/charmbracelet/vhs:v0.10.0}"
DEMO_IMAGE="pwned-deps-demo"

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker not found. Install OrbStack/Docker, or run vhs directly:" >&2
  echo "  brew install vhs && vhs demo.tape" >&2
  exit 1
fi

if [ ! -f demo.tape ]; then
  echo "ERROR: demo.tape not found in $(pwd)" >&2
  exit 1
fi

# Build a wheel of the current checkout into a host scratch dir. The
# demo image installs from that wheel rather than `pip install -e`,
# because the project's `.dockerignore` deliberately excludes LICENSE
# from the dev-image build context (the dev image doesn't need it),
# and pyproject's `license = { file = "LICENSE" }` makes editable
# installs fail without it.
WHEEL_DIR="$(mktemp -d)"
trap 'rm -rf "$WHEEL_DIR"' EXIT

echo "[demo-gif] building pwned-deps wheel for the demo image..."
docker run --rm \
  -v "$PWD":/work \
  -v "$WHEEL_DIR":/out \
  -w /work \
  pwned-deps-dev \
  /bin/bash -c '
    export PATH=/home/appuser/.local/bin:$PATH
    pip install --quiet --user build==1.2.2.post1
    python -m build --wheel --outdir /out . >/dev/null
    ls /out
  ' >/dev/null

WHEEL_NAME="$(ls "$WHEEL_DIR"/*.whl | head -1 | xargs -n1 basename)"
if [ -z "$WHEEL_NAME" ]; then
  echo "ERROR: no wheel produced." >&2
  exit 1
fi
echo "[demo-gif] wheel: $WHEEL_NAME"

# Build the demo image. The wheel built above is bind-mounted into
# the docker build context via a wheel-only directory.
echo "[demo-gif] building demo image (vhs + python3 + pwned-deps wheel)..."
docker build \
  --quiet \
  --build-arg VHS_IMAGE="$VHS_IMAGE" \
  --build-arg WHEEL_NAME="$WHEEL_NAME" \
  --tag "$DEMO_IMAGE" \
  --file - "$WHEEL_DIR" <<'DOCKERFILE' >/dev/null
ARG VHS_IMAGE
FROM ${VHS_IMAGE}
ARG WHEEL_NAME

# vhs's official image is Debian-based as of v0.7+; install python3 +
# pip. The AllowReleaseInfo=Suite,Codename flags handle the case
# where the Debian "stable" alias has rolled to a newer release since
# the upstream vhs image was built (the apt sources file still says
# "stable" but resolves to the new codename).
RUN apt-get update -qq \
      -o "Acquire::AllowReleaseInfoChange::Suite=true" \
      -o "Acquire::AllowReleaseInfoChange::Codename=true" \
 && apt-get install -qq -y --no-install-recommends \
      python3 python3-pip python3-venv zsh \
 && rm -rf /var/lib/apt/lists/*

# Install pwned-deps from the prebuilt wheel into a venv, expose the
# CLI on PATH at /usr/local/bin/pwned-deps.
COPY ${WHEEL_NAME} /tmp/${WHEEL_NAME}
RUN python3 -m venv /opt/pwd-venv \
 && /opt/pwd-venv/bin/pip install --quiet --no-cache-dir /tmp/${WHEEL_NAME} \
 && ln -sf /opt/pwd-venv/bin/pwned-deps /usr/local/bin/pwned-deps \
 && pwned-deps version
DOCKERFILE

mkdir -p docs

# vhs needs to write the gif inside the container; the bind-mounts
# carry the demo.tape script + the project tree (so the bundled
# fixture lockfiles are addressable) into /work, and the resulting
# docs/demo.gif lands back on the host.
echo "[demo-gif] running vhs (this records a real terminal session,
 may take ~30 seconds)..."
docker run --rm \
  -v "$PWD":/work \
  -w /work \
  -e HOME=/tmp \
  --entrypoint vhs \
  "$DEMO_IMAGE" \
  /work/demo.tape

if [ -f docs/demo.gif ]; then
  echo ""
  echo "wrote docs/demo.gif ($(stat -f '%z' docs/demo.gif 2>/dev/null || stat -c '%s' docs/demo.gif) bytes)"
  echo "embed in README.md as: ![pwned-deps demo](docs/demo.gif)"
else
  echo "ERROR: docs/demo.gif was not produced. Check vhs output above." >&2
  exit 1
fi
