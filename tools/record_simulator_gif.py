#!/usr/bin/env python3
"""Record a GIF of the in-browser pwned-deps lockfile simulator.

Usage: python tools/record_simulator_gif.py [SAMPLE]

Defaults to the 'mixed' sample. Output goes to docs/assets/demo-simulator.gif.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

REPO = Path(__file__).resolve().parents[1]
SIMULATOR = REPO / "docs" / "simulator.html"
OUT_GIF = REPO / "docs" / "assets" / "demo-simulator.gif"

SAMPLE = sys.argv[1] if len(sys.argv) > 1 else "mixed"
VIEWPORT = {"width": 920, "height": 1100}
DURATION_MS = 9_000  # enough for the 4-package mixed scan + render


def main() -> None:
    if not shutil.which("ffmpeg"):
        sys.exit("ffmpeg not found on PATH; install with `brew install ffmpeg`.")

    with tempfile.TemporaryDirectory() as tmpdir:
        video_dir = Path(tmpdir)
        with sync_playwright() as p:
            browser = p.chromium.launch()
            ctx = browser.new_context(
                viewport=VIEWPORT,
                record_video_dir=str(video_dir),
                record_video_size=VIEWPORT,
            )
            page = ctx.new_page()
            url = SIMULATOR.as_uri() + f"?autorun={SAMPLE}"
            page.goto(url)
            page.wait_for_timeout(DURATION_MS)
            ctx.close()
            browser.close()

        webm = next(video_dir.glob("*.webm"))
        OUT_GIF.parent.mkdir(parents=True, exist_ok=True)
        # Two-pass palette for a small, sharp GIF.
        palette = video_dir / "palette.png"
        common = ["-y", "-loglevel", "error", "-i", str(webm)]
        subprocess.check_call(
            ["ffmpeg", *common,
             "-vf", "fps=8,scale=640:-1:flags=lanczos,palettegen=max_colors=64",
             str(palette)]
        )
        subprocess.check_call(
            ["ffmpeg", *common, "-i", str(palette),
             "-lavfi", "fps=8,scale=640:-1:flags=lanczos [x]; [x][1:v] paletteuse=dither=bayer:bayer_scale=5",
             str(OUT_GIF)]
        )
        size_kb = OUT_GIF.stat().st_size // 1024
        print(f"wrote {OUT_GIF.relative_to(REPO)} ({size_kb} KB)")


if __name__ == "__main__":
    main()
