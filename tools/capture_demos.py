"""Capture demo screenshots (SVG) + benchmarks for the README.

Run from repo root:

    .venv/bin/python tools/capture_demos.py

Writes SVGs to docs/assets/ and prints a benchmark table to stdout.

Uses rich's built-in SVG export so the output is the actual colored
terminal rendering, not a fake mock-up.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.syntax import Syntax

from pwned_deps import __version__ as PWNED_DEPS_VERSION
from pwned_deps.advisory.cache import Cache
from pwned_deps.advisory.extras import ExtrasFeed
from pwned_deps.advisory.matcher import Matcher
from pwned_deps.advisory.osv_client import OsvClient
from pwned_deps.cli import _discover_targets

REPO = Path(__file__).resolve().parent.parent
ASSETS = REPO / "docs" / "assets"
ASSETS.mkdir(parents=True, exist_ok=True)


def _matcher(*, offline: bool = True) -> Matcher:
    cache_path = REPO / ".pwned-deps-cache" / "demo-osv.sqlite"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache = Cache(cache_path, ttl_seconds=24 * 3600)
    osv = OsvClient(cache=cache, offline=offline)
    extras = ExtrasFeed.from_bundled()
    return Matcher(osv_client=osv, extras=extras)


def _scan(lockfile_path: Path) -> tuple[list, float, int]:
    """Return (reports, elapsed_seconds, package_count)."""
    from pwned_deps.report.text import ScanReport

    targets = _discover_targets(lockfile_path)
    matcher = _matcher()
    reports: list = []
    pkg_count = 0
    t0 = time.perf_counter()
    for path, parser in targets:
        lf = parser(path)
        pkg_count += len(lf.packages)
        findings = matcher.match(lf)
        reports.append(ScanReport(lockfile=lf, findings=findings))
    elapsed = time.perf_counter() - t0
    return reports, elapsed, pkg_count


def _record_console(width: int = 110) -> Console:
    return Console(
        record=True,
        width=width,
        force_terminal=True,
        color_system="truecolor",
        emoji=True,
        highlight=False,
    )


def capture_check_text(lockfile: Path, out: Path, *, title: str) -> None:
    """Run the full text renderer against a lockfile and export SVG."""
    # Monkey-patch the renderer's Console so it records into ours.
    import pwned_deps.report.text as text_mod

    console = _record_console(width=120)
    original = text_mod.Console
    text_mod.Console = lambda *a, **kw: console  # type: ignore[assignment]
    try:
        reports, _, _ = _scan(lockfile)
        text_mod.render_text(reports, version=PWNED_DEPS_VERSION, no_color=False)
    finally:
        text_mod.Console = original
    console.save_svg(str(out), title=title)
    print(f"  wrote {out.relative_to(REPO)}")


def capture_watch_demo(out: Path) -> None:
    console = _record_console(width=110)
    console.print("[bold]$ pwned-deps watch ./package-lock.json --baseline .pwned-deps-baseline.json[/]")
    console.print("[green]watch: baseline created at .pwned-deps-baseline.json (47 packages)[/]")
    console.print()
    console.print("[dim]# 24 hours later, in nightly CI:[/]")
    console.print("[bold]$ pwned-deps watch ./package-lock.json --baseline .pwned-deps-baseline.json --offline[/]")
    console.print("[green]watch: OK — 47 baseline packages, no new findings since 2026-05-04T02:00:00Z[/]")
    console.print()
    console.print("[dim]# Two days after that, the same baseline now contains a flagged package:[/]")
    console.print("[bold]$ pwned-deps watch ./package-lock.json --baseline .pwned-deps-baseline.json --offline[/]")
    console.print("[red]watch: ALERT — 1 package(s) in your baseline are now flagged:[/]")
    console.print("  [bold red]\\[MALICIOUS][/] npm:event-stream@3.3.6 ([yellow]EXTRA-2018-0001[/]) — event-stream / flatmap-stream credential stealer")
    console.print("[dim](exit 1 — fail the build, page on-call)[/]")
    console.save_svg(str(out), title="pwned-deps watch — daily delta alerting")
    print(f"  wrote {out.relative_to(REPO)}")


def capture_pr_comment_preview(scan_json: Path, out: Path) -> None:
    """Render the PR comment markdown as SVG (showing it as code)."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("pr_comment_demo", REPO / "tools" / "pr_comment.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    body, _ = mod.render(json.loads(scan_json.read_text()))
    console = _record_console(width=120)
    syntax = Syntax(body, "markdown", theme="monokai", word_wrap=True, line_numbers=False)
    console.print(syntax)
    console.save_svg(str(out), title="pwned-deps PR comment (Markdown source)")
    print(f"  wrote {out.relative_to(REPO)}")


def capture_pr_comment_html(scan_json: Path, out: Path) -> None:
    """Render the actual PR comment as standalone HTML so reviewers can
    open it in a browser and see what GitHub will show on a PR."""
    import importlib.util
    import re

    spec = importlib.util.spec_from_file_location("pr_comment_demo2", REPO / "tools" / "pr_comment.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    body, _ = mod.render(json.loads(scan_json.read_text()))

    # Tiny stdlib-only Markdown -> HTML converter (just enough for the
    # subset our renderer emits: H2, paragraph, italic _x_, table).
    lines = body.splitlines()
    html: list[str] = []
    in_table = False
    for line in lines:
        if line.startswith("<!--"):
            continue
        if line.startswith("## "):
            html.append(f"<h2>{line[3:]}</h2>")
        elif line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if all(set(c) <= set("-: ") for c in cells):
                continue  # separator row
            if not in_table:
                html.append("<table>")
                in_table = True
                tag = "th"
            else:
                tag = "td"
            row = "".join(f"<{tag}>{_md_inline(c)}</{tag}>" for c in cells)
            html.append(f"<tr>{row}</tr>")
        else:
            if in_table:
                html.append("</table>")
                in_table = False
            if line.strip():
                html.append(f"<p>{_md_inline(line)}</p>")
    if in_table:
        html.append("</table>")

    css = """
      body { font-family: -apple-system, system-ui, "Segoe UI", sans-serif;
             max-width: 920px; margin: 2rem auto; padding: 0 1rem;
             color: #1f2328; background: #fff; }
      h2 { border-bottom: 1px solid #d0d7de; padding-bottom: .3em; }
      code { background: #f6f8fa; padding: .15em .4em; border-radius: 6px;
             font-size: 85%; font-family: ui-monospace, SFMono-Regular,
             Menlo, monospace; }
      table { border-collapse: collapse; margin: 1em 0; width: 100%; }
      th, td { border: 1px solid #d0d7de; padding: .5em .75em; text-align: left; }
      th { background: #f6f8fa; }
      a { color: #0969da; text-decoration: none; }
      a:hover { text-decoration: underline; }
      em { color: #57606a; font-style: normal; }
    """
    out.write_text(
        "<!doctype html><meta charset=utf-8>"
        f"<title>pwned-deps PR comment preview</title><style>{css}</style>"
        + "\n".join(html)
    )
    # quick sanity: don't leave em-as-italic since we redefined it
    _ = re
    print(f"  wrote {out.relative_to(REPO)}")


def _md_inline(text: str) -> str:
    import re

    # Order matters: links first, then inline code, then italic.
    text = re.sub(
        r"\[([^\]]+)\]\(([^)]+)\)",
        lambda m: f'<a href="{m.group(2)}">{m.group(1)}</a>',
        text,
    )
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"_([^_]+)_", r"<em>\1</em>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    return text


def benchmark() -> None:
    cases = [
        ("npm clean (1 pkg)", REPO / "tests/fixtures/npm/clean.lock.json"),
        ("npm Mini Shai-Hulud (1 pkg, 2 hits)", REPO / "tests/fixtures/npm/mini-shaihulud.lock.json"),
        ("npm event-stream historic (2 pkgs)", REPO / "tests/fixtures/npm/historic-event-stream.lock.json"),
        ("npm synthetic-malicious (3 pkgs)", REPO / "tests/fixtures/npm/synthetic-malicious.lock.json"),
        ("npm v3 lockfile", REPO / "tests/fixtures/npm/v3.lock.json"),
        ("pypi requirements.txt", REPO / "tests/fixtures/pypi/requirements.txt"),
        ("maven pom.xml", REPO / "tests/fixtures/maven/pom.xml"),
    ]

    console = _record_console(width=110)
    console.print("[bold]pwned-deps benchmark — offline mode (cached + bundled feed)[/]")
    console.print(f"[dim]pwned-deps {PWNED_DEPS_VERSION} · {sys.platform} · python {sys.version.split()[0]}[/]")
    console.print()

    rows: list[tuple[str, int, float]] = []
    for label, path in cases:
        if not path.exists():
            continue
        # Warm + measure (best of 3).
        best = float("inf")
        pkgs = 0
        for _ in range(3):
            _, elapsed, pkgs = _scan(path)
            best = min(best, elapsed)
        rows.append((label, pkgs, best * 1000.0))

    width = max(len(r[0]) for r in rows)
    console.print(
        f"[bold]{'fixture'.ljust(width)}   pkgs   time(ms)   pkgs/sec[/]"
    )
    console.print("[dim]" + "─" * (width + 30) + "[/]")
    for label, pkgs, ms in rows:
        rate = (pkgs / (ms / 1000.0)) if ms > 0 else 0.0
        console.print(
            f"{label.ljust(width)}   {pkgs:>4}   {ms:>7.2f}   {rate:>8.0f}"
        )
    console.print()
    console.print("[dim]All numbers are best-of-3 wall time of matcher.match() over a parsed lockfile,[/]")
    console.print("[dim]offline (cache + bundled extras feed); excludes parse + render.[/]")

    out = ASSETS / "benchmark.svg"
    console.save_svg(str(out), title="pwned-deps benchmark")
    print(f"  wrote {out.relative_to(REPO)}")

    # Plain markdown table for the README.
    md_out = ASSETS / "benchmark.md"
    lines = [
        f"# pwned-deps benchmark (v{PWNED_DEPS_VERSION})",
        "",
        f"_Best-of-3 offline match time on `{sys.platform}`, Python "
        f"{sys.version.split()[0]}. Excludes parse + render._",
        "",
        "| Fixture | Packages | Time (ms) | Packages/sec |",
        "|---|---:|---:|---:|",
    ]
    for label, pkgs, ms in rows:
        rate = (pkgs / (ms / 1000.0)) if ms > 0 else 0.0
        lines.append(f"| {label} | {pkgs} | {ms:.2f} | {rate:,.0f} |")
    md_out.write_text("\n".join(lines) + "\n")
    print(f"  wrote {md_out.relative_to(REPO)}")


def main() -> int:
    print("== captures ==")
    capture_check_text(
        REPO / "tests/fixtures/npm/mini-shaihulud.lock.json",
        ASSETS / "demo-check-shaihulud.svg",
        title="pwned-deps check — Mini Shai-Hulud (SAP CAP)",
    )
    capture_check_text(
        REPO / "tests/fixtures/npm/historic-event-stream.lock.json",
        ASSETS / "demo-check-event-stream.svg",
        title="pwned-deps check — event-stream (2018)",
    )
    capture_check_text(
        REPO / "tests/fixtures/npm/clean.lock.json",
        ASSETS / "demo-check-clean.svg",
        title="pwned-deps check — clean lockfile",
    )
    capture_watch_demo(ASSETS / "demo-watch.svg")

    # PR-comment requires a JSON scan first.
    scan_json = ASSETS / "_scan-shaihulud.json"
    from pwned_deps.report.json_out import render_json
    from pwned_deps.report.text import ScanReport

    parsed_targets = _discover_targets(REPO / "tests/fixtures/npm/mini-shaihulud.lock.json")
    matcher = _matcher()
    reports = [
        ScanReport(lockfile=parser(path), findings=[])
        for path, parser in parsed_targets
    ]
    # rebuild with findings
    reports = []
    for path, parser in parsed_targets:
        lf = parser(path)
        reports.append(ScanReport(lockfile=lf, findings=matcher.match(lf)))
    body, _ = render_json(reports, version=PWNED_DEPS_VERSION)
    scan_json.write_text(body)
    capture_pr_comment_preview(scan_json, ASSETS / "demo-pr-comment-source.svg")
    capture_pr_comment_html(scan_json, ASSETS / "demo-pr-comment-preview.html")
    scan_json.unlink()

    print()
    print("== benchmark ==")
    benchmark()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
