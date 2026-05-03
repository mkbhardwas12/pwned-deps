"""``pwned-deps`` command-line interface (click-based).

Subcommands:

* ``check [PATH]`` — scan one lockfile, or all known lockfiles under
  the given directory.
* ``update`` — refresh the local cache (re-queries every previously
  cached entry).
* ``version`` — print ``pwned_deps.__version__``.

Exit codes (BUILD_BRIEF §3):

* 0 — clean
* 1 — at least one MAL-* / EXTRA-* (malicious) hit
* 2 — at least one HIGH/CRITICAL CVE hit (no malicious hits)
* 3 — parse error in any scanned lockfile
"""

from __future__ import annotations

from pathlib import Path

import click

import pwned_deps
from pwned_deps.advisory.cache import Cache, default_cache_path
from pwned_deps.advisory.extras import ExtrasFeed
from pwned_deps.advisory.matcher import Matcher
from pwned_deps.advisory.osv_client import OsvClient
from pwned_deps.parsers import npm as npm_parser
from pwned_deps.parsers import pypi as pypi_parser
from pwned_deps.parsers.base import Lockfile, ParseError
from pwned_deps.report.json_out import render_json
from pwned_deps.report.sarif import render_sarif
from pwned_deps.report.text import ScanReport, render_text

# Map known lockfile filenames to their parser entry-point.
_DETECTORS: list[tuple[str, object]] = [
    ("package-lock.json", npm_parser.parse),
    ("npm-shrinkwrap.json", npm_parser.parse),
    ("requirements.txt", pypi_parser.parse),
    ("requirements.lock", pypi_parser.parse),
    ("Pipfile.lock", pypi_parser.parse),
    ("poetry.lock", pypi_parser.parse),
    ("uv.lock", pypi_parser.parse),
]


@click.group()
@click.version_option(pwned_deps.__version__, package_name="pwned-deps")
def main() -> None:
    """Drop your lockfile in, find out if you're pwned."""


@main.command()
@click.argument(
    "path",
    type=click.Path(exists=True, path_type=Path),
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json", "sarif"], case_sensitive=False),
    default="text",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--offline",
    is_flag=True,
    default=False,
    help="Skip network. Use cached database only.",
)
@click.option(
    "--ci",
    is_flag=True,
    default=False,
    help="Suppress color/decorations; deterministic exit codes per BUILD_BRIEF §3.",
)
@click.option(
    "--no-color",
    is_flag=True,
    default=False,
    help="Disable color even outside --ci mode.",
)
@click.option(
    "--cache-ttl",
    type=int,
    default=24,
    show_default=True,
    help="Cache TTL in hours.",
)
@click.option(
    "--feed-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional extra campaign feed (JSON file).",
)
@click.option(
    "--cache-path",
    type=click.Path(path_type=Path),
    default=None,
    help="Override the SQLite cache path. Defaults to ~/.cache/pwned-deps/osv.sqlite.",
)
@click.pass_context
def check(
    ctx: click.Context,
    path: Path,
    fmt: str,
    offline: bool,
    ci: bool,
    no_color: bool,
    cache_ttl: int,
    feed_file: Path | None,
    cache_path: Path | None,
) -> None:
    """Scan PATH (a lockfile or a directory) for compromised packages."""

    targets = _discover_targets(path)
    if not targets:
        click.echo("no recognised lockfiles found", err=True)
        ctx.exit(0)

    reports: list[ScanReport] = []
    parser_failures: list[str] = []
    for target_path, parse in targets:
        try:
            lockfile = parse(target_path)
        except ParseError as exc:
            reports.append(
                ScanReport(
                    lockfile=_empty_lockfile(target_path),
                    findings=[],
                    parse_error=str(exc),
                )
            )
            parser_failures.append(str(exc))
            continue
        except Exception as exc:  # last-resort guard; message captured below
            reports.append(
                ScanReport(
                    lockfile=_empty_lockfile(target_path),
                    findings=[],
                    parse_error=f"{target_path}: unexpected parser error ({exc})",
                )
            )
            parser_failures.append(str(exc))
            continue
        reports.append(ScanReport(lockfile=lockfile, findings=[]))

    extras = _load_extras(feed_file)
    cache = _open_cache(cache_path, cache_ttl)
    try:
        with OsvClient(cache=cache, offline=offline) as osv:
            matcher = Matcher(osv_client=osv, extras=extras)
            for report in reports:
                if report.parse_error:
                    continue
                report.findings = matcher.match(report.lockfile)
    finally:
        if cache is not None:
            cache.close()

    if fmt == "json":
        rendered, exit_code = render_json(reports, version=pwned_deps.__version__)
        click.echo(rendered)
    elif fmt == "sarif":
        rendered, exit_code = render_sarif(reports, version=pwned_deps.__version__)
        click.echo(rendered)
    else:
        exit_code = render_text(
            reports,
            version=pwned_deps.__version__,
            ci=ci,
            no_color=no_color,
        )

    ctx.exit(exit_code)


@main.command()
@click.option(
    "--cache-path",
    type=click.Path(path_type=Path),
    default=None,
    help="Override the SQLite cache path.",
)
def update(cache_path: Path | None) -> None:
    """Refresh the local advisory cache.

    The current implementation just touches the cache file (creates the
    schema if missing). A more aggressive refresh — re-querying every
    cached `(eco, pkg, ver)` — is a Step 10 follow-up.
    """

    target = cache_path or default_cache_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    Cache(target).close()
    click.echo(f"cache initialised at {target}")


@main.command(name="version")
def version_cmd() -> None:
    """Print the pwned-deps version."""

    click.echo(pwned_deps.__version__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _discover_targets(path: Path) -> list[tuple[Path, object]]:
    """Return list of ``(lockfile_path, parser_callable)`` to scan."""

    if path.is_file():
        for filename, parser in _DETECTORS:
            if path.name == filename:
                return [(path, parser)]
        # Fall back to extension-based detection: a `*.txt` is treated
        # as a requirements file; `*-lock.json` is npm.
        if path.suffix == ".txt":
            return [(path, pypi_parser.parse)]
        if path.suffix == ".json" and "lock" in path.name.lower():
            return [(path, npm_parser.parse)]
        return [(path, pypi_parser.parse)]  # last-resort; will raise ParseError if wrong

    if not path.is_dir():
        return []

    found: list[tuple[Path, object]] = []
    for filename, parser in _DETECTORS:
        candidate = path / filename
        if candidate.is_file():
            found.append((candidate, parser))
    return found


def _empty_lockfile(path: Path) -> Lockfile:
    from pwned_deps.parsers.base import Ecosystem

    return Lockfile(path=path, ecosystem=Ecosystem.NPM, packages=())


def _load_extras(feed_file: Path | None) -> ExtrasFeed:
    user_paths: list[Path] = []
    if feed_file is not None:
        user_paths.append(feed_file)
    return ExtrasFeed.from_bundled(user_paths=user_paths)


def _open_cache(cache_path: Path | None, ttl_hours: int) -> Cache | None:
    target = cache_path or default_cache_path()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        return Cache(target, ttl_seconds=ttl_hours * 3600)
    except OSError:
        # Read-only home (e.g. some CI sandboxes). Run without cache.
        return None


if __name__ == "__main__":  # pragma: no cover
    main()
