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
from pwned_deps.audit.repo import (
    DEFAULT_MAX_FILE_BYTES,
    FileHit,
    audit_repo,
    collect_file_iocs,
)
from pwned_deps.parsers import cargo as cargo_parser
from pwned_deps.parsers import gem as gem_parser
from pwned_deps.parsers import go as go_parser
from pwned_deps.parsers import maven as maven_parser
from pwned_deps.parsers import npm as npm_parser
from pwned_deps.parsers import pnpm as pnpm_parser
from pwned_deps.parsers import pypi as pypi_parser
from pwned_deps.parsers import yarn as yarn_parser
from pwned_deps.parsers.base import Lockfile, ParseError
from pwned_deps.report.json_out import render_json
from pwned_deps.report.sarif import render_sarif
from pwned_deps.report.text import ScanReport, render_text
from pwned_deps.watch import Baseline
from pwned_deps.watch import diff as watch_diff

# Map known lockfile filenames to their parser entry-point.
_DETECTORS: list[tuple[str, object]] = [
    ("package-lock.json", npm_parser.parse),
    ("npm-shrinkwrap.json", npm_parser.parse),
    ("pnpm-lock.yaml", pnpm_parser.parse),
    ("yarn.lock", yarn_parser.parse),
    ("requirements.txt", pypi_parser.parse),
    ("requirements.lock", pypi_parser.parse),
    ("Pipfile.lock", pypi_parser.parse),
    ("poetry.lock", pypi_parser.parse),
    ("uv.lock", pypi_parser.parse),
    ("Cargo.lock", cargo_parser.parse),
    ("go.sum", go_parser.parse),
    ("pom.xml", maven_parser.parse),
    ("Gemfile.lock", gem_parser.parse),
]


@click.group()
@click.version_option(pwned_deps.__version__, package_name="pwned-deps")
def main() -> None:
    """Drop your lockfile in, find out if you're pwned."""


@main.command()
@click.argument(
    "paths",
    nargs=-1,
    required=True,
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
    paths: tuple[Path, ...],
    fmt: str,
    offline: bool,
    ci: bool,
    no_color: bool,
    cache_ttl: int,
    feed_file: Path | None,
    cache_path: Path | None,
) -> None:
    """Scan one or more PATHs (lockfiles or directories) for compromised packages."""

    targets: list[tuple[Path, object]] = []
    for path in paths:
        discovered = _discover_targets(path)
        if not discovered and path.is_file():
            click.echo(
                f"warning: skipping {path}: not a recognised lockfile shape",
                err=True,
            )
            continue
        targets.extend(discovered)
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


@main.command(name="audit-repo")
@click.argument(
    "path",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--feed-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional extra campaign feed (JSON file).",
)
@click.option(
    "--max-bytes",
    type=int,
    default=None,
    show_default=False,
    help="Skip files larger than this (default 50 MiB).",
)
@click.option(
    "--ci",
    is_flag=True,
    default=False,
    help="Suppress color/decorations.",
)
@click.pass_context
def audit_repo_cmd(
    ctx: click.Context,
    path: Path,
    fmt: str,
    feed_file: Path | None,
    max_bytes: int | None,
    ci: bool,
) -> None:
    """Hunt for known-bad files (e.g. Mini Shai-Hulud IDE-persistence drops).

    Walks PATH and matches every file against the campaign feed's
    ``file_iocs`` blocks (SHA-256 + path-hint). Use this AFTER `check`
    has flagged a compromised lockfile, to confirm whether the
    second-stage payload landed on disk as IDE persistence.
    """

    extras = _load_extras(feed_file)
    iocs = collect_file_iocs(extras)
    cap = max_bytes if max_bytes is not None else DEFAULT_MAX_FILE_BYTES
    hits = audit_repo(path, extras, max_file_bytes=cap)

    if fmt == "json":
        import json as _json

        payload = {
            "schema_version": "1.0",
            "command": "audit-repo",
            "tool": {"name": "pwned-deps", "version": pwned_deps.__version__},
            "root": str(path),
            "iocs_loaded": len(iocs),
            "hits": [_hit_to_json(h, root=path) for h in hits],
            "summary": {
                "total": len(hits),
                "confirmed_sha256": sum(1 for h in hits if h.is_confirmed),
                "path_only": sum(1 for h in hits if not h.is_confirmed),
            },
        }
        click.echo(_json.dumps(payload, indent=2, sort_keys=True))
    else:
        _render_audit_text(path, iocs_loaded=len(iocs), hits=hits, ci=ci)

    if any(h.is_confirmed for h in hits):
        ctx.exit(1)
    if hits:
        ctx.exit(2)
    ctx.exit(0)


@main.command()
@click.argument(
    "paths",
    nargs=-1,
    required=True,
    type=click.Path(exists=True, path_type=Path),
)
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(path_type=Path),
    required=True,
    help="Baseline file. Created on first run; compared against on subsequent runs.",
)
@click.option(
    "--update-baseline",
    is_flag=True,
    default=False,
    help="Force-rewrite the baseline file with the current scan, then exit 0.",
)
@click.option(
    "--offline",
    is_flag=True,
    default=False,
    help="Skip network. Use cached database only.",
)
@click.option(
    "--feed-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional extra campaign feed (JSON file).",
)
@click.option(
    "--cache-ttl",
    type=int,
    default=24,
    show_default=True,
    help="Cache TTL in hours.",
)
@click.option(
    "--cache-path",
    type=click.Path(path_type=Path),
    default=None,
    help="Override the SQLite cache path.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    show_default=True,
    help="Output format for the alert report.",
)
@click.pass_context
def watch(
    ctx: click.Context,
    paths: tuple[Path, ...],
    baseline_path: Path,
    update_baseline: bool,
    offline: bool,
    feed_file: Path | None,
    cache_ttl: int,
    cache_path: Path | None,
    fmt: str,
) -> None:
    """Alert when an already-installed package becomes newly flagged.

    Designed to run as a daily/scheduled CI job. Exit 1 ONLY when a
    finding lands on a (ecosystem, name, version) that already
    appeared in the baseline — i.e. something you already shipped is
    now publicly compromised. Brand-new findings on packages not in
    the baseline are intentionally NOT alerts (use ``check`` for that).

    First-run behaviour: if --baseline does not exist, write it from
    the current lockfile contents and exit 0 with a message.
    """

    # 1. Discover and parse lockfiles
    targets: list[tuple[Path, object]] = []
    for path in paths:
        targets.extend(_discover_targets(path))
    if not targets:
        click.echo("watch: no recognised lockfiles found", err=True)
        ctx.exit(0)

    lockfiles: list[Lockfile] = []
    for target_path, parse in targets:
        try:
            lockfiles.append(parse(target_path))
        except ParseError as exc:
            click.echo(f"watch: parse error: {exc}", err=True)
            ctx.exit(3)

    # 2. First run OR explicit refresh: write baseline and exit 0
    if not baseline_path.exists() or update_baseline:
        new_baseline = Baseline.from_lockfiles(
            lockfiles, tool_version=pwned_deps.__version__
        )
        new_baseline.write(baseline_path)
        click.echo(
            f"watch: baseline {'updated' if update_baseline else 'created'} at "
            f"{baseline_path} ({len(new_baseline.packages)} packages)"
        )
        ctx.exit(0)

    # 3. Load existing baseline
    try:
        baseline = Baseline.read(baseline_path)
    except (ValueError, OSError) as exc:
        click.echo(f"watch: cannot read baseline {baseline_path}: {exc}", err=True)
        ctx.exit(3)

    # 4. Scan and diff against baseline
    extras = _load_extras(feed_file)
    cache = _open_cache(cache_path, cache_ttl)
    reports: list[ScanReport] = [ScanReport(lockfile=lf, findings=[]) for lf in lockfiles]
    try:
        with OsvClient(cache=cache, offline=offline) as osv:
            matcher = Matcher(osv_client=osv, extras=extras)
            for report in reports:
                report.findings = matcher.match(report.lockfile)
    finally:
        if cache is not None:
            cache.close()

    hits = watch_diff(reports, baseline)

    # 5. Render
    if fmt == "json":
        import json as _json

        payload = {
            "schema_version": "1.0",
            "command": "watch",
            "tool": {"name": "pwned-deps", "version": pwned_deps.__version__},
            "baseline_path": str(baseline_path),
            "baseline_generated_at": baseline.generated_at,
            "baseline_package_count": len(baseline.packages),
            "alerts": [
                {
                    "ecosystem": h.package.ecosystem.value,
                    "name": h.package.name,
                    "version": h.package.version or "",
                    "advisory_id": h.finding.advisory.id,
                    "is_malicious": h.finding.is_malicious,
                    "campaign_name": h.finding.campaign_name,
                }
                for h in hits
            ],
            "summary": {
                "alert_count": len(hits),
            },
        }
        click.echo(_json.dumps(payload, indent=2, sort_keys=True))
    else:
        if not hits:
            click.echo(
                f"watch: OK — {len(baseline.packages)} baseline packages, "
                f"no new findings since {baseline.generated_at}"
            )
        else:
            click.echo(
                f"watch: ALERT — {len(hits)} package(s) in your baseline "
                f"are now flagged:"
            )
            for h in hits:
                marker = "MALICIOUS" if h.finding.is_malicious else "VULN"
                campaign = (
                    f" — {h.finding.campaign_name}"
                    if h.finding.campaign_name
                    else ""
                )
                click.echo(
                    f"  [{marker}] {h.package.ecosystem.value}:"
                    f"{h.package.name}@{h.package.version} "
                    f"({h.finding.advisory.id}){campaign}"
                )

    ctx.exit(1 if hits else 0)


def _hit_to_json(hit: FileHit, *, root: Path) -> dict[str, object]:
    """Serialise a ``FileHit`` for JSON output."""

    try:
        rel = str(hit.path.relative_to(root))
    except ValueError:
        rel = str(hit.path)
    return {
        "path": rel,
        "absolute_path": str(hit.path),
        "sha256": hit.sha256,
        "matched_by": hit.matched_by,
        "confirmed": hit.is_confirmed,
        "ioc": {
            "campaign_id": hit.ioc.campaign_id,
            "campaign_name": hit.ioc.campaign_name,
            "path_hint": hit.ioc.path_hint,
            "expected_sha256": hit.ioc.sha256,
            "expected_size_bytes": hit.ioc.size_bytes,
            "description": hit.ioc.description,
            "source": hit.ioc.source,
        },
    }


def _render_audit_text(
    root: Path,
    *,
    iocs_loaded: int,
    hits: list[FileHit],
    ci: bool,
) -> None:
    """Compact text renderer for ``audit-repo``."""

    click.echo(
        f"pwned-deps {pwned_deps.__version__} \u2014 auditing {root} "
        f"({iocs_loaded} file IoCs loaded)"
    )
    if not iocs_loaded:
        click.echo("no file IoCs in feed \u2014 nothing to match against", err=True)
        click.echo("")
        click.echo("0 hits")
        return

    if not hits:
        click.echo("")
        click.echo("CLEAN \u2014 no known-bad files found")
        return

    confirmed = [h for h in hits if h.is_confirmed]
    suspect = [h for h in hits if not h.is_confirmed]

    if confirmed:
        click.echo("")
        click.echo(f"CONFIRMED \u2014 {len(confirmed)} file(s) match a known-bad SHA-256")
        for h in confirmed:
            try:
                rel = str(h.path.relative_to(root))
            except ValueError:
                rel = str(h.path)
            click.echo(f"  {rel}")
            click.echo(f"    matched: {h.matched_by}")
            click.echo(f"    sha256:  {h.sha256}")
            click.echo(f"    campaign: {h.ioc.campaign_id} \u2014 {h.ioc.campaign_name}")
            if h.ioc.description:
                click.echo(f"    note:    {h.ioc.description}")

    if suspect:
        click.echo("")
        click.echo(
            f"SUSPECT \u2014 {len(suspect)} file(s) at known-persistence paths "
            f"(content modified or new variant)"
        )
        for h in suspect:
            try:
                rel = str(h.path.relative_to(root))
            except ValueError:
                rel = str(h.path)
            click.echo(f"  {rel}")
            click.echo(f"    sha256:  {h.sha256}")
            click.echo(f"    campaign: {h.ioc.campaign_id} \u2014 {h.ioc.campaign_name}")
            if h.ioc.description:
                click.echo(f"    note:    {h.ioc.description}")

    click.echo("")
    click.echo(
        f"{len(hits)} hit(s) \u00b7 "
        f"{len(confirmed)} confirmed \u00b7 "
        f"{len(suspect)} path-only"
    )
    _ = ci  # currently unused; reserved for future colorisation toggle.


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _discover_targets(path: Path) -> list[tuple[Path, object]]:
    """Return list of ``(lockfile_path, parser_callable)`` to scan.

    Returns an empty list when ``path`` is a file we don't recognise;
    the caller surfaces a "skipping" warning so the user knows we
    saw the file but did nothing with it.
    """

    if path.is_file():
        for filename, parser in _DETECTORS:
            if path.name == filename:
                return [(path, parser)]
        # Extension-based fallback: `*.txt` → requirements;
        # `*lock*.json` → npm-style.
        lower = path.name.lower()
        if path.suffix == ".txt":
            return [(path, pypi_parser.parse)]
        if path.suffix == ".json" and "lock" in lower:
            return [(path, npm_parser.parse)]
        return []

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
