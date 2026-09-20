"""Tests for ``pwned-deps watch`` baseline + delta workflow."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from pwned_deps.advisory.cache import Cache
from pwned_deps.cli import main as cli
from pwned_deps.parsers import npm as npm_parser

FIXTURES = Path(__file__).parent / "fixtures"


def _seeded_cache(tmp_path: Path, *fixtures: Path) -> list[str]:
    """Return ``--cache-path`` args for a cache that says "no findings"
    for every package in ``fixtures`` — so ``--offline`` is a genuine
    cache hit rather than an unchecked package."""

    path = tmp_path / "cache" / "osv.sqlite"
    path.parent.mkdir(parents=True, exist_ok=True)
    cache = Cache(path)
    for fixture in fixtures:
        for pkg in npm_parser.parse(fixture).packages:
            cache.put(pkg.ecosystem.value, pkg.name, pkg.version, [])
    cache.close()
    return ["--cache-path", str(path)]


def test_watch_first_run_creates_baseline_and_exits_zero(tmp_path: Path) -> None:
    """First run with a non-existent baseline must create it and exit 0
    even if the lockfile would otherwise trigger findings."""
    runner = CliRunner()
    baseline = tmp_path / "baseline.json"
    fixture = FIXTURES / "npm" / "historic-event-stream.lock.json"

    result = runner.invoke(
        cli,
        ["watch", str(fixture), "--baseline", str(baseline), "--offline"],
    )
    assert result.exit_code == 0, result.output
    assert "baseline created" in result.output
    assert baseline.exists()

    data = json.loads(baseline.read_text())
    assert data["schema_version"] == "1.0"
    pkg_keys = {(p["ecosystem"], p["name"]) for p in data["packages"]}
    assert ("npm", "event-stream") in pkg_keys


def test_watch_alerts_when_baseline_package_is_now_flagged(tmp_path: Path) -> None:
    """The killer use case: a package that was in the baseline (and
    presumably clean at the time) is now publicly flagged. Exit 1."""
    runner = CliRunner()
    baseline = tmp_path / "baseline.json"
    fixture = FIXTURES / "npm" / "historic-event-stream.lock.json"
    cache_args = _seeded_cache(tmp_path, fixture)

    # First run: write the baseline (event-stream@3.3.6 is in it).
    r1 = runner.invoke(
        cli, ["watch", str(fixture), "--baseline", str(baseline), "--offline", *cache_args]
    )
    assert r1.exit_code == 0

    # Second run: same lockfile. event-stream@3.3.6 is in the baseline
    # AND in the bundled extras feed (EXTRA-2018-0001) -> alert.
    r2 = runner.invoke(
        cli,
        [
            "watch",
            str(fixture),
            "--baseline",
            str(baseline),
            "--offline",
            *cache_args,
            "--format",
            "json",
        ],
    )
    assert r2.exit_code == 1, r2.output
    payload = json.loads(r2.output)
    assert payload["command"] == "watch"
    assert payload["summary"]["alert_count"] >= 1
    alert_ids = {a["advisory_id"] for a in payload["alerts"]}
    assert "EXTRA-2018-0001" in alert_ids


def test_watch_clean_lockfile_against_baseline_exits_zero(tmp_path: Path) -> None:
    """A baseline + a lockfile whose packages are cached as clean -> exit 0."""
    runner = CliRunner()
    baseline = tmp_path / "baseline.json"
    fixture = FIXTURES / "npm" / "clean.lock.json"
    cache_args = _seeded_cache(tmp_path, fixture)

    runner.invoke(
        cli, ["watch", str(fixture), "--baseline", str(baseline), "--offline", *cache_args]
    )
    assert baseline.exists()

    r2 = runner.invoke(
        cli, ["watch", str(fixture), "--baseline", str(baseline), "--offline", *cache_args]
    )
    assert r2.exit_code == 0, r2.output
    assert "watch: OK" in r2.output


def test_watch_offline_cache_miss_is_incomplete_not_ok(tmp_path: Path) -> None:
    """Regression: offline with nothing cached used to print 'watch: OK'
    and exit 0 — a silent false negative. It must now say INCOMPLETE
    and exit 4."""
    runner = CliRunner()
    baseline = tmp_path / "baseline.json"
    fixture = FIXTURES / "npm" / "clean.lock.json"
    cache_args = ["--cache-path", str(tmp_path / "empty" / "osv.sqlite")]

    runner.invoke(
        cli, ["watch", str(fixture), "--baseline", str(baseline), "--offline", *cache_args]
    )
    r2 = runner.invoke(
        cli, ["watch", str(fixture), "--baseline", str(baseline), "--offline", *cache_args]
    )
    assert r2.exit_code == 4, r2.output
    assert "INCOMPLETE" in r2.output
    assert "watch: OK" not in r2.output


def test_watch_update_baseline_flag_rewrites_and_exits_zero(tmp_path: Path) -> None:
    """--update-baseline must overwrite the existing file and exit 0
    even when the lockfile contains a flagged package."""
    runner = CliRunner()
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "generated_at": "2020-01-01T00:00:00Z",
                "tool": {"name": "pwned-deps", "version": "0.0.1"},
                "packages": [],
            }
        )
    )
    fixture = FIXTURES / "npm" / "historic-event-stream.lock.json"

    result = runner.invoke(
        cli,
        [
            "watch",
            str(fixture),
            "--baseline",
            str(baseline),
            "--update-baseline",
            "--offline",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "baseline updated" in result.output

    data = json.loads(baseline.read_text())
    pkg_keys = {(p["ecosystem"], p["name"]) for p in data["packages"]}
    assert ("npm", "event-stream") in pkg_keys
    assert data["generated_at"] != "2020-01-01T00:00:00Z"


def test_watch_does_not_alert_on_brand_new_findings(tmp_path: Path) -> None:
    """If a finding lands on a package NOT in the baseline, watch must
    not alert (that's a job for ``check``, not ``watch``)."""
    runner = CliRunner()
    baseline = tmp_path / "baseline.json"

    # Seed baseline from the clean fixture (no event-stream).
    clean = FIXTURES / "npm" / "clean.lock.json"
    fixture = FIXTURES / "npm" / "historic-event-stream.lock.json"
    cache_args = _seeded_cache(tmp_path, clean, fixture)
    runner.invoke(
        cli, ["watch", str(clean), "--baseline", str(baseline), "--offline", *cache_args]
    )
    assert baseline.exists()

    # Now scan the historic-event-stream fixture against the
    # clean-package baseline. event-stream@3.3.6 IS flagged, but it's
    # not in the baseline -> should NOT alert.
    r = runner.invoke(
        cli,
        [
            "watch",
            str(fixture),
            "--baseline",
            str(baseline),
            "--offline",
            *cache_args,
            "--format",
            "json",
        ],
    )
    assert r.exit_code == 0, r.output
    payload = json.loads(r.output)
    assert payload["summary"]["alert_count"] == 0
