"""End-to-end CLI tests using click.testing.CliRunner."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner
from pytest_httpx import HTTPXMock

from pwned_deps.cli import main

FIXTURES = Path(__file__).resolve().parent / "fixtures"
NPM_FIXTURES = FIXTURES / "npm"
EXTRAS_FIXTURES = FIXTURES / "extras"


def _isolated_cache(tmp_path: Path) -> Path:
    return tmp_path / "cache" / "osv.sqlite"


def test_check_clean_lockfile_exits_zero(tmp_path: Path, httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        method="POST",
        json={"results": [{}]},
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "check",
            str(NPM_FIXTURES / "clean.lock.json"),
            "--cache-path",
            str(_isolated_cache(tmp_path)),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert "clean" in result.output.lower()


def test_check_synthetic_malicious_exits_one_and_names_campaign(
    tmp_path: Path, httpx_mock: HTTPXMock
) -> None:
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        method="POST",
        json={"results": [{}]},
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "check",
            str(NPM_FIXTURES / "synthetic-malicious.lock.json"),
            "--feed-file",
            str(EXTRAS_FIXTURES / "synthetic-campaign.json"),
            "--cache-path",
            str(_isolated_cache(tmp_path)),
            "--ci",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 1, result.output
    assert "COMPROMISED" in result.output
    assert "Synthetic test campaign" in result.output


def test_check_format_json_emits_valid_json(
    tmp_path: Path, httpx_mock: HTTPXMock
) -> None:
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        method="POST",
        json={"results": [{}]},
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "check",
            str(NPM_FIXTURES / "clean.lock.json"),
            "--format",
            "json",
            "--cache-path",
            str(_isolated_cache(tmp_path)),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["tool"]["name"] == "pwned-deps"
    assert payload["lockfiles"][0]["package_count"] == 1
    assert payload["summary"]["compromised"] == 0


def test_check_ci_text_has_no_ansi_escape_codes(
    tmp_path: Path, httpx_mock: HTTPXMock
) -> None:
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        method="POST",
        json={"results": [{}]},
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "check",
            str(NPM_FIXTURES / "clean.lock.json"),
            "--ci",
            "--cache-path",
            str(_isolated_cache(tmp_path)),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert "\x1b[" not in result.output


def test_check_directory_autodetects_lockfiles(
    tmp_path: Path, httpx_mock: HTTPXMock
) -> None:
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        method="POST",
        json={"results": [{}]},
    )
    project = tmp_path / "proj"
    project.mkdir()
    (project / "package-lock.json").write_text(
        (NPM_FIXTURES / "clean.lock.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "check",
            str(project),
            "--cache-path",
            str(_isolated_cache(tmp_path)),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert "package-lock.json" in result.output


def test_check_offline_with_empty_cache_does_not_call_network(
    tmp_path: Path, httpx_mock: HTTPXMock
) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "check",
            str(NPM_FIXTURES / "clean.lock.json"),
            "--offline",
            "--cache-path",
            str(_isolated_cache(tmp_path)),
        ],
        catch_exceptions=False,
    )
    # Empty cache + offline => nothing was actually looked up. That is
    # an INCOMPLETE scan (exit 4), never "clean", and never a network call.
    assert result.exit_code == 4, result.output
    assert "UNCHECKED" in result.output
    assert "INCOMPLETE" in result.output
    assert "packages clean" not in result.output
    assert httpx_mock.get_requests() == []


def test_check_offline_with_warm_cache_is_clean(
    tmp_path: Path, httpx_mock: HTTPXMock
) -> None:
    from pwned_deps.advisory.cache import Cache
    from pwned_deps.parsers import npm as npm_parser

    fixture = NPM_FIXTURES / "clean.lock.json"
    cache_path = _isolated_cache(tmp_path)
    cache_path.parent.mkdir(parents=True)
    cache = Cache(cache_path)
    for pkg in npm_parser.parse(fixture).packages:
        cache.put(pkg.ecosystem.value, pkg.name, pkg.version, [])
    cache.close()

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["check", str(fixture), "--offline", "--ci", "--cache-path", str(cache_path)],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert "All 1 pinned packages clean." in result.output
    assert httpx_mock.get_requests() == []


def test_check_network_failure_is_incomplete_not_clean(
    tmp_path: Path, httpx_mock: HTTPXMock, monkeypatch
) -> None:
    import httpx

    from pwned_deps.advisory import osv_client

    monkeypatch.setattr(osv_client.time, "sleep", lambda _s: None)
    httpx_mock.add_exception(httpx.ConnectError("boom"), is_reusable=True)
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "check",
            str(NPM_FIXTURES / "clean.lock.json"),
            "--ci",
            "--cache-path",
            str(_isolated_cache(tmp_path)),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 4, result.output
    assert "OSV query failed: ConnectError" in result.output
    assert "packages clean" not in result.output


def test_check_malicious_hit_wins_over_unchecked(
    tmp_path: Path, httpx_mock: HTTPXMock
) -> None:
    """Extras feed hit + offline cache miss => exit 1, not 4."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "check",
            str(NPM_FIXTURES / "synthetic-malicious.lock.json"),
            "--feed-file",
            str(EXTRAS_FIXTURES / "synthetic-campaign.json"),
            "--offline",
            "--ci",
            "--cache-path",
            str(_isolated_cache(tmp_path)),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 1, result.output
    assert "COMPROMISED" in result.output
    assert "unchecked" in result.output


def test_check_json_reports_unchecked_and_exit_four(
    tmp_path: Path, httpx_mock: HTTPXMock
) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "check",
            str(NPM_FIXTURES / "clean.lock.json"),
            "--offline",
            "--format",
            "json",
            "--cache-path",
            str(_isolated_cache(tmp_path)),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 4, result.output
    payload = json.loads(result.output)
    assert payload["summary"]["unchecked"] == 1
    assert payload["summary"]["checked"] == 0
    assert payload["lockfiles"][0]["unchecked"][0]["reason"] == "offline and not in cache"


def test_check_unpinned_requirements_are_reported_not_silently_clean(
    tmp_path: Path, httpx_mock: HTTPXMock
) -> None:
    reqs = tmp_path / "requirements.txt"
    reqs.write_text("requests>=2\nflask\n", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["check", str(reqs), "--ci", "--cache-path", str(_isolated_cache(tmp_path))],
        catch_exceptions=False,
    )
    # Nothing pinned -> nothing to check; that is exit 0 but the user
    # must be told the coverage was zero.
    assert result.exit_code == 0, result.output
    assert "All 0 pinned packages clean." in result.output
    assert "2 unpinned entries" in result.output
    assert httpx_mock.get_requests() == []


def test_check_corrupted_lockfile_exits_three(tmp_path: Path) -> None:
    bad = tmp_path / "package-lock.json"
    bad.write_text("{not json", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "check",
            str(bad),
            "--cache-path",
            str(_isolated_cache(tmp_path)),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 3, result.output
    assert "parse error" in result.output.lower()


def test_version_subcommand_prints_version() -> None:
    import pwned_deps

    runner = CliRunner()
    result = runner.invoke(main, ["version"])
    assert result.exit_code == 0
    assert result.output.strip() == pwned_deps.__version__


def test_update_creates_cache(tmp_path: Path) -> None:
    runner = CliRunner()
    cache_path = _isolated_cache(tmp_path)
    result = runner.invoke(main, ["update", "--cache-path", str(cache_path)])
    assert result.exit_code == 0
    assert cache_path.exists()


def test_check_multiple_paths_skips_unrecognised(
    tmp_path: Path, httpx_mock: HTTPXMock
) -> None:
    """Pass an unrecognised manifest (pyproject.toml shape) alongside
    a real lockfile. The unrecognised file should produce a warning on
    stderr and the run should report the lockfile findings only."""

    manifest = tmp_path / "pyproject.toml"
    manifest.write_text("[project]\nname = 'x'\n", encoding="utf-8")

    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        method="POST",
        json={"results": [{}]},
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "check",
            str(manifest),
            str(NPM_FIXTURES / "clean.lock.json"),
            "--cache-path",
            str(_isolated_cache(tmp_path)),
            "--ci",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    # click 8.3+ exposes stderr separately on result.stderr.
    assert "skipping" in (result.stderr or result.output)
    assert "clean.lock.json" in result.output
