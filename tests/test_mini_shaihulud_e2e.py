"""End-to-end check that the bundled Mini Shai-Hulud campaign is detected.

Acceptance: running `pwned-deps check` against a fixture lockfile that
pins a known-bad version returns the campaign as a finding with the
correct exposure window and remediation steps.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner
from pytest_httpx import HTTPXMock

from pwned_deps.cli import main

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _isolated_cache(tmp_path: Path) -> Path:
    return tmp_path / "cache" / "osv.sqlite"


def test_bundled_extras_loaded_with_mini_shaihulud_campaign() -> None:
    """The shipped extras.json contains the Mini Shai-Hulud campaign and
    cites at least three named research blogs. This guards against
    accidental regressions of the file or the package data."""

    from importlib import resources

    bundle = resources.files("pwned_deps.extras_data").joinpath("extras.json")
    data = json.loads(bundle.read_text(encoding="utf-8"))
    campaigns = {c["id"]: c for c in data.get("campaigns", [])}
    assert "EXTRA-2026-0001" in campaigns

    campaign = campaigns["EXTRA-2026-0001"]
    assert campaign["name"] == "Mini Shai-Hulud (SAP CAP)"
    assert campaign["ecosystem"] == "npm"
    assert len(campaign["references"]) >= 3
    package_versions = {(p["name"], v) for p in campaign["packages"] for v in p["versions"]}
    # The four sourced (name, version) tuples from Wiz / THN / SecurityBridge.
    assert ("@cap-js/sqlite", "2.2.2") in package_versions
    assert ("@cap-js/postgres", "2.2.2") in package_versions
    assert ("@cap-js/db-service", "2.10.1") in package_versions
    assert ("mbt", "1.2.48") in package_versions
    # Exposure-window endpoints are ISO 8601 UTC strings.
    assert campaign["exposure_window"][0].startswith("2026-04-29T")
    assert campaign["exposure_window"][1].startswith("2026-04-29T")


def test_check_pinning_known_bad_version_reports_campaign(
    tmp_path: Path, httpx_mock: HTTPXMock
) -> None:
    """`pwned-deps check tests/fixtures/npm/mini-shaihulud.lock.json`
    must exit 1 with the campaign visible in JSON output."""

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
            str(FIXTURES / "npm" / "mini-shaihulud.lock.json"),
            "--format",
            "json",
            "--cache-path",
            str(_isolated_cache(tmp_path)),
            "--ci",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    findings = [f for lf in payload["lockfiles"] for f in lf["findings"]]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["id"] == "EXTRA-2026-0001"
    assert finding["package"] == "@cap-js/sqlite"
    assert finding["version"] == "2.2.2"
    assert finding["is_malicious"] is True
    assert finding["campaign_name"] == "Mini Shai-Hulud (SAP CAP)"
    assert finding["severity"] == "CRITICAL"


def test_bundled_extras_loaded_with_april30_followon_campaign() -> None:
    """The shipped extras.json also carries the April-30 follow-on
    campaign (EXTRA-2026-0002) covering intercom-client@7.0.5 and
    lightning@{2.6.2,2.6.3}, sourced from Wiz."""

    from importlib import resources

    bundle = resources.files("pwned_deps.extras_data").joinpath("extras.json")
    data = json.loads(bundle.read_text(encoding="utf-8"))
    campaigns = {c["id"]: c for c in data.get("campaigns", [])}
    assert "EXTRA-2026-0002" in campaigns

    campaign = campaigns["EXTRA-2026-0002"]
    pairs = {(p["name"], v) for p in campaign["packages"] for v in p["versions"]}
    assert ("intercom-client", "7.0.5") in pairs
    assert ("lightning", "2.6.2") in pairs
    assert ("lightning", "2.6.3") in pairs
    assert any("wiz.io" in ref for ref in campaign["references"])


def test_check_pinning_april30_version_reports_followon_campaign(
    tmp_path: Path, httpx_mock: HTTPXMock
) -> None:
    """`pwned-deps check tests/fixtures/npm/mini-shaihulud-followon.lock.json`
    must surface EXTRA-2026-0002."""

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
            str(FIXTURES / "npm" / "mini-shaihulud-followon.lock.json"),
            "--format",
            "json",
            "--cache-path",
            str(_isolated_cache(tmp_path)),
            "--ci",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    findings = [f for lf in payload["lockfiles"] for f in lf["findings"]]
    assert any(f["id"] == "EXTRA-2026-0002" for f in findings)


def test_check_text_output_shows_campaign_and_remediation(
    tmp_path: Path, httpx_mock: HTTPXMock
) -> None:
    """Text output must surface the campaign name and at least one
    remediation action."""

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
            str(FIXTURES / "npm" / "mini-shaihulud.lock.json"),
            "--cache-path",
            str(_isolated_cache(tmp_path)),
            "--ci",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 1, result.output
    assert "COMPROMISED" in result.output
    assert "Mini Shai-Hulud (SAP CAP)" in result.output
    assert "@cap-js/sqlite@2.2.2" in result.output


def test_lightning_pypi_is_caught_via_per_package_ecosystem_override(
    tmp_path: Path, httpx_mock: HTTPXMock
) -> None:
    """Regression: EXTRA-2026-0002 covers `lightning@2.6.2/2.6.3` on
    PyPI (per Wiz). Before the per-package ecosystem override, this
    entry was silently ignored on Python lockfiles because the campaign-
    level ecosystem said `npm`. Confirm a Python requirements.txt
    pinning lightning@2.6.2 now exits 1."""

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
            str(FIXTURES / "pypi" / "lightning-pinned.txt"),
            "--format",
            "json",
            "--cache-path",
            str(_isolated_cache(tmp_path)),
            "--ci",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    findings = [f for lf in payload["lockfiles"] for f in lf["findings"]]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["id"] == "EXTRA-2026-0002"
    assert finding["package"] == "lightning"
    assert finding["version"] == "2.6.2"
    assert finding["ecosystem"] == "PyPI"
    # The campaign-level `iocs` field must be carried into the JSON
    # output so consumers (Code Scanning, dashboards) can hunt for the
    # non-lockfile indicators (rogue C2 domains, suspicious commits).
    assert any("zero.masscan.cloud" in ioc for ioc in finding["iocs"])


def test_text_output_surfaces_tarball_sha256_and_iocs(
    tmp_path: Path, httpx_mock: HTTPXMock
) -> None:
    """For Mini Shai-Hulud (which carries tarball_sha256 + iocs),
    the text report must surface both so users can act on them
    without re-reading the source blogs."""

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
            str(FIXTURES / "npm" / "mini-shaihulud.lock.json"),
            "--cache-path",
            str(_isolated_cache(tmp_path)),
            "--ci",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 1, result.output
    # tarball_sha256 from extras.json for @cap-js/sqlite@2.2.2.
    assert "a1da198bb4e883d077a0e13351bf2c3acdea10497152292e873d79d4f7420211" in result.output
    # At least one campaign-level IoC line must be visible.
    assert "additional indicators" in result.output.lower()
    assert "A Mini Shai-Hulud has Appeared" in result.output
