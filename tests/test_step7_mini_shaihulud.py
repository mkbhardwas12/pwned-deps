"""End-to-end check that the bundled Mini Shai-Hulud campaign is detected.

Per BUILD_BRIEF §7 Step 7 acceptance: running `pwned-deps check` against
a fixture lockfile that pins a known-bad version returns the campaign as
a finding with the correct exposure window and remediation steps.
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
