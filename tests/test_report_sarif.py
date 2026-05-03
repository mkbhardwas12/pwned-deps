"""SARIF v2.1.0 reporter tests.

The bundled SARIF schema is at
``tests/fixtures/sarif/sarif-2.1.0-schema.json`` (fetched from
json.schemastore.org). We validate the renderer output with
``jsonschema.validate``, then assert the brief's required fields.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
from click.testing import CliRunner
from pytest_httpx import HTTPXMock

from pwned_deps.advisory.matcher import Finding
from pwned_deps.advisory.types import Advisory, Severity
from pwned_deps.cli import main
from pwned_deps.parsers.base import Ecosystem, Lockfile, Package
from pwned_deps.report.sarif import render_sarif
from pwned_deps.report.text import ScanReport

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SARIF_SCHEMA = json.loads(
    (FIXTURES / "sarif" / "sarif-2.1.0-schema.json").read_text(encoding="utf-8")
)


def _malicious_finding() -> Finding:
    pkg = Package(
        name="@cap-js/sqlite",
        version="2.2.2",
        ecosystem=Ecosystem.NPM,
        lockfile_path="tests/fixtures/npm/mini-shaihulud.lock.json",
    )
    advisory = Advisory(
        id="EXTRA-2026-0001",
        summary="Mini Shai-Hulud (SAP CAP) — credential stealer.",
        ecosystem="npm",
        package="@cap-js/sqlite",
        version="2.2.2",
        references=("https://wiz.io/test", "https://thehackernews.com/test"),
        severity=Severity.CRITICAL,
        raw={},
    )
    return Finding(
        package=pkg,
        advisory=advisory,
        is_malicious=True,
        campaign_name="Mini Shai-Hulud (SAP CAP)",
    )


def _high_finding() -> Finding:
    pkg = Package(
        name="lodash",
        version="4.17.15",
        ecosystem=Ecosystem.NPM,
        lockfile_path="tests/fixtures/npm/v1.lock.json",
    )
    advisory = Advisory(
        id="GHSA-LODASH",
        summary="Prototype pollution.",
        ecosystem="npm",
        package="lodash",
        version="4.17.15",
        references=("https://example.test/lodash",),
        severity=Severity.HIGH,
        raw={},
    )
    return Finding(package=pkg, advisory=advisory, is_malicious=False)


def _scan_report(*findings: Finding) -> ScanReport:
    if findings:
        path = Path(findings[0].package.lockfile_path)
    else:
        path = Path("tests/fixtures/empty.json")
    lockfile = Lockfile(
        path=path,
        ecosystem=Ecosystem.NPM,
        packages=tuple(f.package for f in findings),
    )
    return ScanReport(lockfile=lockfile, findings=list(findings))


def test_sarif_validates_against_schema_for_malicious_finding() -> None:
    text, exit_code = render_sarif([_scan_report(_malicious_finding())], version="0.1.0")
    payload = json.loads(text)

    jsonschema.validate(payload, SARIF_SCHEMA)
    assert exit_code == 1


def test_sarif_required_top_level_fields() -> None:
    text, _ = render_sarif([_scan_report(_malicious_finding())], version="0.1.0")
    payload = json.loads(text)

    assert payload["version"] == "2.1.0"
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "pwned-deps"
    assert run["tool"]["driver"]["version"] == "0.1.0"
    assert run["tool"]["driver"]["informationUri"].endswith("/pwned-deps")
    rules = run["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "EXTRA-2026-0001"


def test_sarif_level_mapping() -> None:
    text, _ = render_sarif(
        [_scan_report(_malicious_finding(), _high_finding())],
        version="0.1.0",
    )
    payload = json.loads(text)
    levels = {r["ruleId"]: r["level"] for r in payload["runs"][0]["results"]}
    # Malicious campaign and severity HIGH both map to "error"
    assert levels["EXTRA-2026-0001"] == "error"
    assert levels["GHSA-LODASH"] == "error"


def test_sarif_partial_fingerprints_are_stable() -> None:
    text_a, _ = render_sarif([_scan_report(_malicious_finding())], version="0.1.0")
    text_b, _ = render_sarif([_scan_report(_malicious_finding())], version="0.1.0")
    fp_a = json.loads(text_a)["runs"][0]["results"][0]["partialFingerprints"]
    fp_b = json.loads(text_b)["runs"][0]["results"][0]["partialFingerprints"]
    assert fp_a == fp_b
    assert "primaryLocationLineHash" in fp_a
    assert len(fp_a["primaryLocationLineHash"]) == 64  # sha256 hex


def test_cli_format_sarif_emits_valid_sarif(tmp_path: Path, httpx_mock: HTTPXMock) -> None:
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
            "sarif",
            "--cache-path",
            str(tmp_path / "cache.sqlite"),
            "--ci",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    jsonschema.validate(payload, SARIF_SCHEMA)
    rules = payload["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = {r["id"] for r in rules}
    assert "EXTRA-2026-0001" in rule_ids
