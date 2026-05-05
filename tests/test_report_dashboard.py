"""Tests for the static HTML dashboard renderer."""

from __future__ import annotations

import json
import re
from pathlib import Path

from click.testing import CliRunner

from pwned_deps.cli import main as cli
from pwned_deps.report.dashboard import (
    DASHBOARD_SCHEMA_VERSION,
    render_dashboard,
    render_dashboard_from_paths,
)


def _scan(
    *,
    source: str = "scan.json",
    findings: list[dict] | None = None,
    total_packages: int = 0,
    compromised: int = 0,
    high_critical: int = 0,
) -> tuple[str, dict]:
    return source, {
        "schema_version": "1.0",
        "tool": {"name": "pwned-deps", "version": "0.1.0"},
        "lockfiles": [
            {
                "path": "package-lock.json",
                "ecosystem": "npm",
                "package_count": total_packages,
                "parse_error": None,
                "findings": findings or [],
            }
        ],
        "summary": {
            "total_packages": total_packages,
            "compromised": compromised,
            "high_critical": high_critical,
            "other": 0,
        },
    }


def _finding(**overrides) -> dict:
    base = {
        "id": "EXTRA-2018-0001",
        "package": "event-stream",
        "version": "3.3.6",
        "ecosystem": "npm",
        "severity": "CRITICAL",
        "summary": "credential stealer",
        "references": ["https://example.test/disclosure"],
        "is_malicious": True,
        "campaign_name": "event-stream / flatmap-stream",
        "iocs": [],
    }
    base.update(overrides)
    return base


def test_clean_dashboard_renders_zero_kpis_and_empty_state() -> None:
    html = render_dashboard([_scan(total_packages=42)])
    assert "<!doctype html>" in html
    # Headline KPIs
    assert ">42<" in html  # packages scanned
    assert ">0<" in html  # compromised
    # Empty-state message instead of campaign / findings tables.
    assert "clean across all scans" in html
    # Schema version baked into the meta tag.
    assert DASHBOARD_SCHEMA_VERSION in html


def test_compromised_dashboard_shows_finding_and_pill() -> None:
    html = render_dashboard(
        [_scan(total_packages=1, compromised=1, findings=[_finding()])]
    )
    assert "MALICIOUS" in html
    assert "event-stream" in html
    assert "EXTRA-2018-0001" in html
    assert "https://example.test/disclosure" in html
    # Campaign rollup row + per-finding row both rendered.
    assert html.count("EXTRA-2018-0001") >= 2


def test_aggregation_across_multiple_scans() -> None:
    """Same advisory hitting two repos should show hits=2, sources=2."""
    html = render_dashboard(
        [
            _scan(source="repo-a/scan.json", total_packages=10, compromised=1, findings=[_finding()]),
            _scan(source="repo-b/scan.json", total_packages=20, compromised=1, findings=[_finding()]),
        ]
    )
    # Total packages aggregated.
    assert ">30<" in html
    # Both source labels in the scans table.
    assert "repo-a/scan.json" in html
    assert "repo-b/scan.json" in html
    # Campaign rollup shows hits=2 sources=2 (extract the row).
    rollup = re.search(
        r"EXTRA-2018-0001.*?</tr>", html, re.DOTALL
    )
    assert rollup is not None
    row = rollup.group(0)
    # Two ">2<" in the same row (hits column + sources column).
    assert row.count(">2<") >= 2


def test_xss_in_campaign_summary_is_escaped() -> None:
    """Campaign-supplied strings are attacker-influenced; must escape."""
    html = render_dashboard(
        [
            _scan(
                total_packages=1,
                compromised=1,
                findings=[
                    _finding(
                        campaign_name="<script>alert(1)</script>",
                        package='evil"><img src=x onerror=alert(1)>',
                    )
                ],
            )
        ]
    )
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert 'evil"><img' not in html  # raw form must not appear
    assert "&quot;" in html or "&#34;" in html


def test_non_http_reference_url_is_dropped() -> None:
    """Only http/https references become clickable links."""
    html = render_dashboard(
        [
            _scan(
                total_packages=1,
                compromised=1,
                findings=[
                    _finding(
                        references=[
                            "javascript:alert(1)",
                            "https://safe.example.test/x",
                        ]
                    )
                ],
            )
        ]
    )
    assert "javascript:alert" not in html
    assert "https://safe.example.test/x" in html


def test_render_from_paths_skips_non_pwned_deps_files(tmp_path: Path) -> None:
    good = tmp_path / "scan.json"
    good.write_text(json.dumps(_scan(total_packages=5)[1]))
    junk = tmp_path / "garbage.json"
    junk.write_text("not json at all")
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"hello": "world"}))
    html = render_dashboard_from_paths([good, junk, other])
    # One scan ingested -> shows count of 1, not 3.
    assert html.count(str(good)) >= 1
    assert "garbage.json" not in html
    assert "other.json" not in html


def test_cli_report_subcommand_writes_html(tmp_path: Path) -> None:
    scan = tmp_path / "scan.json"
    scan.write_text(
        json.dumps(_scan(total_packages=1, compromised=1, findings=[_finding()])[1])
    )
    out = tmp_path / "dashboard.html"
    runner = CliRunner()
    result = runner.invoke(cli, ["report", str(scan), "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert out.exists()
    body = out.read_text()
    assert "<!doctype html>" in body
    assert "MALICIOUS" in body
    assert "EXTRA-2018-0001" in body
