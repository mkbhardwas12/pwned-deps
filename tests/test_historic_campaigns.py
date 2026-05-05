"""Regression tests for the historical-campaigns backfill.

These assert that pwned-deps flags well-documented public incidents from
2018-2022 across npm and PyPI ecosystems — proving the tool is useful
beyond the launch campaign.
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

from click.testing import CliRunner

from pwned_deps.cli import main as cli

FIXTURES = Path(__file__).parent / "fixtures"


def _campaigns() -> dict[str, dict]:
    bundle = resources.files("pwned_deps.extras_data").joinpath("extras.json")
    data = json.loads(bundle.read_text())
    return {c["id"]: c for c in data["campaigns"]}


def test_extras_carries_eight_historical_campaigns() -> None:
    """The bundled feed must include the 2018-2022 backfill so a fresh
    install knows about classic incidents, not just the launch peg."""
    campaigns = _campaigns()
    expected_historical = {
        "EXTRA-2018-0001",  # event-stream
        "EXTRA-2018-0002",  # eslint-scope
        "EXTRA-2021-0001",  # ua-parser-js
        "EXTRA-2021-0002",  # coa
        "EXTRA-2021-0003",  # rc
        "EXTRA-2022-0001",  # ctx (PyPI)
        "EXTRA-2022-0002",  # node-ipc
        "EXTRA-2022-0003",  # torchtriton (PyPI)
    }
    missing = expected_historical - set(campaigns.keys())
    assert not missing, f"historical campaigns missing from feed: {missing}"

    # Every historical entry must carry at least one named-blog citation.
    for cid in expected_historical:
        refs = campaigns[cid].get("references", [])
        assert refs, f"{cid} has no references"
        assert any("http" in r for r in refs), f"{cid} references not URLs"


def test_npm_historic_event_stream_fixture_flags_2018_incident() -> None:
    """The historic event-stream fixture must trigger EXTRA-2018-0001."""
    runner = CliRunner()
    fixture = FIXTURES / "npm" / "historic-event-stream.lock.json"
    result = runner.invoke(
        cli, ["check", str(fixture), "--offline", "--format", "json"]
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    findings = [f for lf in payload["lockfiles"] for f in lf["findings"]]
    ids = {f["id"] for f in findings}
    assert "EXTRA-2018-0001" in ids, f"event-stream not flagged: {ids}"


def test_pypi_historic_fixture_flags_ctx_and_torchtriton() -> None:
    """A single PyPI requirements file pinning ctx@0.2.2 and
    torchtriton@0.0.1 must surface both 2022 campaigns — proves the
    feed works on PyPI, not just npm."""
    runner = CliRunner()
    fixture = FIXTURES / "pypi" / "historic-compromised.txt"
    result = runner.invoke(
        cli, ["check", str(fixture), "--offline", "--format", "json"]
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    findings = [f for lf in payload["lockfiles"] for f in lf["findings"]]
    ids = {f["id"] for f in findings}
    assert "EXTRA-2022-0001" in ids, f"ctx not flagged: {ids}"
    assert "EXTRA-2022-0003" in ids, f"torchtriton not flagged: {ids}"


def test_feed_spans_multiple_ecosystems() -> None:
    """Sanity: prove the backfill is genuinely multi-ecosystem so the
    project does not look like an npm-only / SAP-only tool."""
    campaigns = _campaigns()
    ecosystems = set()
    for c in campaigns.values():
        ecosystems.add(c["ecosystem"])
        for pkg in c.get("packages", []):
            if "ecosystem" in pkg:
                ecosystems.add(pkg["ecosystem"])
    assert "npm" in ecosystems
    assert "PyPI" in ecosystems
    assert len(ecosystems) >= 2, f"feed is single-ecosystem: {ecosystems}"
