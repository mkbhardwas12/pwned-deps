"""Tests for the PR-comment renderer (tools/pr_comment.py)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "pwned_deps_pr_comment_under_test",
    Path(__file__).resolve().parent.parent / "tools" / "pr_comment.py",
)
assert _SPEC is not None and _SPEC.loader is not None
_MOD = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MOD)
render = _MOD.render
MARKER = _MOD.MARKER


def test_clean_scan_renders_green_comment_with_marker_and_zero_exit() -> None:
    body, code = render(
        {
            "schema_version": "1.0",
            "tool": {"name": "pwned-deps", "version": "0.1.0"},
            "lockfiles": [
                {"path": "package-lock.json", "ecosystem": "npm", "findings": []}
            ],
            "summary": {
                "total_packages": 42,
                "compromised": 0,
                "high_critical": 0,
                "other": 0,
            },
        }
    )
    assert code == 0
    assert body.startswith(MARKER)
    assert "Clean" in body
    assert "42 pinned" in body
    # Clean comments don't include the findings table.
    assert "| Severity |" not in body


def test_compromised_scan_renders_red_comment_and_exit_one() -> None:
    body, code = render(
        {
            "schema_version": "1.0",
            "tool": {"name": "pwned-deps", "version": "0.1.0"},
            "lockfiles": [
                {
                    "path": "package-lock.json",
                    "ecosystem": "npm",
                    "findings": [
                        {
                            "id": "EXTRA-2018-0001",
                            "package": "event-stream",
                            "version": "3.3.6",
                            "ecosystem": "npm",
                            "severity": "CRITICAL",
                            "summary": "credential stealer",
                            "references": ["https://example.test/disclosure"],
                            "is_malicious": True,
                            "campaign_name": "event-stream / flatmap-stream",
                        }
                    ],
                }
            ],
            "summary": {
                "total_packages": 100,
                "compromised": 1,
                "high_critical": 0,
                "other": 0,
            },
        }
    )
    assert code == 1
    assert body.startswith(MARKER)
    assert "compromised" in body.lower()
    assert "MALICIOUS" in body
    assert "event-stream" in body
    assert "EXTRA-2018-0001" in body
    assert "event-stream / flatmap-stream" in body
    # Reference link rendered.
    assert "https://example.test/disclosure" in body


def test_high_only_scan_exits_two() -> None:
    body, code = render(
        {
            "schema_version": "1.0",
            "tool": {"name": "pwned-deps", "version": "0.1.0"},
            "lockfiles": [
                {
                    "path": "requirements.txt",
                    "ecosystem": "PyPI",
                    "findings": [
                        {
                            "id": "GHSA-xxxx",
                            "package": "requests",
                            "version": "2.10.0",
                            "ecosystem": "PyPI",
                            "severity": "HIGH",
                            "summary": "x",
                            "references": [],
                            "is_malicious": False,
                            "campaign_name": None,
                        }
                    ],
                }
            ],
            "summary": {
                "total_packages": 5,
                "compromised": 0,
                "high_critical": 1,
                "other": 0,
            },
        }
    )
    assert code == 2
    assert "HIGH/CRITICAL" in body
    assert "GHSA-xxxx" in body
