"""Tests for the minimal range matcher used by extras campaigns."""

from __future__ import annotations

import pytest

from pwned_deps.advisory.version_match import matches


@pytest.mark.parametrize(
    ("version", "spec", "expected"),
    [
        # Exact match
        ("1.2.3", "1.2.3", True),
        ("1.2.4", "1.2.3", False),
        # `==` shorthand
        ("1.2.3", "==1.2.3", True),
        # AND-joined ranges
        ("4.17.15", ">=4.17.0,<4.17.21", True),
        ("4.17.21", ">=4.17.0,<4.17.21", False),
        ("4.17.22", ">=4.17.0,<4.17.21", False),
        ("4.16.0", ">=4.17.0,<4.17.21", False),
        # Inequality
        ("1.4.2", "<2.0,!=1.4.2", False),
        ("1.5.0", "<2.0,!=1.4.2", True),
        # Greater-or-equal
        ("2.0.0", ">=2.0", True),
        ("1.9.9", ">=2.0", False),
        # Garbage doesn't crash, just no-match
        ("not-a-version", "1.2.3", False),
        ("1.2.3", "garbage-spec", False),
    ],
)
def test_npm_style_ranges(version: str, spec: str, expected: bool) -> None:
    assert matches(version, spec, ecosystem="npm") is expected


def test_pypi_uses_pep440() -> None:
    # PEP 440 specials: 1.0.0a1 is a pre-release of 1.0.0
    assert matches("1.0.0a1", "<1.0.0", ecosystem="PyPI") is True
    assert matches("1.0.0", ">=1.0.0a1", ecosystem="PyPI") is True
    assert matches("1.2.3", "==1.2.3", ecosystem="PyPI") is True


def test_npm_prerelease_sorts_below_release() -> None:
    assert matches("1.0.0-rc.1", "<1.0.0", ecosystem="npm") is True
    assert matches("1.0.0", ">1.0.0-rc.1", ecosystem="npm") is True


def test_empty_version_or_spec_returns_false() -> None:
    assert matches("", "1.2.3", ecosystem="npm") is False
    assert matches("1.2.3", "", ecosystem="npm") is False
