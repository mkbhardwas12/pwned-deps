"""Tests for the npm lockfile parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from pwned_deps.parsers import Ecosystem, ParseError
from pwned_deps.parsers import npm as npm_parser

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "npm"


def _by_name(packages: tuple) -> dict[str, str]:
    """Convenience: collapse packages to {name: version} dropping
    duplicates that resolve to the same version (real-world v1 trees
    can list the same dep at multiple depths)."""

    out: dict[str, str] = {}
    for pkg in packages:
        out.setdefault(pkg.name, pkg.version)
    return out


def test_parses_v1_lockfile_with_nested_dependencies() -> None:
    lf = npm_parser.parse(FIXTURES / "v1.lock.json")

    assert lf.ecosystem is Ecosystem.NPM
    by_name = _by_name(lf.packages)
    assert by_name["lodash"] == "4.17.15"
    assert by_name["express"] == "4.17.1"
    # nested transitive picked up too
    assert by_name["qs"] == "6.7.0"
    # transitive `qs` should record its parent chain
    qs = next(p for p in lf.packages if p.name == "qs")
    assert qs.parents == ("express",)


def test_parses_v2_lockfile_prefers_packages_block_no_double_count() -> None:
    lf = npm_parser.parse(FIXTURES / "v2.lock.json")

    # The v2 fixture intentionally lists each dep in BOTH `packages`
    # (preferred) and the legacy `dependencies` block. We must not
    # double-count.
    names = [p.name for p in lf.packages]
    assert names.count("lodash") == 1
    assert names.count("express") == 1
    assert names.count("@cap-js/cds") == 1

    by_name = _by_name(lf.packages)
    assert by_name["lodash"] == "4.17.21"
    assert by_name["express"] == "4.18.2"
    # Transitive nested under express
    assert by_name["qs"] == "6.11.0"
    # Workspace link entries (link: true) are skipped
    assert "workspace-link-pkg" not in by_name


def test_parses_v3_lockfile_packages_only() -> None:
    lf = npm_parser.parse(FIXTURES / "v3.lock.json")

    by_name = _by_name(lf.packages)
    assert by_name["react"] == "18.2.0"
    assert by_name["@types/node"] == "20.0.0"


def test_scoped_package_keeps_leading_at() -> None:
    lf = npm_parser.parse(FIXTURES / "v2.lock.json")

    assert any(p.name == "@cap-js/cds" and p.version == "1.2.3" for p in lf.packages)


def test_empty_packages_block_returns_empty_lockfile() -> None:
    lf = npm_parser.parse(FIXTURES / "empty.lock.json")

    assert lf.packages == ()


def test_missing_file_raises_parse_error_with_friendly_message() -> None:
    with pytest.raises(ParseError) as excinfo:
        npm_parser.parse(FIXTURES / "definitely-not-here.json")

    assert "not found" in str(excinfo.value)


def test_corrupted_json_raises_parse_error(tmp_path: Path) -> None:
    bad = tmp_path / "package-lock.json"
    bad.write_text("{not valid json", encoding="utf-8")

    with pytest.raises(ParseError) as excinfo:
        npm_parser.parse(bad)

    assert "not valid JSON" in str(excinfo.value)


def test_unsupported_lockfile_version_raises_parse_error(tmp_path: Path) -> None:
    weird = tmp_path / "package-lock.json"
    weird.write_text('{"name": "x", "version": "0.0.0", "lockfileVersion": 99}', encoding="utf-8")

    with pytest.raises(ParseError) as excinfo:
        npm_parser.parse(weird)

    assert "lockfileVersion" in str(excinfo.value)
