"""Tests for the secondary ecosystem parsers (Cargo, Go, pnpm, yarn, Maven, RubyGems).

Each parser gets at least 3 happy/edge-case tests on hand-crafted INERT
fixtures committed under ``tests/fixtures/<ecosystem>/``. We never run
the underlying package manager.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pwned_deps.parsers import (
    Ecosystem,
    ParseError,
    cargo,
    gem,
    go,
    maven,
    pnpm,
    yarn,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


# ---------------------------------------------------------------------------
# Cargo
# ---------------------------------------------------------------------------


def test_cargo_extracts_name_version_pairs() -> None:
    lf = cargo.parse(FIXTURES / "cargo" / "Cargo.lock")
    by_name = {p.name: p.version for p in lf.packages}
    assert by_name["serde"] == "1.0.219"
    assert by_name["serde_json"] == "1.0.140"
    assert by_name["demo"] == "0.1.0"
    # entry without a version must be dropped silently
    assert "broken-entry" not in by_name
    assert lf.ecosystem is Ecosystem.CRATES


def test_cargo_corrupted_toml_raises_parse_error(tmp_path: Path) -> None:
    bad = tmp_path / "Cargo.lock"
    bad.write_text("[[package\nname = oops", encoding="utf-8")
    with pytest.raises(ParseError) as excinfo:
        cargo.parse(bad)
    assert "TOML" in str(excinfo.value)


def test_cargo_missing_file_raises_parse_error(tmp_path: Path) -> None:
    with pytest.raises(ParseError):
        cargo.parse(tmp_path / "absent.lock")


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------


def test_go_dedups_module_and_gomod_lines() -> None:
    lf = go.parse(FIXTURES / "go" / "go.sum")
    pairs = {(p.name, p.version) for p in lf.packages}
    assert ("example.com/foo", "v1.2.3") in pairs
    assert ("example.com/bar", "v0.5.0") in pairs
    assert ("github.com/stretchr/testify", "v1.9.0") in pairs
    # 3 unique modules, not 6 (two lines per module)
    assert len(pairs) == 3
    assert lf.ecosystem is Ecosystem.GO


def test_go_empty_file_returns_empty_lockfile(tmp_path: Path) -> None:
    empty = tmp_path / "go.sum"
    empty.write_text("", encoding="utf-8")
    lf = go.parse(empty)
    assert lf.packages == ()


def test_go_missing_file_raises_parse_error(tmp_path: Path) -> None:
    with pytest.raises(ParseError):
        go.parse(tmp_path / "nope.sum")


# ---------------------------------------------------------------------------
# pnpm
# ---------------------------------------------------------------------------


def test_pnpm_handles_both_v5_and_v6_key_styles() -> None:
    lf = pnpm.parse(FIXTURES / "pnpm" / "pnpm-lock.yaml")
    by_name = {p.name: p.version for p in lf.packages}
    # /lodash/4.17.21 (v5 style) -> lodash 4.17.21
    assert by_name["lodash"] == "4.17.21"
    # /@cap-js/sqlite/2.2.2 (v5 style scoped) -> @cap-js/sqlite 2.2.2
    assert by_name["@cap-js/sqlite"] == "2.2.2"
    # react@18.2.0 (v6 style) -> react 18.2.0; the peer-dep duplicate
    # ('react@18.2.0(peer@4.5.6)') must dedup with the first one.
    assert by_name["react"] == "18.2.0"
    names = [p.name for p in lf.packages]
    assert names.count("react") == 1


def test_pnpm_corrupted_yaml_raises_parse_error(tmp_path: Path) -> None:
    bad = tmp_path / "pnpm-lock.yaml"
    bad.write_text("packages:\n  - [oops, unbalanced\n", encoding="utf-8")
    with pytest.raises(ParseError) as excinfo:
        pnpm.parse(bad)
    assert "YAML" in str(excinfo.value)


def test_pnpm_missing_file_raises_parse_error(tmp_path: Path) -> None:
    with pytest.raises(ParseError):
        pnpm.parse(tmp_path / "absent.yaml")


# ---------------------------------------------------------------------------
# yarn (v1 + Berry)
# ---------------------------------------------------------------------------


def test_yarn_v1_extracts_block_versions() -> None:
    lf = yarn.parse(FIXTURES / "yarn" / "yarn.v1.lock")
    by_name = {p.name: p.version for p in lf.packages}
    assert by_name["lodash"] == "4.17.21"
    assert by_name["@cap-js/sqlite"] == "2.2.2"
    assert by_name["express"] == "4.18.2"
    assert lf.ecosystem is Ecosystem.NPM


def test_yarn_berry_extracts_yaml_keys() -> None:
    lf = yarn.parse(FIXTURES / "yarn" / "yarn.berry.lock")
    by_name = {p.name: p.version for p in lf.packages}
    assert by_name["lodash"] == "4.17.21"
    assert by_name["@cap-js/sqlite"] == "2.2.2"
    # workspace local entry — captured (won't match OSV, but recorded)
    assert by_name["my-app"] == "0.0.0-use.local"


def test_yarn_missing_file_raises_parse_error(tmp_path: Path) -> None:
    with pytest.raises(ParseError):
        yarn.parse(tmp_path / "yarn.lock")


# ---------------------------------------------------------------------------
# Maven
# ---------------------------------------------------------------------------


def test_maven_extracts_dependencies_and_dependency_management() -> None:
    lf = maven.parse(FIXTURES / "maven" / "pom.xml")
    pairs = {(p.name, p.version, p.version_unspecified) for p in lf.packages}
    assert ("org.apache.commons:commons-text", "1.10.0", False) in pairs
    assert ("com.fasterxml.jackson.core:jackson-databind", "2.17.2", False) in pairs
    # ${spring.version} property: surfaced as version_unspecified=True
    assert ("org.springframework:spring-core", "", True) in pairs
    assert lf.ecosystem is Ecosystem.MAVEN


def test_maven_corrupted_xml_raises_parse_error(tmp_path: Path) -> None:
    bad = tmp_path / "pom.xml"
    bad.write_text("<project>\n<unclosed", encoding="utf-8")
    with pytest.raises(ParseError) as excinfo:
        maven.parse(bad)
    assert "XML" in str(excinfo.value)


def test_maven_missing_file_raises_parse_error(tmp_path: Path) -> None:
    with pytest.raises(ParseError):
        maven.parse(tmp_path / "absent.xml")


# ---------------------------------------------------------------------------
# Gemfile.lock
# ---------------------------------------------------------------------------


def test_gem_parses_gem_specs_block() -> None:
    lf = gem.parse(FIXTURES / "gem" / "Gemfile.lock")
    by_name = {p.name: p.version for p in lf.packages}
    assert by_name["rake"] == "13.2.1"
    assert by_name["rspec-core"] == "3.13.0"
    assert by_name["rspec-support"] == "3.13.1"
    assert by_name["nokogiri"] == "1.16.7"
    assert by_name["racc"] == "1.8.1"
    assert lf.ecosystem is Ecosystem.RUBYGEMS


def test_gem_ignores_dependency_lines_under_specs() -> None:
    lf = gem.parse(FIXTURES / "gem" / "Gemfile.lock")
    # `rspec-support (~> 3.13.0)` appears under rspec-core's specs as
    # a *dependency line* (6-space indent), not an actual gem entry.
    # That entry should NOT win against the real
    # `rspec-support (3.13.1)` entry — rspec-support must come back as
    # 3.13.1 (the concrete pin), not "~> 3.13.0".
    by_name = {p.name: p.version for p in lf.packages}
    assert by_name["rspec-support"] == "3.13.1"


def test_gem_missing_file_raises_parse_error(tmp_path: Path) -> None:
    with pytest.raises(ParseError):
        gem.parse(tmp_path / "Gemfile.lock")
