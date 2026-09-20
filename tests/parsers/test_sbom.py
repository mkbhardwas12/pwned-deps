"""Tests for the CycloneDX / SPDX SBOM parser (INERT hand-crafted fixtures)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pwned_deps.cli import _discover_targets
from pwned_deps.parsers import Ecosystem, ParseError, npm, sbom

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "sbom"


def test_cyclonedx_maps_purl_types_to_ecosystems() -> None:
    lf = sbom.parse(FIXTURES / "app.cdx.json")
    found = {(p.name, p.version, p.ecosystem) for p in lf.packages}
    assert ("chalk", "5.6.1", Ecosystem.NPM) in found
    assert ("@babel/core", "7.24.0", Ecosystem.NPM) in found  # nested + percent-encoded
    assert ("jinja2", "3.1.2", Ecosystem.PYPI) in found  # PEP 503 canonical
    assert ("serde", "1.0.219", Ecosystem.CRATES) in found
    assert ("github.com/gin-gonic/gin", "v1.9.1", Ecosystem.GO) in found
    assert ("org.apache.commons:commons-lang3", "3.12.0", Ecosystem.MAVEN) in found
    assert ("rack", "3.0.8", Ecosystem.RUBYGEMS) in found
    assert lf.ecosystem is Ecosystem.NPM  # header = most common ecosystem


def test_cyclonedx_skips_what_it_cannot_place_but_keeps_unpinned_entries() -> None:
    packages = sbom.parse(FIXTURES / "app.cdx.json").packages
    names = [p.name for p in packages]
    assert "Newtonsoft.Json" not in names  # purl type we don't map
    assert "debian" not in names  # component with no purl
    assert "demo-app" not in names  # metadata.component is the artifact itself
    assert names.count("chalk") == 1  # duplicate component reported once
    # A purl with no version is unpinned, never silently dropped.
    (left_pad,) = [p for p in packages if p.name == "left-pad"]
    assert left_pad.version == "" and left_pad.version_unspecified is True


def test_spdx_reads_purl_external_refs() -> None:
    lf = sbom.parse(FIXTURES / "app.spdx.json")
    found = {(p.name, p.version, p.ecosystem) for p in lf.packages}
    assert found == {("chalk", "5.6.1", Ecosystem.NPM), ("jinja2", "3.1.2", Ecosystem.PYPI)}


def test_composer_purl_maps_to_packagist(tmp_path: Path) -> None:
    path = tmp_path / "bom.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [{"purl": "pkg:composer/monolog/monolog@v3.5.0"}],
            }
        ),
        encoding="utf-8",
    )
    (pkg,) = sbom.parse(path).packages
    assert (pkg.name, pkg.version, pkg.ecosystem) == ("monolog/monolog", "v3.5.0", Ecosystem.PACKAGIST)


def test_non_sbom_malformed_or_missing_json_raises_parse_error(tmp_path: Path) -> None:
    path = tmp_path / "bom.json"
    path.write_text('{"lockfileVersion": 3}', encoding="utf-8")
    with pytest.raises(ParseError, match="bomFormat"):
        sbom.parse(path)
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ParseError):
        sbom.parse(path)
    with pytest.raises(ParseError):
        sbom.parse(tmp_path / "absent.cdx.json")


@pytest.mark.parametrize("doc", [  # unmapped ecosystem, then no purl at all
    {"bomFormat": "CycloneDX", "components": [{"purl": "pkg:nuget/Serilog@3.1.1"}]},
    {"spdxVersion": "SPDX-2.3", "packages": [{"name": "blob", "versionInfo": "1.0"}]},
])
def test_uncheckable_document_raises_rather_than_reporting_clean(tmp_path: Path, doc: dict) -> None:
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(ParseError, match="no component"):
        sbom.parse(path)


@pytest.mark.parametrize("name", ["bom.json", "app.cdx.json", "app.spdx.json", "syft-out.json"])
def test_cli_routes_sbom_documents_to_the_sbom_parser(tmp_path: Path, name: str) -> None:
    path = tmp_path / name
    path.write_text((FIXTURES / "app.cdx.json").read_text(encoding="utf-8"), encoding="utf-8")
    assert _discover_targets(path) == [(path, sbom.parse)]
    lock = tmp_path / "package-lock.json"
    lock.write_text('{"lockfileVersion": 3}', encoding="utf-8")
    assert _discover_targets(lock) == [(lock, npm.parse)]
