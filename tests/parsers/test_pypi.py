"""Tests for the Python (PyPI) lockfile parsers."""

from __future__ import annotations

from pathlib import Path

import pytest

from pwned_deps.parsers import Ecosystem, ParseError
from pwned_deps.parsers import pypi as pypi_parser

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "pypi"


def _by_name(packages: tuple) -> dict[str, str]:
    return {pkg.name: pkg.version for pkg in packages}


def test_requirements_txt_extracts_pinned_packages() -> None:
    lf = pypi_parser.parse(FIXTURES / "requirements.txt")

    assert lf.ecosystem is Ecosystem.PYPI

    pinned = {p.name: p.version for p in lf.packages if not p.version_unspecified}
    # Names canonicalised to PEP 503 form: lowercase, runs of [-_.]→'-'.
    assert pinned["requests"] == "2.32.3"
    assert pinned["django"] == "5.0.7"
    assert pinned["pyyaml"] == "6.0.2"
    assert pinned["flask"] == "3.0.3"  # extras `[async]` stripped from the name
    assert pinned["cryptography"] == "43.0.1"  # backslash continuation tolerated


def test_requirements_txt_loose_pins_marked_unspecified() -> None:
    lf = pypi_parser.parse(FIXTURES / "requirements.txt")
    loose = {p.name for p in lf.packages if p.version_unspecified}
    assert "numpy" in loose
    assert "sqlalchemy" in loose
    assert "typing-extensions" in loose


def test_requirements_txt_skips_editable_vcs_local_and_includes() -> None:
    lf = pypi_parser.parse(FIXTURES / "requirements.txt")
    names = [p.name for p in lf.packages]
    # Should not pick up editables/VCS/local-paths/-r as "packages"
    for forbidden in ("foo", "mylib", "local-pkg", "dev-requirements"):
        assert forbidden not in names, forbidden


def test_pipfile_lock_combines_default_and_develop_sections() -> None:
    lf = pypi_parser.parse(FIXTURES / "Pipfile.lock")

    by_name = _by_name(lf.packages)
    assert by_name["requests"] == "2.32.3"
    assert by_name["urllib3"] == "2.2.3"
    assert by_name["pytest"] == "8.3.3"
    # `==` prefix stripped from Pipfile-stored versions
    assert all(not p.version.startswith("==") for p in lf.packages)


def test_poetry_lock_extracts_packages_array() -> None:
    lf = pypi_parser.parse(FIXTURES / "poetry.lock")

    by_name = _by_name(lf.packages)
    # Names canonicalised: "Rich" → "rich"
    assert by_name["requests"] == "2.32.3"
    assert by_name["click"] == "8.1.7"
    assert by_name["rich"] == "13.7.1"


def test_uv_lock_extracts_packages_skipping_workspace_roots() -> None:
    lf = pypi_parser.parse(FIXTURES / "uv.lock")

    by_name = _by_name(lf.packages)
    assert by_name["httpx"] == "0.27.2"
    assert by_name["click"] == "8.1.7"
    # Workspace virtual / editable entries (no version, or local source)
    # must be skipped.
    assert "demo-app" not in by_name
    assert "workspace-only-pkg" not in by_name


def test_unrecognised_filename_raises_parse_error(tmp_path: Path) -> None:
    weird = tmp_path / "mystery.unknown"
    weird.write_text("nothing", encoding="utf-8")

    with pytest.raises(ParseError) as excinfo:
        pypi_parser.parse(weird)

    assert "unrecognised" in str(excinfo.value).lower()


def test_corrupted_pipfile_lock_raises_parse_error(tmp_path: Path) -> None:
    bad = tmp_path / "Pipfile.lock"
    bad.write_text("{not json", encoding="utf-8")

    with pytest.raises(ParseError) as excinfo:
        pypi_parser.parse(bad)

    assert "not valid JSON" in str(excinfo.value)


def test_corrupted_poetry_lock_raises_parse_error(tmp_path: Path) -> None:
    bad = tmp_path / "poetry.lock"
    bad.write_text("[[package\nname = oops", encoding="utf-8")

    with pytest.raises(ParseError) as excinfo:
        pypi_parser.parse(bad)

    assert "TOML" in str(excinfo.value)
