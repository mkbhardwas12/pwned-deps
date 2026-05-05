"""Smoke tests.

These verify the package imports and exposes a version. Behavioural
tests live alongside their respective modules.
"""

import re

import pwned_deps


def test_package_imports() -> None:
    assert pwned_deps is not None


def test_version_is_pep440_string() -> None:
    version = pwned_deps.__version__
    assert isinstance(version, str)
    assert re.fullmatch(r"\d+\.\d+\.\d+(?:[-.+][0-9A-Za-z.+-]+)?", version), version
