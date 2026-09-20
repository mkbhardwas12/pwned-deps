"""Regression tests for parser false negatives fixed in 0.1.1.

Every case here is a real-world lockfile shape that previously produced
a wrong ``(name, version)`` tuple — so the OSV / extras lookup silently
missed the package. Inputs are inert, hand-written fixtures.
"""

from __future__ import annotations

import json
from pathlib import Path

from pwned_deps.parsers import gem, go, npm, pypi, yarn


def _names_versions(lf) -> dict[str, str]:
    return {p.name: p.version for p in lf.packages}


# ---------------------------------------------------------------------------
# npm — aliased installs
# ---------------------------------------------------------------------------


def test_npm_v3_alias_uses_real_registry_name(tmp_path: Path) -> None:
    """`npm i safe-name@npm:evil-pkg@1.0.0` stores the alias in the key
    and the real name under ``name``. The lookup must use the real name."""
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "app"},
                    "node_modules/safe-name": {
                        "name": "evil-pkg",
                        "version": "1.0.0",
                    },
                    "node_modules/plain": {"version": "2.0.0"},
                },
            }
        ),
        encoding="utf-8",
    )
    got = _names_versions(npm.parse(lock))
    assert got == {"evil-pkg": "1.0.0", "plain": "2.0.0"}
    assert "safe-name" not in got


def test_npm_v1_alias_version_is_unwrapped(tmp_path: Path) -> None:
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        json.dumps(
            {
                "lockfileVersion": 1,
                "dependencies": {
                    "safe-name": {"version": "npm:evil-pkg@1.0.0"},
                    "scoped-alias": {"version": "npm:@scope/real@3.2.1"},
                    "plain": {"version": "2.0.0"},
                },
            }
        ),
        encoding="utf-8",
    )
    got = _names_versions(npm.parse(lock))
    assert got == {"evil-pkg": "1.0.0", "@scope/real": "3.2.1", "plain": "2.0.0"}


# ---------------------------------------------------------------------------
# yarn — aliases and Berry protocol wrappers
# ---------------------------------------------------------------------------


def test_yarn_v1_alias_uses_real_registry_name(tmp_path: Path) -> None:
    lock = tmp_path / "yarn.lock"
    lock.write_text(
        '# yarn lockfile v1\n\n'
        '"safe-name@npm:evil-pkg@^1.0.0":\n'
        '  version "1.0.0"\n'
        '  resolved "https://registry.yarnpkg.com/evil-pkg/-/evil-pkg-1.0.0.tgz#abc"\n\n'
        'lodash@^4.17.21:\n'
        '  version "4.17.21"\n',
        encoding="utf-8",
    )
    got = _names_versions(yarn.parse(lock))
    assert got == {"evil-pkg": "1.0.0", "lodash": "4.17.21"}


def test_yarn_berry_patch_protocol_and_alias_are_unwrapped(tmp_path: Path) -> None:
    lock = tmp_path / "yarn.lock"
    lock.write_text(
        "__metadata:\n"
        "  version: 6\n\n"
        '"patch:lodash@npm%3A4.17.21#./.yarn/patches/lodash.patch":\n'
        "  version: 4.17.21\n"
        '  resolution: "lodash@patch:lodash@npm%3A4.17.21#./.yarn/patches/lodash.patch"\n\n'
        '"patch:@scope/pkg@npm%3A2.0.0#./p.patch":\n'
        "  version: 2.0.0\n\n"
        '"safe-name@npm:evil-pkg@^1.0.0":\n'
        "  version: 1.0.0\n\n"
        '"plain@npm:^3.0.0":\n'
        "  version: 3.1.0\n\n"
        '"my-app@workspace:.":\n'
        "  version: 0.0.0-use.local\n",
        encoding="utf-8",
    )
    got = _names_versions(yarn.parse(lock))
    assert got == {
        "lodash": "4.17.21",
        "@scope/pkg": "2.0.0",
        "evil-pkg": "1.0.0",
        "plain": "3.1.0",
    }
    assert "my-app" not in got


# ---------------------------------------------------------------------------
# RubyGems — platform-specific builds
# ---------------------------------------------------------------------------


def test_gem_platform_suffix_is_stripped(tmp_path: Path) -> None:
    lock = tmp_path / "Gemfile.lock"
    lock.write_text(
        "GEM\n"
        "  remote: https://rubygems.org/\n"
        "  specs:\n"
        "    nokogiri (1.15.0-x86_64-linux)\n"
        "    nokogiri (1.15.0-arm64-darwin)\n"
        "    pg (1.5.4-x64-mingw-ucrt)\n"
        "    jruby-openssl (0.14.0-java)\n"
        "    rake (13.2.1)\n"
        "    rc-pre (2.0.0.pre1)\n",
        encoding="utf-8",
    )
    lf = gem.parse(lock)
    pairs = {(p.name, p.version) for p in lf.packages}
    assert pairs == {
        ("nokogiri", "1.15.0"),
        ("pg", "1.5.4"),
        ("jruby-openssl", "0.14.0"),
        ("rake", "13.2.1"),
        ("rc-pre", "2.0.0.pre1"),
    }


# ---------------------------------------------------------------------------
# Go — degenerate lines
# ---------------------------------------------------------------------------


def test_go_sum_empty_version_after_gomod_strip_is_dropped(tmp_path: Path) -> None:
    lock = tmp_path / "go.sum"
    lock.write_text(
        "example.com/broken /go.mod h1:abc=\n"
        "example.com/ok v1.2.3 h1:xyz=\n"
        "example.com/ok v1.2.3/go.mod h1:xyz=\n",
        encoding="utf-8",
    )
    got = _names_versions(go.parse(lock))
    assert got == {"example.com/ok": "v1.2.3"}


# ---------------------------------------------------------------------------
# PyPI — requirements.txt shapes that broke the pin
# ---------------------------------------------------------------------------


def test_requirements_hash_on_same_line_keeps_exact_version(tmp_path: Path) -> None:
    reqs = tmp_path / "requirements.txt"
    reqs.write_text(
        "requests==2.31.0 --hash=sha256:aaaa --hash=sha256:bbbb\n",
        encoding="utf-8",
    )
    got = _names_versions(pypi.parse(reqs))
    assert got == {"requests": "2.31.0"}


def test_requirements_marker_with_double_equals_is_not_a_pin(tmp_path: Path) -> None:
    reqs = tmp_path / "requirements.txt"
    reqs.write_text(
        'requests>=2; python_version == "3.8"\n'
        'urllib3==1.26.0; sys_platform == "win32"\n',
        encoding="utf-8",
    )
    lf = pypi.parse(reqs)
    by_name = {p.name: p for p in lf.packages}
    assert by_name["requests"].version_unspecified is True
    assert by_name["urllib3"].version == "1.26.0"
    assert by_name["urllib3"].version_unspecified is False


def test_requirements_wildcard_and_arbitrary_equality(tmp_path: Path) -> None:
    reqs = tmp_path / "requirements.txt"
    reqs.write_text(
        "django==4.2.*\n"
        "legacy===1.0-custom\n"
        "pinned-with-upper==1.5.0,<2\n",
        encoding="utf-8",
    )
    lf = pypi.parse(reqs)
    by_name = {p.name: p for p in lf.packages}
    assert by_name["django"].version_unspecified is True
    assert by_name["legacy"].version == "1.0-custom"
    assert by_name["pinned-with-upper"].version == "1.5.0"
