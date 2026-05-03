"""Tests for the extras (campaign) feed loader + matcher."""

from __future__ import annotations

import json
from pathlib import Path

from pwned_deps.advisory.extras import ExtrasFeed
from pwned_deps.parsers.base import Ecosystem, Lockfile, Package


def _campaign_dict(
    *,
    id_: str,
    name: str,
    ecosystem: str,
    packages: list[dict],
) -> dict:
    return {
        "id": id_,
        "name": name,
        "summary": f"{name} summary",
        "references": ["https://example.test/research"],
        "ecosystem": ecosystem,
        "packages": packages,
        "exposure_window": ["2026-04-29T13:00:00Z", "2026-04-29T17:00:00Z"],
        "actions": ["Rotate npm tokens"],
    }


def _lockfile(*pkgs: Package, ecosystem: Ecosystem = Ecosystem.NPM) -> Lockfile:
    return Lockfile(path=Path("(test)"), ecosystem=ecosystem, packages=tuple(pkgs))


def _pkg(name: str, version: str, ecosystem: Ecosystem = Ecosystem.NPM) -> Package:
    return Package(name=name, version=version, ecosystem=ecosystem, lockfile_path="(test)")


def test_exact_version_match_in_npm_campaign() -> None:
    feed = ExtrasFeed.from_dict(
        {
            "version": 1,
            "campaigns": [
                _campaign_dict(
                    id_="EXTRA-2026-0001",
                    name="Mini Shai-Hulud (SAP CAP)",
                    ecosystem="npm",
                    packages=[{"name": "@cap-js/foo", "versions": ["1.2.3"]}],
                )
            ],
        }
    )
    lf = _lockfile(_pkg("@cap-js/foo", "1.2.3"), _pkg("benign-pkg", "9.9.9"))

    matches = feed.find_matches(lf)
    assert len(matches) == 1
    hit = matches[0]
    assert hit.package.name == "@cap-js/foo"
    assert hit.campaign_name == "Mini Shai-Hulud (SAP CAP)"
    assert hit.advisory.id == "EXTRA-2026-0001"
    assert hit.advisory.is_malicious


def test_no_false_positive_on_benign_package() -> None:
    feed = ExtrasFeed.from_dict(
        {
            "version": 1,
            "campaigns": [
                _campaign_dict(
                    id_="EXTRA-2026-0002",
                    name="Imaginary",
                    ecosystem="npm",
                    packages=[{"name": "compromised", "versions": ["1.0.0"]}],
                )
            ],
        }
    )
    lf = _lockfile(_pkg("totally-fine", "1.0.0"))
    assert feed.find_matches(lf) == []


def test_range_match_inclusive_lower_exclusive_upper() -> None:
    feed = ExtrasFeed.from_dict(
        {
            "version": 1,
            "campaigns": [
                _campaign_dict(
                    id_="EXTRA-2026-0003",
                    name="lodash window",
                    ecosystem="npm",
                    packages=[{"name": "lodash", "versions": [">=4.17.0,<4.17.21"]}],
                )
            ],
        }
    )
    inside = _lockfile(_pkg("lodash", "4.17.15"))
    boundary = _lockfile(_pkg("lodash", "4.17.21"))
    outside = _lockfile(_pkg("lodash", "4.17.22"))

    assert len(feed.find_matches(inside)) == 1
    assert feed.find_matches(boundary) == []
    assert feed.find_matches(outside) == []


def test_user_supplied_feed_path_is_loaded(tmp_path: Path) -> None:
    user_feed = tmp_path / "extras-user.json"
    user_feed.write_text(
        json.dumps(
            {
                "version": 1,
                "campaigns": [
                    _campaign_dict(
                        id_="EXTRA-USER-0001",
                        name="user-only",
                        ecosystem="npm",
                        packages=[{"name": "u-pkg", "versions": ["1.0.0"]}],
                    )
                ],
            }
        ),
        encoding="utf-8",
    )

    feed = ExtrasFeed.from_bundled(user_paths=[user_feed])
    lf = _lockfile(_pkg("u-pkg", "1.0.0"))

    hits = feed.find_matches(lf)
    assert len(hits) == 1
    assert hits[0].advisory.id == "EXTRA-USER-0001"


def test_malformed_user_feed_silently_skipped(tmp_path: Path) -> None:
    bad = tmp_path / "junk.json"
    bad.write_text("not json", encoding="utf-8")
    feed = ExtrasFeed.from_bundled(user_paths=[bad])
    lf = _lockfile(_pkg("anything", "1.0.0"))
    # No campaigns to match against, no crash.
    assert feed.find_matches(lf) == []


def test_version_unspecified_packages_are_skipped() -> None:
    feed = ExtrasFeed.from_dict(
        {
            "version": 1,
            "campaigns": [
                _campaign_dict(
                    id_="EXTRA-2026-0004",
                    name="loose",
                    ecosystem="npm",
                    packages=[{"name": "loose-dep", "versions": ["1.0.0"]}],
                )
            ],
        }
    )
    pkg = Package(
        name="loose-dep",
        version="",
        ecosystem=Ecosystem.NPM,
        lockfile_path="(test)",
        version_unspecified=True,
    )
    assert feed.find_matches(_lockfile(pkg)) == []
