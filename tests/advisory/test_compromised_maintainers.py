"""Tests for the ``compromised_maintainers`` schema field.

When a maintainer's account is hijacked, you don't yet know which
specific *versions* are bad — just that everything they published
during the compromise window is suspect. This is the classic
'first-30-minutes' problem: get a HIGH-severity warning out
immediately, even before specific MAL-* records exist for each
version.
"""

from __future__ import annotations

from pathlib import Path

from pwned_deps.advisory.extras import ExtrasFeed
from pwned_deps.parsers.base import Ecosystem, Lockfile, Package


def _pkg(name: str, version: str, eco: Ecosystem = Ecosystem.NPM) -> Package:
    return Package(
        name=name, version=version, ecosystem=eco, lockfile_path="(test)"
    )


def _lockfile(*pkgs: Package) -> Lockfile:
    return Lockfile(
        path=Path("(test)"), ecosystem=Ecosystem.NPM, packages=tuple(pkgs)
    )


def test_compromised_maintainer_emits_suspect_finding() -> None:
    """A package whose name appears in compromised_maintainers[].packages
    must be flagged as a SUSPECT (is_suspect=True) hit."""
    feed = ExtrasFeed.from_dict(
        {
            "version": 1,
            "campaigns": [
                {
                    "id": "EXTRA-2026-9001",
                    "name": "Hypothetical maintainer hijack",
                    "summary": "Test campaign for compromised_maintainers schema.",
                    "references": ["https://example.test/disclosure"],
                    "ecosystem": "npm",
                    "packages": [],
                    "compromised_maintainers": [
                        {
                            "name": "alice",
                            "registry_url": "https://www.npmjs.com/~alice",
                            "compromised_after": "2026-05-01T00:00:00Z",
                            "compromised_until": "2026-05-02T12:00:00Z",
                            "packages": ["alice-utils", "alice-cli"],
                        }
                    ],
                    "exposure_window": [
                        "2026-05-01T00:00:00Z",
                        "2026-05-02T12:00:00Z",
                    ],
                    "actions": ["Audit + rotate."],
                }
            ],
        }
    )
    lf = _lockfile(
        _pkg("alice-utils", "1.0.0"),
        _pkg("benign", "9.9.9"),
    )
    matches = feed.find_matches(lf)
    assert len(matches) == 1
    hit = matches[0]
    assert hit.is_suspect is True
    assert hit.package.name == "alice-utils"
    assert hit.advisory.id == "EXTRA-2026-9001-suspect-alice"
    assert "SUSPECT" in hit.advisory.summary
    assert "alice" in hit.advisory.summary


def test_exact_version_match_takes_precedence_over_maintainer_suspect() -> None:
    """If both the exact-version block AND the compromised_maintainers
    block would flag the same package, only the CONFIRMED hit is
    emitted (no double-reporting)."""
    feed = ExtrasFeed.from_dict(
        {
            "version": 1,
            "campaigns": [
                {
                    "id": "EXTRA-2026-9002",
                    "name": "Both-paths test",
                    "summary": "Test that exact-match suppresses suspect.",
                    "references": ["https://example.test/research"],
                    "ecosystem": "npm",
                    "packages": [
                        {"name": "alice-utils", "versions": ["1.0.0"]}
                    ],
                    "compromised_maintainers": [
                        {
                            "name": "alice",
                            "packages": ["alice-utils"],
                        }
                    ],
                    "exposure_window": [
                        "2026-05-01T00:00:00Z",
                        "2026-05-02T12:00:00Z",
                    ],
                    "actions": ["Rotate."],
                }
            ],
        }
    )
    lf = _lockfile(_pkg("alice-utils", "1.0.0"))
    matches = feed.find_matches(lf)
    assert len(matches) == 1
    hit = matches[0]
    assert hit.is_suspect is False  # CONFIRMED, not SUSPECT
    assert hit.advisory.id == "EXTRA-2026-9002"  # not -suspect-alice


def test_maintainer_suspect_does_not_flag_unaffected_packages() -> None:
    """A package not in compromised_maintainers[].packages must not fire."""
    feed = ExtrasFeed.from_dict(
        {
            "version": 1,
            "campaigns": [
                {
                    "id": "EXTRA-2026-9003",
                    "name": "Negative test",
                    "summary": "x",
                    "references": ["https://example.test/x"],
                    "ecosystem": "npm",
                    "packages": [],
                    "compromised_maintainers": [
                        {"name": "alice", "packages": ["pkg-a"]}
                    ],
                    "exposure_window": [
                        "2026-05-01T00:00:00Z",
                        "2026-05-02T00:00:00Z",
                    ],
                    "actions": [],
                }
            ],
        }
    )
    lf = _lockfile(_pkg("pkg-b", "1.0.0"), _pkg("pkg-c", "2.0.0"))
    assert feed.find_matches(lf) == []


def test_maintainer_suspect_marks_finding_non_malicious_high_severity() -> None:
    """Through the full Matcher path, a maintainer-suspect hit must
    produce a Finding with is_malicious=False and HIGH severity, so it
    maps to exit 2 (informational HIGH/CRITICAL) rather than exit 1
    (confirmed malicious)."""
    from unittest.mock import MagicMock

    from pwned_deps.advisory.matcher import Matcher

    feed = ExtrasFeed.from_dict(
        {
            "version": 1,
            "campaigns": [
                {
                    "id": "EXTRA-2026-9004",
                    "name": "Suspect-only campaign",
                    "summary": "x",
                    "references": ["https://example.test/x"],
                    "ecosystem": "npm",
                    "packages": [],
                    "compromised_maintainers": [
                        {"name": "alice", "packages": ["watched-pkg"]}
                    ],
                    "exposure_window": [
                        "2026-05-01T00:00:00Z",
                        "2026-05-02T00:00:00Z",
                    ],
                    "actions": [],
                }
            ],
        }
    )
    lf = _lockfile(_pkg("watched-pkg", "3.1.4"))
    osv = MagicMock()
    osv.query_batch.return_value = {}
    matcher = Matcher(osv_client=osv, extras=feed)
    findings = matcher.match(lf)
    assert len(findings) == 1
    assert findings[0].is_malicious is False
    assert findings[0].severity.name == "HIGH"
