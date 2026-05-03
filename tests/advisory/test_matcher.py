"""Tests for the matcher (OSV + extras combined)."""

from __future__ import annotations

from pathlib import Path

from pytest_httpx import HTTPXMock

from pwned_deps.advisory.extras import ExtrasFeed
from pwned_deps.advisory.matcher import Matcher
from pwned_deps.advisory.osv_client import OsvClient
from pwned_deps.parsers.base import Ecosystem, Lockfile, Package


def _no_op_sleep(_seconds: float) -> None:
    return None


def _pkg(name: str, version: str, ecosystem: Ecosystem = Ecosystem.NPM) -> Package:
    return Package(name=name, version=version, ecosystem=ecosystem, lockfile_path="(test)")


def _lockfile(*pkgs: Package) -> Lockfile:
    return Lockfile(path=Path("(test)"), ecosystem=Ecosystem.NPM, packages=tuple(pkgs))


def test_lodash_known_vulnerable_yields_osv_finding(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        method="POST",
        json={"results": [{"vulns": [{"id": "GHSA-LODASH"}]}]},
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/vulns/GHSA-LODASH",
        method="GET",
        json={
            "id": "GHSA-LODASH",
            "summary": "Prototype pollution in lodash",
            "database_specific": {"severity": "HIGH"},
        },
    )

    extras = ExtrasFeed.from_dict({"version": 1, "campaigns": []})
    with OsvClient(sleep=_no_op_sleep) as osv:
        matcher = Matcher(osv_client=osv, extras=extras)
        findings = matcher.match(_lockfile(_pkg("lodash", "4.17.15")))

    assert len(findings) == 1
    assert findings[0].advisory.id == "GHSA-LODASH"
    assert not findings[0].is_malicious
    assert findings[0].campaign_name is None


def test_extras_campaign_marks_finding_malicious_and_named(
    httpx_mock: HTTPXMock,
) -> None:
    extras = ExtrasFeed.from_dict(
        {
            "version": 1,
            "campaigns": [
                {
                    "id": "EXTRA-2026-0001",
                    "name": "Mini Shai-Hulud (SAP CAP)",
                    "summary": "credential stealer",
                    "references": ["https://wiz.io/test"],
                    "ecosystem": "npm",
                    "packages": [
                        {"name": "@cap-js/foo", "versions": ["1.2.3"]},
                    ],
                }
            ],
        }
    )

    # OSV will be queried for both packages but returns nothing.
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        method="POST",
        json={"results": [{}, {}]},
    )

    with OsvClient(sleep=_no_op_sleep) as osv:
        matcher = Matcher(osv_client=osv, extras=extras)
        findings = matcher.match(
            _lockfile(_pkg("@cap-js/foo", "1.2.3"), _pkg("benign", "1.0.0"))
        )

    assert len(findings) == 1
    f = findings[0]
    assert f.is_malicious
    assert f.campaign_name == "Mini Shai-Hulud (SAP CAP)"
    assert f.advisory.id == "EXTRA-2026-0001"


def test_no_findings_for_clean_lockfile(httpx_mock: HTTPXMock) -> None:
    extras = ExtrasFeed.from_dict({"version": 1, "campaigns": []})
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        method="POST",
        json={"results": [{}]},
    )

    with OsvClient(sleep=_no_op_sleep) as osv:
        matcher = Matcher(osv_client=osv, extras=extras)
        findings = matcher.match(_lockfile(_pkg("clean-pkg", "1.0.0")))

    assert findings == []


def test_unspecified_version_skips_osv_call_and_extras(
    httpx_mock: HTTPXMock,
) -> None:
    extras = ExtrasFeed.from_dict({"version": 1, "campaigns": []})
    pkg = Package(
        name="numpy",
        version="",
        ecosystem=Ecosystem.PYPI,
        lockfile_path="(test)",
        version_unspecified=True,
    )

    with OsvClient(sleep=_no_op_sleep) as osv:
        matcher = Matcher(osv_client=osv, extras=extras)
        findings = matcher.match(
            Lockfile(path=Path("(test)"), ecosystem=Ecosystem.PYPI, packages=(pkg,))
        )

    assert findings == []
    # No batch query fires when there is nothing to ask about.
    assert httpx_mock.get_requests() == []
