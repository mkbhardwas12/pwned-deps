"""Tests for the OSV REST client (mocked with pytest-httpx)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pytest_httpx import HTTPXMock

from pwned_deps.advisory.cache import Cache
from pwned_deps.advisory.osv_client import OsvClient
from pwned_deps.advisory.types import Severity
from pwned_deps.parsers.base import Ecosystem, Package


def _pkg(name: str, version: str, ecosystem: Ecosystem = Ecosystem.NPM) -> Package:
    return Package(
        name=name,
        version=version,
        ecosystem=ecosystem,
        lockfile_path="(test)",
    )


def _no_op_sleep(_seconds: float) -> None:
    return None


def test_query_batch_single_package_returns_advisories(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        method="POST",
        json={"results": [{"vulns": [{"id": "GHSA-AAAA"}]}]},
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/vulns/GHSA-AAAA",
        method="GET",
        json={
            "id": "GHSA-AAAA",
            "summary": "Example",
            "references": [{"type": "WEB", "url": "https://example.test/x"}],
            "database_specific": {"severity": "HIGH"},
        },
    )

    with OsvClient(sleep=_no_op_sleep) as client:
        result = client.query_batch([_pkg("lodash", "4.17.15")])

    advisories = result[_pkg("lodash", "4.17.15")]
    assert [a.id for a in advisories] == ["GHSA-AAAA"]
    assert advisories[0].severity is Severity.HIGH
    assert advisories[0].references == ("https://example.test/x",)


def test_query_batch_returns_empty_for_clean_packages(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        method="POST",
        json={"results": [{}, {}]},
    )

    with OsvClient(sleep=_no_op_sleep) as client:
        result = client.query_batch([
            _pkg("safe-pkg-a", "1.0.0"),
            _pkg("safe-pkg-b", "2.0.0"),
        ])

    assert result[_pkg("safe-pkg-a", "1.0.0")] == []
    assert result[_pkg("safe-pkg-b", "2.0.0")] == []


def test_query_batch_chunks_50_packages_in_one_call(httpx_mock: HTTPXMock) -> None:
    pkgs = [_pkg(f"p{i}", "1.0.0") for i in range(50)]
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        method="POST",
        json={"results": [{} for _ in pkgs]},
    )

    with OsvClient(sleep=_no_op_sleep) as client:
        result = client.query_batch(pkgs)

    assert len(result) == 50
    assert all(result[p] == [] for p in pkgs)
    # Default chunk size is 1000, so 50 fits in a single batch call.
    assert len(httpx_mock.get_requests()) == 1


def test_query_batch_retries_on_429(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        method="POST",
        status_code=429,
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        method="POST",
        json={"results": [{"vulns": [{"id": "GHSA-AAAA"}]}]},
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/vulns/GHSA-AAAA",
        method="GET",
        json={"id": "GHSA-AAAA", "summary": "ok"},
    )

    with OsvClient(sleep=_no_op_sleep) as client:
        result = client.query_batch([_pkg("lodash", "4.17.15")])

    advisories = result[_pkg("lodash", "4.17.15")]
    assert [a.id for a in advisories] == ["GHSA-AAAA"]
    # Two batchquery POSTs, one vulns GET = 3 requests.
    assert len(httpx_mock.get_requests()) == 3


def test_offline_mode_returns_empty_without_network(
    tmp_path: Path, httpx_mock: HTTPXMock
) -> None:
    cache = Cache(tmp_path / "osv.sqlite")
    # No mocked responses queued — any network call would error.

    with OsvClient(cache=cache, offline=True, sleep=_no_op_sleep) as client:
        result = client.query_batch([_pkg("lodash", "4.17.15")])

    assert result[_pkg("lodash", "4.17.15")] == []
    assert httpx_mock.get_requests() == []


def test_cache_hit_skips_network(
    tmp_path: Path, httpx_mock: HTTPXMock
) -> None:
    cache = Cache(tmp_path / "osv.sqlite")
    cache.put("npm", "lodash", "4.17.15", [])  # cached as "no findings"

    # First call should not touch network.
    with OsvClient(cache=cache, sleep=_no_op_sleep) as client:
        result = client.query_batch([_pkg("lodash", "4.17.15")])

    assert result[_pkg("lodash", "4.17.15")] == []
    assert httpx_mock.get_requests() == []


def test_malicious_advisory_id_promotes_severity_to_critical(
    httpx_mock: HTTPXMock,
) -> None:
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        method="POST",
        json={"results": [{"vulns": [{"id": "MAL-2026-1234"}]}]},
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/vulns/MAL-2026-1234",
        method="GET",
        json={"id": "MAL-2026-1234", "summary": "credential stealer"},
    )

    with OsvClient(sleep=_no_op_sleep) as client:
        result = client.query_batch([_pkg("evil-pkg", "1.0.0")])

    adv = result[_pkg("evil-pkg", "1.0.0")][0]
    assert adv.severity is Severity.CRITICAL
    assert adv.is_malicious


def test_version_unspecified_packages_short_circuit_to_empty(
    httpx_mock: HTTPXMock,
) -> None:
    pkg = Package(
        name="numpy",
        version="",
        ecosystem=Ecosystem.PYPI,
        lockfile_path="(test)",
        version_unspecified=True,
    )

    with OsvClient(sleep=_no_op_sleep) as client:
        result = client.query_batch([pkg])

    # No version means we cannot match — caller is told "[]" so it
    # can render the warning. No network call must fire.
    assert result[pkg] == []
    assert httpx_mock.get_requests() == []


@pytest.mark.network
def test_live_lookup_lodash_known_vulnerable() -> None:
    """Opt-in integration test: hits real api.osv.dev.

    Run with: pytest -m network
    """

    with OsvClient() as client:
        result = client.query_batch([_pkg("lodash", "4.17.20")])

    advisories = result[_pkg("lodash", "4.17.20")]
    assert len(advisories) >= 1, "expected at least one advisory for lodash 4.17.20"
