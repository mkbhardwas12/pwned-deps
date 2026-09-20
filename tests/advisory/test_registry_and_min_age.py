"""0.2.0: registry publish-time client, SUSPECT window resolution, --min-age."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from click.testing import CliRunner
from pytest_httpx import HTTPXMock

from pwned_deps.advisory.cache import Cache
from pwned_deps.advisory.extras import ExtrasFeed
from pwned_deps.advisory.matcher import MIN_AGE_RULE_ID, Matcher
from pwned_deps.advisory.osv_client import OsvClient
from pwned_deps.advisory.registry import RegistryClient, parse_timestamp
from pwned_deps.cli import main
from pwned_deps.parsers.base import Ecosystem, Lockfile, Package

NOW = datetime(2026, 5, 10, 12, 0, tzinfo=timezone.utc)


def _pkg(name: str, version: str, eco: Ecosystem = Ecosystem.NPM) -> Package:
    return Package(name=name, version=version, ecosystem=eco, lockfile_path="(test)")


def _lockfile(*pkgs: Package) -> Lockfile:
    return Lockfile(path=Path("(test)"), ecosystem=pkgs[0].ecosystem, packages=tuple(pkgs))


def _mock_npm(httpx_mock: HTTPXMock, name: str, times: dict[str, str]) -> None:
    from urllib.parse import quote

    httpx_mock.add_response(
        url=f"https://registry.npmjs.org/{quote(name, safe='@')}",
        method="GET",
        json={"name": name, "time": times},
    )


def _mock_pypi(httpx_mock: HTTPXMock, name: str, version: str, stamps: list[str]) -> None:
    httpx_mock.add_response(
        url=f"https://pypi.org/pypi/{name}/{version}/json",
        method="GET",
        json={"urls": [{"upload_time_iso_8601": s} for s in stamps]},
    )


def _mock_osv_empty(httpx_mock: HTTPXMock, n: int = 1) -> None:
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        method="POST",
        json={"results": [{} for _ in range(n)]},
        is_reusable=True,
    )


# ---------------------------------------------------------------------------
# parse_timestamp
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "2026-05-01T00:00:00Z",
        "2026-05-01T00:00:00.000Z",
        "2026-05-01T00:00:00.123456+00:00",
        "2026-05-01",
    ],
)
def test_parse_timestamp_accepts_registry_and_feed_shapes(raw: str) -> None:
    parsed = parse_timestamp(raw)
    assert parsed is not None
    assert parsed.tzinfo is not None
    assert (parsed.year, parsed.month, parsed.day) == (2026, 5, 1)


def test_parse_timestamp_garbage_is_none() -> None:
    assert parse_timestamp("yesterday") is None
    assert parse_timestamp("") is None


# ---------------------------------------------------------------------------
# RegistryClient
# ---------------------------------------------------------------------------


def test_npm_scoped_name_is_encoded_and_time_read(httpx_mock: HTTPXMock) -> None:
    _mock_npm(httpx_mock, "@scope/pkg", {"created": "2020-01-01T00:00:00Z", "1.2.3": "2026-05-09T10:00:00.000Z"})
    with RegistryClient() as reg:
        lookup = reg.publish_time(_pkg("@scope/pkg", "1.2.3"))
    assert lookup.ok
    assert lookup.published_at == datetime(2026, 5, 9, 10, 0, tzinfo=timezone.utc)
    assert httpx_mock.get_requests()[0].url.raw_path == b"/@scope%2Fpkg"


def test_npm_document_is_fetched_once_per_package(httpx_mock: HTTPXMock) -> None:
    _mock_npm(httpx_mock, "lodash", {"1.0.0": "2020-01-01T00:00:00Z", "2.0.0": "2021-01-01T00:00:00Z"})
    with RegistryClient() as reg:
        a = reg.publish_time(_pkg("lodash", "1.0.0"))
        b = reg.publish_time(_pkg("lodash", "2.0.0"))
        missing = reg.publish_time(_pkg("lodash", "9.9.9"))
    assert a.ok and b.ok
    assert not missing.ok and "not found" in missing.reason
    assert len(httpx_mock.get_requests()) == 1


def test_pypi_uses_earliest_upload_time(httpx_mock: HTTPXMock) -> None:
    _mock_pypi(
        httpx_mock,
        "lightning",
        "2.6.2",
        ["2026-05-02T09:00:00.000000Z", "2026-05-02T08:30:00.000000Z"],
    )
    with RegistryClient() as reg:
        lookup = reg.publish_time(_pkg("lightning", "2.6.2", Ecosystem.PYPI))
    assert lookup.published_at == datetime(2026, 5, 2, 8, 30, tzinfo=timezone.utc)


def test_publish_time_is_cached_without_ttl(tmp_path: Path, httpx_mock: HTTPXMock) -> None:
    _mock_npm(httpx_mock, "lodash", {"1.0.0": "2020-01-01T00:00:00Z"})
    cache = Cache(tmp_path / "c.sqlite", ttl_seconds=0)  # advisory TTL irrelevant here
    with RegistryClient(cache=cache) as reg:
        assert reg.publish_time(_pkg("lodash", "1.0.0")).ok
    with RegistryClient(cache=cache, offline=True) as reg:
        again = reg.publish_time(_pkg("lodash", "1.0.0"))
    assert again.ok
    assert len(httpx_mock.get_requests()) == 1


def test_offline_miss_and_network_error_are_reported_not_raised(
    tmp_path: Path, httpx_mock: HTTPXMock
) -> None:
    with RegistryClient(cache=Cache(tmp_path / "c.sqlite"), offline=True) as reg:
        off = reg.publish_time(_pkg("lodash", "1.0.0"))
    assert not off.ok and off.reason.startswith("offline")

    httpx_mock.add_exception(httpx.ConnectError("down"))
    with RegistryClient() as reg:
        err = reg.publish_time(_pkg("lodash", "1.0.0"))
    assert not err.ok and "ConnectError" in err.reason

    httpx_mock.add_response(url="https://registry.npmjs.org/gone", status_code=404)
    with RegistryClient() as reg:
        nf = reg.publish_time(_pkg("gone", "1.0.0"))
    assert not nf.ok and "HTTP 404" in nf.reason


def test_unsupported_ecosystem_is_a_soft_reason() -> None:
    with RegistryClient() as reg:
        lookup = reg.publish_time(_pkg("serde", "1.0.0", Ecosystem.CRATES))
    assert not lookup.ok
    assert lookup.reason.startswith("publish time not supported")


# ---------------------------------------------------------------------------
# SUSPECT -> CONFIRMED / cleared via publish window
# ---------------------------------------------------------------------------


def _window_feed() -> ExtrasFeed:
    return ExtrasFeed.from_dict(
        {
            "version": 1,
            "campaigns": [
                {
                    "id": "EXTRA-2026-9100",
                    "name": "Window campaign",
                    "summary": "alice's npm token was stolen",
                    "references": ["https://example.test/alice"],
                    "ecosystem": "npm",
                    "packages": [],
                    "compromised_maintainers": [
                        {
                            "name": "alice",
                            "compromised_after": "2026-05-01T00:00:00Z",
                            "compromised_until": "2026-05-02T12:00:00Z",
                            "packages": ["alice-utils"],
                        }
                    ],
                }
            ],
        }
    )


def test_suspect_inside_window_becomes_confirmed_malicious(httpx_mock: HTTPXMock) -> None:
    _mock_osv_empty(httpx_mock)
    _mock_npm(httpx_mock, "alice-utils", {"3.0.0": "2026-05-01T06:00:00.000Z"})
    with OsvClient() as osv, RegistryClient() as reg:
        matcher = Matcher(osv_client=osv, extras=_window_feed(), registry=reg)
        findings = matcher.match(_lockfile(_pkg("alice-utils", "3.0.0")))
    assert len(findings) == 1
    f = findings[0]
    assert f.is_malicious is True
    assert f.advisory.id == "EXTRA-2026-9100"
    assert "CONFIRMED by publish timestamp" in f.advisory.summary
    assert f.advisory.raw["match_type"] == "compromised_maintainer_confirmed"


def test_suspect_outside_window_is_cleared(httpx_mock: HTTPXMock) -> None:
    _mock_osv_empty(httpx_mock)
    _mock_npm(httpx_mock, "alice-utils", {"2.9.0": "2026-04-20T00:00:00.000Z"})
    with OsvClient() as osv, RegistryClient() as reg:
        matcher = Matcher(osv_client=osv, extras=_window_feed(), registry=reg)
        findings = matcher.match(_lockfile(_pkg("alice-utils", "2.9.0")))
    assert findings == []


def test_suspect_stays_suspect_when_timestamp_unavailable(httpx_mock: HTTPXMock) -> None:
    _mock_osv_empty(httpx_mock)
    httpx_mock.add_response(url="https://registry.npmjs.org/alice-utils", status_code=503)
    with OsvClient() as osv, RegistryClient() as reg:
        matcher = Matcher(osv_client=osv, extras=_window_feed(), registry=reg)
        findings = matcher.match(_lockfile(_pkg("alice-utils", "3.0.0")))
    assert len(findings) == 1
    assert findings[0].is_malicious is False
    assert findings[0].advisory.id.endswith("-suspect-alice")


def test_without_registry_behaviour_is_unchanged(httpx_mock: HTTPXMock) -> None:
    _mock_osv_empty(httpx_mock)
    with OsvClient() as osv:
        matcher = Matcher(osv_client=osv, extras=_window_feed())
        findings = matcher.match(_lockfile(_pkg("alice-utils", "3.0.0")))
    assert len(findings) == 1 and findings[0].is_malicious is False
    assert all(r.url.host == "api.osv.dev" for r in httpx_mock.get_requests())


# ---------------------------------------------------------------------------
# --min-age
# ---------------------------------------------------------------------------


def test_min_age_flags_fresh_package_and_not_old_one(httpx_mock: HTTPXMock) -> None:
    _mock_osv_empty(httpx_mock, n=2)
    _mock_npm(httpx_mock, "fresh", {"1.0.0": (NOW - timedelta(hours=5)).isoformat()})
    _mock_npm(httpx_mock, "old", {"1.0.0": (NOW - timedelta(days=400)).isoformat()})
    with OsvClient() as osv, RegistryClient() as reg:
        matcher = Matcher(
            osv_client=osv, extras=ExtrasFeed([]), registry=reg, min_age_days=7, now=NOW
        )
        result = matcher.match_detailed(_lockfile(_pkg("fresh", "1.0.0"), _pkg("old", "1.0.0")))
    assert [f.package.name for f in result.findings] == ["fresh"]
    f = result.findings[0]
    assert f.advisory.id == MIN_AGE_RULE_ID
    assert f.is_policy and not f.is_malicious
    assert f.severity.name == "HIGH"
    assert "5 hour(s) ago" in f.advisory.summary
    assert result.unchecked == []


def test_min_age_lookup_failure_is_unchecked_not_silent(httpx_mock: HTTPXMock) -> None:
    _mock_osv_empty(httpx_mock)
    httpx_mock.add_response(url="https://registry.npmjs.org/flaky", status_code=500)
    with OsvClient() as osv, RegistryClient() as reg:
        matcher = Matcher(
            osv_client=osv, extras=ExtrasFeed([]), registry=reg, min_age_days=7, now=NOW
        )
        result = matcher.match_detailed(_lockfile(_pkg("flaky", "1.0.0")))
    assert result.findings == []
    assert len(result.unchecked) == 1
    assert result.unchecked[0].reason == "min-age: registry HTTP 500"


def test_min_age_skips_ecosystems_without_timestamps(httpx_mock: HTTPXMock) -> None:
    _mock_osv_empty(httpx_mock)
    with OsvClient() as osv, RegistryClient() as reg:
        matcher = Matcher(
            osv_client=osv, extras=ExtrasFeed([]), registry=reg, min_age_days=7, now=NOW
        )
        result = matcher.match_detailed(_lockfile(_pkg("serde", "1.0.0", Ecosystem.CRATES)))
    assert result.findings == [] and result.unchecked == []
    assert all(r.url.host == "api.osv.dev" for r in httpx_mock.get_requests())


def test_min_age_without_registry_is_a_noop(httpx_mock: HTTPXMock) -> None:
    _mock_osv_empty(httpx_mock)
    with OsvClient() as osv:
        matcher = Matcher(osv_client=osv, extras=ExtrasFeed([]), min_age_days=7, now=NOW)
        result = matcher.match_detailed(_lockfile(_pkg("fresh", "1.0.0")))
    assert result.findings == []


# ---------------------------------------------------------------------------
# CLI end-to-end
# ---------------------------------------------------------------------------


def test_cli_min_age_exits_two_and_prints_too_new(tmp_path: Path, httpx_mock: HTTPXMock) -> None:
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {"": {}, "node_modules/fresh": {"version": "1.0.0"}},
            }
        ),
        encoding="utf-8",
    )
    _mock_osv_empty(httpx_mock)
    recent = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    _mock_npm(httpx_mock, "fresh", {"1.0.0": recent})

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["check", str(lock), "--ci", "--min-age", "3", "--cache-path", str(tmp_path / "c.sqlite")],
        catch_exceptions=False,
    )
    assert result.exit_code == 2, result.output
    assert "TOO NEW" in result.output
    assert "fresh@1.0.0" in result.output
    assert "1 too new" in result.output


def test_cli_min_age_json_carries_policy_finding(tmp_path: Path, httpx_mock: HTTPXMock) -> None:
    lock = tmp_path / "requirements.txt"
    lock.write_text("brand-new-lib==0.0.1\n", encoding="utf-8")
    _mock_osv_empty(httpx_mock)
    recent = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    _mock_pypi(httpx_mock, "brand-new-lib", "0.0.1", [recent])

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "check",
            str(lock),
            "--format",
            "json",
            "--min-age",
            "7",
            "--cache-path",
            str(tmp_path / "c.sqlite"),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 2, result.output
    payload = json.loads(result.output)
    finding = payload["lockfiles"][0]["findings"][0]
    assert finding["id"] == MIN_AGE_RULE_ID
    assert finding["is_malicious"] is False
    assert payload["summary"]["high_critical"] == 1


def test_cli_without_min_age_never_contacts_registries(
    tmp_path: Path, httpx_mock: HTTPXMock
) -> None:
    lock = tmp_path / "requirements.txt"
    lock.write_text("requests==2.31.0\n", encoding="utf-8")
    _mock_osv_empty(httpx_mock)
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["check", str(lock), "--ci", "--cache-path", str(tmp_path / "c.sqlite")],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert {r.url.host for r in httpx_mock.get_requests()} == {"api.osv.dev"}
