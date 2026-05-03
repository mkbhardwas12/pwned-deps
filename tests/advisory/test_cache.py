"""Tests for the SQLite advisory cache."""

from __future__ import annotations

from pathlib import Path

from pwned_deps.advisory.cache import Cache
from pwned_deps.advisory.types import Advisory, Severity


def _adv(id_: str, *, severity: Severity = Severity.HIGH) -> Advisory:
    return Advisory(
        id=id_,
        summary="example",
        ecosystem="npm",
        package="lodash",
        version="4.17.15",
        references=("https://example.test/a", "https://example.test/b"),
        severity=severity,
        raw={"id": id_, "details": "..."},
    )


def test_get_returns_none_when_never_queried(tmp_path: Path) -> None:
    cache = Cache(tmp_path / "osv.sqlite")
    assert cache.get("npm", "lodash", "4.17.15") is None


def test_round_trip_with_two_advisories(tmp_path: Path) -> None:
    cache = Cache(tmp_path / "osv.sqlite")

    advisories = [_adv("GHSA-AAAA"), _adv("GHSA-BBBB", severity=Severity.MEDIUM)]
    cache.put("npm", "lodash", "4.17.15", advisories)

    out = cache.get("npm", "lodash", "4.17.15")
    assert out is not None
    assert {a.id for a in out} == {"GHSA-AAAA", "GHSA-BBBB"}
    medium = next(a for a in out if a.id == "GHSA-BBBB")
    assert medium.severity is Severity.MEDIUM
    assert medium.references == ("https://example.test/a", "https://example.test/b")


def test_negative_caching_returns_empty_list_not_none(tmp_path: Path) -> None:
    """An entry that was queried and produced no findings must come
    back as an empty list, distinguishable from "never queried"
    (None)."""
    cache = Cache(tmp_path / "osv.sqlite")
    cache.put("npm", "left-pad", "1.0.0", [])
    assert cache.get("npm", "left-pad", "1.0.0") == []


def test_ttl_expired_entries_yield_none(tmp_path: Path) -> None:
    fake_time = [1_700_000_000.0]  # mutable so we can advance it

    def clock() -> float:
        return fake_time[0]

    cache = Cache(tmp_path / "osv.sqlite", ttl_seconds=10, clock=clock)
    cache.put("npm", "lodash", "4.17.15", [_adv("GHSA-AAAA")])
    fake_time[0] += 5
    assert cache.get("npm", "lodash", "4.17.15") is not None
    fake_time[0] += 100
    # Past TTL — must come back as None so callers re-fetch.
    assert cache.get("npm", "lodash", "4.17.15") is None


def test_put_replaces_existing_rows(tmp_path: Path) -> None:
    cache = Cache(tmp_path / "osv.sqlite")
    cache.put("npm", "lodash", "4.17.15", [_adv("GHSA-AAAA")])
    cache.put("npm", "lodash", "4.17.15", [_adv("GHSA-CCCC")])
    out = cache.get("npm", "lodash", "4.17.15") or []
    assert {a.id for a in out} == {"GHSA-CCCC"}
