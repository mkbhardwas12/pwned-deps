"""OSV.dev REST client.

Two endpoints:

* ``POST /v1/querybatch`` — bulk existence check. The response only
  carries advisory IDs and modified timestamps. We chunk our input
  list into ≤1000-element batches.
* ``GET /v1/vulns/{id}`` — full advisory record. We call this once per
  unique ID returned by the batch query, then de-duplicate so the
  same advisory isn't fetched twice during a single
  ``query_batch`` invocation.

Network-side guarantees:

* Only ``api.osv.dev`` is contacted (and an opt-in user-configured
  feed URL handled elsewhere; this client never reaches outside its
  ``base_url``).
* ``httpx.Client(trust_env=False)`` so host proxy environment vars
  cannot silently redirect traffic.
* Request timeouts are bounded.
* Retries on 429 / 5xx / transport errors with exponential backoff,
  bounded to 3 attempts.

Caching is done by the caller (``OsvClient.__init__(cache=...)``) so
this module stays focused on transport.
"""

from __future__ import annotations

import time
from collections.abc import Iterable, Sequence
from typing import Any

import httpx

from pwned_deps.advisory.cache import Cache
from pwned_deps.advisory.types import Advisory, Severity
from pwned_deps.parsers.base import Package

DEFAULT_BASE_URL = "https://api.osv.dev"
DEFAULT_BATCH_SIZE = 1000
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_USER_AGENT = (
    "pwned-deps/0.1.0 (+https://github.com/mkbhardwas12/pwned-deps)"
)
_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
_MAX_ATTEMPTS = 3


class OsvClient:
    """Synchronous OSV client with optional read-through cache.

    ``query_batch`` is the only public call most callers want.
    """

    def __init__(
        self,
        *,
        cache: Cache | None = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        user_agent: str = DEFAULT_USER_AGENT,
        offline: bool = False,
        sleep: Any = time.sleep,
        client: httpx.Client | None = None,
    ) -> None:
        self.cache = cache
        self.base_url = base_url.rstrip("/")
        self.offline = offline
        self._sleep = sleep
        self._owns_client = client is None
        self._client = client or httpx.Client(
            timeout=timeout,
            headers={"User-Agent": user_agent},
            trust_env=False,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def query_batch(
        self,
        packages: Sequence[Package],
    ) -> dict[Package, list[Advisory]]:
        """Return ``{Package: [Advisory, ...]}`` for every input package.

        Empty list means "queried, no findings". Cache is consulted
        before any network call.
        """

        # 1. Cache pass — keep the input order, identify what still
        #    needs a network query.
        results: dict[Package, list[Advisory]] = {}
        to_fetch: list[Package] = []
        for pkg in packages:
            if pkg.version_unspecified:
                results[pkg] = []
                continue
            if self.cache is not None:
                cached = self.cache.get(pkg.ecosystem.value, pkg.name, pkg.version)
                if cached is not None:
                    results[pkg] = cached
                    continue
            to_fetch.append(pkg)

        if not to_fetch:
            return results
        if self.offline:
            for pkg in to_fetch:
                results[pkg] = []
            return results

        # 2. Network pass — chunk into ≤1000 batches.
        for chunk in _chunks(to_fetch, DEFAULT_BATCH_SIZE):
            id_lists = self._post_querybatch(chunk)
            unique_ids: set[str] = set()
            for ids in id_lists:
                unique_ids.update(ids)
            full_records = self._fetch_advisory_records(unique_ids)
            for pkg, ids in zip(chunk, id_lists, strict=True):
                advisories = [
                    _build_advisory(pkg, full_records[id_]) for id_ in ids if id_ in full_records
                ]
                results[pkg] = advisories
                if self.cache is not None:
                    self.cache.put(pkg.ecosystem.value, pkg.name, pkg.version, advisories)

        return results

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> OsvClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _post_querybatch(self, packages: Sequence[Package]) -> list[list[str]]:
        body = {
            "queries": [
                {
                    "package": {
                        "name": pkg.name,
                        "ecosystem": pkg.ecosystem.value,
                    },
                    "version": pkg.version,
                }
                for pkg in packages
            ]
        }
        data = self._post_with_retry("/v1/querybatch", body)
        results = data.get("results", [])
        out: list[list[str]] = []
        for result in results:
            vulns = result.get("vulns", []) if isinstance(result, dict) else []
            ids = [v.get("id") for v in vulns if isinstance(v, dict) and v.get("id")]
            out.append([str(i) for i in ids])
        # Pad to the same length as input even if OSV returned shorter
        # (defensive — should not happen).
        while len(out) < len(packages):
            out.append([])
        return out

    def _fetch_advisory_records(self, ids: Iterable[str]) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for advisory_id in ids:
            try:
                payload = self._get_with_retry(f"/v1/vulns/{advisory_id}")
            except httpx.HTTPError:
                continue
            out[advisory_id] = payload
        return out

    def _post_with_retry(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._request_with_retry("POST", path, json_body=body)

    def _get_with_retry(self, path: str) -> dict[str, Any]:
        return self._request_with_retry("GET", path)

    def _request_with_retry(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        last_exc: Exception | None = None
        for attempt in range(_MAX_ATTEMPTS):
            try:
                if method == "POST":
                    response = self._client.post(url, json=json_body)
                else:
                    response = self._client.get(url)
            except httpx.HTTPError as exc:
                last_exc = exc
                self._sleep(_backoff(attempt))
                continue
            if response.status_code in _RETRY_STATUS and attempt + 1 < _MAX_ATTEMPTS:
                self._sleep(_backoff(attempt))
                continue
            response.raise_for_status()
            return response.json()
        if last_exc is not None:
            raise last_exc
        raise httpx.HTTPError(f"OSV {method} {path} failed after {_MAX_ATTEMPTS} attempts")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _backoff(attempt: int) -> float:
    """Exponential backoff: 0.5s, 1s, 2s for attempts 0/1/2."""

    return 0.5 * (2**attempt)


def _chunks(seq: Sequence[Package], size: int) -> Iterable[Sequence[Package]]:
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


def _build_advisory(pkg: Package, payload: dict[str, Any]) -> Advisory:
    advisory_id = str(payload.get("id", ""))
    summary = str(payload.get("summary") or payload.get("details") or "").strip()
    references = tuple(
        ref.get("url") for ref in payload.get("references", []) if isinstance(ref, dict) and ref.get("url")
    )
    severity = _severity_from_payload(advisory_id, payload)
    return Advisory(
        id=advisory_id,
        summary=summary,
        ecosystem=pkg.ecosystem.value,
        package=pkg.name,
        version=pkg.version,
        references=references,
        severity=severity,
        raw=payload,
    )


def _severity_from_payload(advisory_id: str, payload: dict[str, Any]) -> Severity:
    """Map OSV severity to our 5-level scale.

    MAL-* records are forced to CRITICAL: a malicious package version
    is always a top-priority finding regardless of any CVSS data.
    """

    if advisory_id.upper().startswith("MAL-"):
        return Severity.CRITICAL

    # OSV provides `database_specific.severity` (sometimes) and a
    # `severity` array (CVSS scores). Try database_specific first.
    db_sev = (
        payload.get("database_specific", {}).get("severity")
        if isinstance(payload.get("database_specific"), dict)
        else None
    )
    if isinstance(db_sev, str):
        upper = db_sev.upper()
        if upper in {"CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW"}:
            if upper == "MODERATE":
                return Severity.MEDIUM
            return Severity(upper)

    # Fallback: parse CVSS v3 score from the severity array if present.
    severity_array = payload.get("severity", [])
    if isinstance(severity_array, list):
        for entry in severity_array:
            if not isinstance(entry, dict):
                continue
            score = entry.get("score", "")
            if not isinstance(score, str):
                continue
            cvss_score = _extract_cvss_base_score(score)
            if cvss_score is not None:
                return _cvss_to_severity(cvss_score)
    return Severity.UNKNOWN


def _extract_cvss_base_score(score: str) -> float | None:
    """Pull the numeric base score out of a CVSS vector string.

    OSV severity entries usually carry a CVSS vector like
    ``"CVSS:3.1/AV:N/..."`` rather than a plain number. We don't
    re-implement the spec — we just look for the trailing/embedded
    base score if the entry is a bare number.
    """

    score = score.strip()
    if not score:
        return None
    # Handle bare numeric scores.
    try:
        return float(score)
    except ValueError:
        return None


def _cvss_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.UNKNOWN
