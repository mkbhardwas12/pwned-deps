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
from dataclasses import dataclass, field
from typing import Any

import httpx

from pwned_deps import __version__
from pwned_deps.advisory.cache import Cache
from pwned_deps.advisory.types import Advisory, Severity
from pwned_deps.parsers.base import Package

DEFAULT_BASE_URL = "https://api.osv.dev"
DEFAULT_BATCH_SIZE = 1000
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_USER_AGENT = (
    f"pwned-deps/{__version__} (+https://github.com/mkbhardwas12/pwned-deps)"
)
_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
_MAX_ATTEMPTS = 3


@dataclass(frozen=True)
class Unchecked:
    """A pinned package we could NOT get an answer for.

    Distinct from ``version_unspecified`` (the input had no pin): the
    package was concrete, but the lookup did not happen or failed.
    Callers must never report these as clean.
    """

    package: Package
    reason: str


@dataclass
class BatchResult:
    """Outcome of one ``query_batch_detailed`` call."""

    advisories: dict[Package, list[Advisory]] = field(default_factory=dict)
    unchecked: list[Unchecked] = field(default_factory=list)


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
        sleep: Any = None,
        client: httpx.Client | None = None,
    ) -> None:
        self.cache = cache
        self.base_url = base_url.rstrip("/")
        self.offline = offline
        self._sleep = sleep if sleep is not None else time.sleep
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

        Empty list means "queried, no findings" *or* "could not be
        checked" — callers that need to tell the two apart must use
        :meth:`query_batch_detailed`.
        """

        return self.query_batch_detailed(packages).advisories

    def query_batch_detailed(self, packages: Sequence[Package]) -> BatchResult:
        """Like :meth:`query_batch` but also reports what went unchecked.

        Every input package appears in ``advisories``; the ones that
        were not actually resolved (offline cache miss, network failure,
        advisory record fetch failure) are additionally listed in
        ``unchecked`` with a human-readable reason.
        """

        result = BatchResult()
        results = result.advisories

        # 1. Cache pass — keep the input order, identify what still
        #    needs a network query.
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
            return result
        if self.offline:
            for pkg in to_fetch:
                results[pkg] = []
                result.unchecked.append(Unchecked(pkg, "offline and not in cache"))
            return result

        # 2. Network pass — chunk into ≤1000 batches. A transport
        #    failure marks the whole chunk unchecked rather than
        #    aborting the scan (or, worse, reporting it clean).
        for chunk in _chunks(to_fetch, DEFAULT_BATCH_SIZE):
            try:
                id_lists = self._post_querybatch(chunk)
            except httpx.HTTPError as exc:
                reason = f"OSV query failed: {_describe(exc)}"
                for pkg in chunk:
                    results[pkg] = []
                    result.unchecked.append(Unchecked(pkg, reason))
                continue
            unique_ids: set[str] = set()
            for ids in id_lists:
                unique_ids.update(ids)
            full_records, failed_ids = self._fetch_advisory_records(unique_ids)
            for pkg, ids in zip(chunk, id_lists, strict=True):
                advisories = [
                    _build_advisory(pkg, full_records[id_]) for id_ in ids if id_ in full_records
                ]
                results[pkg] = advisories
                missing = [id_ for id_ in ids if id_ in failed_ids]
                if missing:
                    # Do not cache a partial answer.
                    result.unchecked.append(
                        Unchecked(pkg, f"could not fetch advisory {', '.join(missing)}")
                    )
                    continue
                if self.cache is not None:
                    self.cache.put(pkg.ecosystem.value, pkg.name, pkg.version, advisories)

        return result

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

    def _fetch_advisory_records(
        self, ids: Iterable[str]
    ) -> tuple[dict[str, dict[str, Any]], set[str]]:
        out: dict[str, dict[str, Any]] = {}
        failed: set[str] = set()
        for advisory_id in ids:
            try:
                payload = self._get_with_retry(f"/v1/vulns/{advisory_id}")
            except httpx.HTTPError:
                failed.add(advisory_id)
                continue
            out[advisory_id] = payload
        return out, failed

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


def _describe(exc: httpx.HTTPError) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP {exc.response.status_code}"
    return type(exc).__name__


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

    MAL-* records (and GHSA records flagged as malware) are forced to
    CRITICAL: a malicious package version is always a top-priority
    finding regardless of any CVSS data.
    """

    if advisory_id.upper().startswith("MAL-"):
        return Severity.CRITICAL
    aliases = payload.get("aliases")
    if isinstance(aliases, list) and any(
        isinstance(a, str) and a.upper().startswith("MAL-") for a in aliases
    ):
        return Severity.CRITICAL

    # OSV provides `database_specific.severity` (sometimes) and a
    # `severity` array (CVSS scores). Try database_specific first.
    db = payload.get("database_specific")
    db_sev = db.get("severity") if isinstance(db, dict) else None
    if isinstance(db_sev, str):
        upper = db_sev.upper()
        if upper in {"CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW"}:
            if upper == "MODERATE":
                return Severity.MEDIUM
            return Severity(upper)

    # Fallback: the `severity` array. Entries are almost always CVSS
    # vector strings, so compute the base score ourselves.
    best: Severity | None = None
    severity_array = payload.get("severity", [])
    if isinstance(severity_array, list):
        for entry in severity_array:
            if not isinstance(entry, dict):
                continue
            score = entry.get("score", "")
            if not isinstance(score, str):
                continue
            cvss_score = _extract_cvss_base_score(score)
            if cvss_score is None:
                continue
            candidate = _cvss_to_severity(cvss_score)
            if best is None or _RANK[candidate] > _RANK[best]:
                best = candidate
    # Per-package `ecosystem_specific.severity` (PyPI/Go often use it).
    if best is None:
        for affected in payload.get("affected", []) or []:
            eco = affected.get("ecosystem_specific") if isinstance(affected, dict) else None
            eco_sev = eco.get("severity") if isinstance(eco, dict) else None
            if isinstance(eco_sev, str) and eco_sev.upper() in {
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "MODERATE",
                "LOW",
            }:
                up = eco_sev.upper()
                return Severity.MEDIUM if up == "MODERATE" else Severity(up)
    return best or Severity.UNKNOWN


_RANK = {
    Severity.UNKNOWN: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _extract_cvss_base_score(score: str) -> float | None:
    """Return the CVSS base score for a bare number or a v3.x/v4.0 vector.

    OSV severity entries carry vectors like ``CVSS:3.1/AV:N/AC:L/...``
    rather than numbers. We compute the v3.x base score per the spec
    (it is a short closed formula) and approximate v4.0 by its
    exploitability/impact metrics so HIGH/CRITICAL records are not
    silently downgraded to UNKNOWN.
    """

    score = score.strip()
    if not score:
        return None
    try:
        return float(score)
    except ValueError:
        pass
    if score.upper().startswith("CVSS:3"):
        return _cvss3_base_score(score)
    if score.upper().startswith("CVSS:4"):
        return _cvss4_approx_score(score)
    return None


def _cvss_metrics(vector: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        key, _, value = part.partition(":")
        if key and value:
            out[key.upper()] = value.upper()
    return out


def _roundup(value: float) -> float:
    # CVSS v3.1 Roundup: smallest number, to 1 decimal, >= input.
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (int_input // 10000 + 1) / 10.0


def _cvss3_base_score(vector: str) -> float | None:
    m = _cvss_metrics(vector)
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
        ac = {"L": 0.77, "H": 0.44}[m["AC"]]
        ui = {"N": 0.85, "R": 0.62}[m["UI"]]
        scope_changed = m["S"] == "C"
        pr_table = (
            {"N": 0.85, "L": 0.68, "H": 0.5}
            if scope_changed
            else {"N": 0.85, "L": 0.62, "H": 0.27}
        )
        pr = pr_table[m["PR"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        c, i, a = cia[m["C"]], cia[m["I"]], cia[m["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10.0))
    return _roundup(min(impact + exploitability, 10.0))


def _cvss4_approx_score(vector: str) -> float | None:
    """Coarse CVSS v4.0 bucket: the full MacroVector table is large.

    Network-reachable, low-complexity, no-privilege, high-impact
    vectors land in CRITICAL/HIGH; everything else is at least MEDIUM
    so it is surfaced rather than dropped as UNKNOWN.
    """

    m = _cvss_metrics(vector)
    if not m:
        return None
    high_impact = any(m.get(k) == "H" for k in ("VC", "VI", "VA", "SC", "SI", "SA"))
    easy = m.get("AV") == "N" and m.get("AC") == "L" and m.get("PR") == "N"
    if high_impact and easy and m.get("UI") == "N":
        return 9.3
    if high_impact and (easy or m.get("AV") == "N"):
        return 7.5
    if high_impact:
        return 6.0
    return 4.0


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
