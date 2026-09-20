"""Registry publish-timestamp client (npm + PyPI).

Lockfiles do not record *when* a version was published, but two
0.2.0 features need that fact:

* ``compromised_maintainers`` campaign entries describe a time window
  during which an account was hijacked. With the publish timestamp
  we can turn a SUSPECT ("this package is on the list") into a
  CONFIRMED ("this exact version was published inside the window")
  or clear it entirely.
* ``--min-age N`` flags versions published fewer than N days ago —
  the "cooling-off" defence against the first hours of a campaign,
  before any advisory exists.

Network-side guarantees mirror ``osv_client``: one well-known host per
ecosystem (``registry.npmjs.org``, ``pypi.org``), ``trust_env=False``,
bounded timeouts, GET only. Publish timestamps are immutable, so
successful lookups are cached without TTL. Failures are returned as
``PublishLookup(published_at=None, reason=...)`` — never swallowed —
so callers can report what they could not evaluate.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx

from pwned_deps import __version__
from pwned_deps.advisory.cache import Cache
from pwned_deps.parsers.base import Ecosystem, Package

NPM_REGISTRY_URL = "https://registry.npmjs.org"
PYPI_URL = "https://pypi.org"
DEFAULT_TIMEOUT_SECONDS = 20.0
DEFAULT_USER_AGENT = (
    f"pwned-deps/{__version__} (+https://github.com/mkbhardwas12/pwned-deps)"
)

SUPPORTED = frozenset({Ecosystem.NPM, Ecosystem.PYPI})


@dataclass(frozen=True)
class PublishLookup:
    """Outcome of one publish-time lookup."""

    package: Package
    published_at: datetime | None
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.published_at is not None


class RegistryClient:
    """Fetch the publish timestamp of an exact ``(ecosystem, name, version)``."""

    def __init__(
        self,
        *,
        cache: Cache | None = None,
        offline: bool = False,
        npm_url: str = NPM_REGISTRY_URL,
        pypi_url: str = PYPI_URL,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        user_agent: str = DEFAULT_USER_AGENT,
        client: httpx.Client | None = None,
    ) -> None:
        self.cache = cache
        self.offline = offline
        self._npm_url = npm_url.rstrip("/")
        self._pypi_url = pypi_url.rstrip("/")
        self._owns_client = client is None
        self._client = client or httpx.Client(
            timeout=timeout,
            headers={"User-Agent": user_agent, "Accept": "application/json"},
            trust_env=False,
            follow_redirects=False,
        )
        # One registry document per npm package covers every version.
        self._npm_docs: dict[str, dict[str, Any] | str] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def publish_time(self, pkg: Package) -> PublishLookup:
        if pkg.version_unspecified or not pkg.version:
            return PublishLookup(pkg, None, "no exact version")
        if pkg.ecosystem not in SUPPORTED:
            return PublishLookup(pkg, None, f"publish time not supported for {pkg.ecosystem}")

        if self.cache is not None:
            cached = self.cache.get_publish_time(pkg.ecosystem.value, pkg.name, pkg.version)
            if cached is not None:
                parsed = parse_timestamp(cached)
                if parsed is not None:
                    return PublishLookup(pkg, parsed)
        if self.offline:
            return PublishLookup(pkg, None, "offline and publish time not in cache")

        try:
            if pkg.ecosystem is Ecosystem.NPM:
                raw = self._npm_publish_time(pkg.name, pkg.version)
            else:
                raw = self._pypi_publish_time(pkg.name, pkg.version)
        except httpx.HTTPStatusError as exc:
            return PublishLookup(pkg, None, f"registry HTTP {exc.response.status_code}")
        except httpx.HTTPError as exc:
            return PublishLookup(pkg, None, f"registry {type(exc).__name__}")
        if raw is None:
            return PublishLookup(pkg, None, "version not found in registry metadata")
        parsed = parse_timestamp(raw)
        if parsed is None:
            return PublishLookup(pkg, None, f"unparseable timestamp {raw!r}")
        if self.cache is not None:
            self.cache.put_publish_time(pkg.ecosystem.value, pkg.name, pkg.version, raw)
        return PublishLookup(pkg, parsed)

    def publish_times(self, packages: Sequence[Package]) -> dict[Package, PublishLookup]:
        return {pkg: self.publish_time(pkg) for pkg in packages}

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> RegistryClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _npm_publish_time(self, name: str, version: str) -> str | None:
        doc = self._npm_docs.get(name)
        if doc is None:
            # Scoped names keep the '@' but the '/' must be encoded.
            encoded = quote(name, safe="@")
            response = self._client.get(f"{self._npm_url}/{encoded}")
            response.raise_for_status()
            payload = response.json()
            doc = payload if isinstance(payload, dict) else "invalid"
            self._npm_docs[name] = doc
        if not isinstance(doc, dict):
            return None
        times = doc.get("time")
        if not isinstance(times, dict):
            return None
        value = times.get(version)
        return value if isinstance(value, str) else None

    def _pypi_publish_time(self, name: str, version: str) -> str | None:
        response = self._client.get(f"{self._pypi_url}/pypi/{quote(name)}/{quote(version)}/json")
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            return None
        urls = payload.get("urls")
        if not isinstance(urls, list):
            return None
        stamps = [
            u.get("upload_time_iso_8601") or u.get("upload_time")
            for u in urls
            if isinstance(u, dict)
        ]
        stamps = [s for s in stamps if isinstance(s, str) and s]
        if not stamps:
            return None
        # The release "happened" when its first file landed.
        parsed = [(parse_timestamp(s), s) for s in stamps]
        parsed = [(dt, s) for dt, s in parsed if dt is not None]
        if not parsed:
            return None
        return min(parsed, key=lambda p: p[0])[1]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def parse_timestamp(value: str) -> datetime | None:
    """Parse an ISO-8601 timestamp into an aware UTC datetime.

    Accepts the shapes npm, PyPI and ``extras.json`` use
    (``2026-05-01T00:00:00Z``, ``...00.123Z``, ``...00.123456+00:00``,
    date-only ``2026-05-01``). Python 3.10's ``fromisoformat`` does not
    accept a trailing ``Z``, hence the normalisation.
    """

    text = value.strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
