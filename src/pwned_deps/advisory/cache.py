"""Local SQLite cache for OSV advisory lookups.

Layout (deviates slightly from BUILD_BRIEF §7 Step 4 — see BUILD_LOG.md
for rationale):

* ``queries`` — one row per ``(ecosystem, package, version)`` we have
  ever asked OSV about. Records the last-fetch wall-clock so we can
  apply TTLs and distinguish "queried but no advisories" from "never
  queried".
* ``advisories`` — one row per ``(advisory_id, ecosystem, package,
  version)`` triple. Multiple rows when an advisory affects more than
  one (pkg, ver). Indexed for fast (eco, pkg, ver) lookup.

The cache is the only place where we persist OSV data. Writes happen
on success only; failures (5xx, network errors) leave the cache
untouched so the next run still has the previous good data.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from collections.abc import Iterable
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any

from pwned_deps.advisory.types import Advisory, Severity

_DEFAULT_TTL_SECONDS = 24 * 60 * 60  # 24h per BUILD_BRIEF §6


def default_cache_path() -> Path:
    """Return the platform-appropriate default cache file path.

    * Honors ``XDG_CACHE_HOME`` if set (Linux/macOS XDG users).
    * Falls back to ``~/.cache/pwned-deps/`` on Unix.
    * Uses ``%LOCALAPPDATA%\\pwned-deps\\`` on Windows.
    """

    env = os.environ.get("XDG_CACHE_HOME")
    if env:
        return Path(env) / "pwned-deps" / "osv.sqlite"
    if os.name == "nt":  # pragma: no cover — Windows-only branch
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            return Path(local_app_data) / "pwned-deps" / "osv.sqlite"
    return Path.home() / ".cache" / "pwned-deps" / "osv.sqlite"


_CREATE_TABLES = (
    """
    CREATE TABLE IF NOT EXISTS queries (
        ecosystem  TEXT NOT NULL,
        package    TEXT NOT NULL,
        version    TEXT NOT NULL,
        fetched_at INTEGER NOT NULL,
        PRIMARY KEY (ecosystem, package, version)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS advisories (
        id           TEXT NOT NULL,
        ecosystem    TEXT NOT NULL,
        package      TEXT NOT NULL,
        version      TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        fetched_at   INTEGER NOT NULL,
        PRIMARY KEY (id, ecosystem, package, version)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_pkg
        ON advisories (ecosystem, package, version)
    """,
)


class Cache:
    """SQLite-backed cache. Thread-safe per-instance.

    Constructed with a file path. Calling ``close()`` closes the
    underlying connection; the instance is also a context manager.
    """

    def __init__(
        self,
        path: Path,
        *,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
        clock: Any = time.time,
    ) -> None:
        self.path = Path(path)
        self.ttl_seconds = ttl_seconds
        self._clock = clock
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        for stmt in _CREATE_TABLES:
            self._conn.execute(stmt)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(
        self,
        ecosystem: str,
        package: str,
        version: str,
    ) -> list[Advisory] | None:
        """Return cached advisories or ``None`` if no fresh row exists.

        ``None`` distinguishes "never queried / TTL-expired" from
        "queried, found nothing" (which returns ``[]``).
        """

        now = self._clock()
        cutoff = now - self.ttl_seconds
        cur = self._conn.execute(
            "SELECT fetched_at FROM queries "
            "WHERE ecosystem=? AND package=? AND version=?",
            (ecosystem, package, version),
        )
        row = cur.fetchone()
        if row is None or row[0] < cutoff:
            return None
        cur = self._conn.execute(
            "SELECT payload_json FROM advisories "
            "WHERE ecosystem=? AND package=? AND version=?",
            (ecosystem, package, version),
        )
        return [_advisory_from_payload(json.loads(p[0])) for p in cur.fetchall()]

    def put(
        self,
        ecosystem: str,
        package: str,
        version: str,
        advisories: Iterable[Advisory],
    ) -> None:
        """Replace any existing rows for ``(eco, pkg, ver)`` with ``advisories``.

        Always records the query timestamp, even when ``advisories`` is
        empty (so a "no findings" cache hit is possible).
        """

        now = int(self._clock())
        with self._tx():
            self._conn.execute(
                "DELETE FROM advisories "
                "WHERE ecosystem=? AND package=? AND version=?",
                (ecosystem, package, version),
            )
            for adv in advisories:
                self._conn.execute(
                    "INSERT OR REPLACE INTO advisories "
                    "(id, ecosystem, package, version, payload_json, fetched_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        adv.id,
                        ecosystem,
                        package,
                        version,
                        json.dumps(_advisory_to_payload(adv)),
                        now,
                    ),
                )
            self._conn.execute(
                "INSERT OR REPLACE INTO queries "
                "(ecosystem, package, version, fetched_at) "
                "VALUES (?, ?, ?, ?)",
                (ecosystem, package, version, now),
            )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Cache:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @contextmanager
    def _tx(self) -> Any:
        try:
            yield
            self._conn.commit()
        except BaseException:
            self._conn.rollback()
            raise


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def _advisory_to_payload(adv: Advisory) -> dict[str, Any]:
    """Render an Advisory to a dict suitable for json.dumps storage."""

    data = asdict(adv)
    data["severity"] = adv.severity.value
    return data


def _advisory_from_payload(payload: dict[str, Any]) -> Advisory:
    sev_raw = payload.get("severity", "UNKNOWN")
    try:
        severity = Severity(sev_raw)
    except ValueError:
        severity = Severity.UNKNOWN
    return Advisory(
        id=payload["id"],
        summary=payload.get("summary", ""),
        ecosystem=payload.get("ecosystem", ""),
        package=payload.get("package", ""),
        version=payload.get("version", ""),
        references=tuple(payload.get("references", [])),
        severity=severity,
        raw=payload.get("raw", {}),
    )
