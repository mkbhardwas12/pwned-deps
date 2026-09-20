"""Advisory + severity dataclasses, shared across OSV and extras."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Five-level severity scale we map every advisory into.

    OSV does not always expose a severity; when it doesn't we use
    ``UNKNOWN``. MAL-* advisories are reported as ``CRITICAL``
    regardless of any CVSS data because they describe a malicious
    package version, not a code-quality bug.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Advisory:
    """A single advisory record bound to a (eco, pkg, ver) tuple.

    ``raw`` is the full OSV payload for `--explain`. We keep it so the
    CLI can render rich detail without needing another network call.
    """

    id: str
    summary: str
    ecosystem: str
    package: str
    version: str
    references: tuple[str, ...] = field(default_factory=tuple)
    severity: Severity = Severity.UNKNOWN
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_malicious(self) -> bool:
        """Treat MAL-* OSV IDs and EXTRA-* (campaign) IDs as malicious.

        GHSA malware advisories are also caught when the MAL-* alias
        exists on the record, or when the record is tagged as malware
        (GitHub publishes "Malicious code in <pkg>" before the OpenSSF
        MAL-* mirror lands).
        """

        upper_id = self.id.upper()
        if upper_id.startswith("MAL-") or upper_id.startswith("EXTRA-"):
            return True
        aliases = self.raw.get("aliases") if isinstance(self.raw, dict) else None
        if isinstance(aliases, list) and any(
            isinstance(a, str) and a.upper().startswith("MAL-") for a in aliases
        ):
            return True
        db = self.raw.get("database_specific") if isinstance(self.raw, dict) else None
        if isinstance(db, dict) and db.get("malware") is True:
            return True
        return self.summary.lower().startswith("malicious code in ")
