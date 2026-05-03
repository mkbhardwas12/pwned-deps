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
        """Treat MAL-* OSV IDs and EXTRA-* (campaign) IDs as malicious."""

        upper_id = self.id.upper()
        return upper_id.startswith("MAL-") or upper_id.startswith("EXTRA-")
