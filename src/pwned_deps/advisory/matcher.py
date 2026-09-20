"""Combine OSV results with `extras.json` campaigns into Findings."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from pwned_deps.advisory.extras import ExtrasFeed
from pwned_deps.advisory.osv_client import OsvClient, Unchecked
from pwned_deps.advisory.types import Advisory, Severity
from pwned_deps.parsers.base import Lockfile, Package


@dataclass(frozen=True)
class Finding:
    """A single advisory bound to a single (package, version)."""

    package: Package
    advisory: Advisory
    is_malicious: bool
    campaign_name: str | None = None

    @property
    def severity(self) -> Severity:
        return self.advisory.severity


@dataclass
class MatchResult:
    """Findings plus the packages whose lookup did not complete."""

    findings: list[Finding] = field(default_factory=list)
    unchecked: list[Unchecked] = field(default_factory=list)


class Matcher:
    """Run a lockfile through OSV + extras and produce findings."""

    def __init__(self, *, osv_client: OsvClient, extras: ExtrasFeed) -> None:
        self._osv = osv_client
        self._extras = extras

    def match(self, lockfile: Lockfile) -> list[Finding]:
        return self.match_detailed(lockfile).findings

    def match_detailed(self, lockfile: Lockfile) -> MatchResult:
        out: list[Finding] = []

        # Extras campaigns are checked first so the user always sees
        # them in the report even if OSV is offline.
        seen: set[tuple[str, str, str]] = set()
        for hit in self._extras.find_matches(lockfile):
            key = (hit.package.name, hit.package.version, hit.advisory.id)
            seen.add(key)
            # Maintainer-suspect hits are NOT marked is_malicious=True
            # (we cannot prove the version in the lockfile is the bad
            # one without a publish timestamp). They still surface as
            # HIGH-severity findings -> exit 2.
            out.append(
                Finding(
                    package=hit.package,
                    advisory=hit.advisory,
                    is_malicious=not hit.is_suspect,
                    campaign_name=hit.campaign_name,
                )
            )

        # OSV pass — query every package, including ones already
        # flagged by extras (an extras campaign and an OSV MAL-* may
        # both apply, and we want to show both).
        batch = self._osv.query_batch_detailed(_match_targets(lockfile.packages))
        for pkg, advisories in batch.advisories.items():
            for adv in advisories:
                key = (pkg.name, pkg.version, adv.id)
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    Finding(
                        package=pkg,
                        advisory=adv,
                        is_malicious=adv.is_malicious,
                        campaign_name=None,
                    )
                )
        return MatchResult(findings=out, unchecked=list(batch.unchecked))


def _match_targets(packages: Sequence[Package]) -> list[Package]:
    """Filter out unpinned entries before sending to OSV."""

    return [p for p in packages if not p.version_unspecified]
