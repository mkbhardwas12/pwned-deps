"""Combine OSV results with `extras.json` campaigns into Findings.

0.2.0 adds an optional :class:`RegistryClient` that supplies publish
timestamps. When present:

* a ``compromised_maintainers`` SUSPECT hit is *resolved*: version
  published inside the compromise window -> CONFIRMED malicious;
  published outside it -> cleared (dropped); timestamp unavailable ->
  stays SUSPECT.
* ``min_age_days`` flags versions younger than the threshold as
  ``MIN-AGE`` policy findings (HIGH, non-malicious -> exit 2).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from pwned_deps.advisory.extras import CampaignMatch, ExtrasFeed
from pwned_deps.advisory.osv_client import OsvClient, Unchecked
from pwned_deps.advisory.registry import RegistryClient, parse_timestamp
from pwned_deps.advisory.types import Advisory, Severity
from pwned_deps.parsers.base import Lockfile, Package

MIN_AGE_RULE_ID = "MIN-AGE"


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

    @property
    def is_policy(self) -> bool:
        """True for --min-age findings (a policy, not an advisory)."""

        return self.advisory.id == MIN_AGE_RULE_ID


@dataclass
class MatchResult:
    """Findings plus the packages whose lookup did not complete."""

    findings: list[Finding] = field(default_factory=list)
    unchecked: list[Unchecked] = field(default_factory=list)


class Matcher:
    """Run a lockfile through OSV + extras and produce findings."""

    def __init__(
        self,
        *,
        osv_client: OsvClient,
        extras: ExtrasFeed,
        registry: RegistryClient | None = None,
        min_age_days: int | None = None,
        now: datetime | None = None,
    ) -> None:
        self._osv = osv_client
        self._extras = extras
        self._registry = registry
        self._min_age_days = min_age_days
        self._now = now

    def match(self, lockfile: Lockfile) -> list[Finding]:
        return self.match_detailed(lockfile).findings

    def match_detailed(self, lockfile: Lockfile) -> MatchResult:
        out: list[Finding] = []
        unchecked: list[Unchecked] = []

        # Extras campaigns are checked first so the user always sees
        # them in the report even if OSV is offline.
        seen: set[tuple[str, str, str]] = set()
        for hit in self._extras.find_matches(lockfile):
            finding = self._resolve_campaign_hit(hit)
            if finding is None:
                continue
            key = (finding.package.name, finding.package.version, finding.advisory.id)
            if key in seen:
                continue
            seen.add(key)
            out.append(finding)

        # OSV pass — query every package, including ones already
        # flagged by extras (an extras campaign and an OSV MAL-* may
        # both apply, and we want to show both).
        targets = _match_targets(lockfile.packages)
        batch = self._osv.query_batch_detailed(targets)
        unchecked.extend(batch.unchecked)
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

        if self._min_age_days is not None and self._registry is not None:
            findings, missing = self._min_age_findings(targets)
            out.extend(findings)
            unchecked.extend(missing)

        return MatchResult(findings=out, unchecked=unchecked)

    # ------------------------------------------------------------------
    # Publish-time resolution
    # ------------------------------------------------------------------

    def _resolve_campaign_hit(self, hit: CampaignMatch) -> Finding | None:
        """Turn a campaign hit into a Finding, resolving SUSPECTs if we can.

        Exact-version hits are CONFIRMED as-is. Maintainer-window
        SUSPECT hits stay SUSPECT (HIGH, non-malicious -> exit 2)
        unless a registry publish timestamp proves the version was
        published inside the window (-> CONFIRMED) or outside it
        (-> cleared).
        """

        if not hit.is_suspect:
            return Finding(
                package=hit.package,
                advisory=hit.advisory,
                is_malicious=True,
                campaign_name=hit.campaign_name,
            )

        suspect = Finding(
            package=hit.package,
            advisory=hit.advisory,
            is_malicious=False,
            campaign_name=hit.campaign_name,
        )
        if self._registry is None:
            return suspect
        raw = hit.advisory.raw if isinstance(hit.advisory.raw, dict) else {}
        maintainer = raw.get("maintainer")
        campaign = raw.get("campaign")
        if not isinstance(maintainer, dict) or not isinstance(campaign, dict):
            return suspect
        after = parse_timestamp(str(maintainer.get("compromised_after") or ""))
        until = parse_timestamp(str(maintainer.get("compromised_until") or ""))
        if after is None:
            return suspect  # no window declared -> nothing to resolve against

        lookup = self._registry.publish_time(hit.package)
        if lookup.published_at is None:
            return suspect
        published = lookup.published_at
        inside = published >= after and (until is None or published <= until)
        if not inside:
            return None
        return Finding(
            package=hit.package,
            advisory=_confirmed_by_timestamp(campaign, maintainer, hit.package, published),
            is_malicious=True,
            campaign_name=hit.campaign_name,
        )

    def _min_age_findings(
        self, packages: Sequence[Package]
    ) -> tuple[list[Finding], list[Unchecked]]:
        if self._registry is None or self._min_age_days is None:
            return [], []
        now = self._now or datetime.now(timezone.utc)
        threshold = timedelta(days=self._min_age_days)
        findings: list[Finding] = []
        missing: list[Unchecked] = []
        for pkg in packages:
            lookup = self._registry.publish_time(pkg)
            if lookup.published_at is None:
                if lookup.reason.startswith("publish time not supported"):
                    continue  # ecosystem without a timestamp source; not a failure
                missing.append(Unchecked(pkg, f"min-age: {lookup.reason}"))
                continue
            age = now - lookup.published_at
            if age < threshold:
                findings.append(
                    Finding(
                        package=pkg,
                        advisory=_min_age_advisory(
                            pkg, lookup.published_at, age, self._min_age_days
                        ),
                        is_malicious=False,
                        campaign_name=None,
                    )
                )
        return findings, missing


def _match_targets(packages: Sequence[Package]) -> list[Package]:
    """Filter out unpinned entries before sending to OSV."""

    return [p for p in packages if not p.version_unspecified]


def _confirmed_by_timestamp(
    campaign: dict[str, Any],
    maintainer: dict[str, Any],
    pkg: Package,
    published: datetime,
) -> Advisory:
    references = tuple(r for r in campaign.get("references", []) if isinstance(r, str))
    handle = maintainer.get("name", "unknown-maintainer")
    window = str(maintainer.get("compromised_after", "?"))
    until = maintainer.get("compromised_until")
    if isinstance(until, str):
        window += f" to {until}"
    else:
        window += " onwards"
    name = campaign.get("name")
    summary = (
        f"CONFIRMED by publish timestamp: {pkg.name}@{pkg.version} was published "
        f"{published.isoformat()} — inside the window ({window}) during which "
        f"maintainer '{handle}' was compromised."
    )
    if isinstance(name, str) and name:
        summary = f"{name} — {summary}"
    return Advisory(
        id=str(campaign.get("id", "EXTRA")),
        summary=summary,
        ecosystem=pkg.ecosystem.value,
        package=pkg.name,
        version=pkg.version,
        references=references,
        severity=Severity.CRITICAL,
        raw={
            "campaign": campaign,
            "maintainer": maintainer,
            "match_type": "compromised_maintainer_confirmed",
            "published_at": published.isoformat(),
        },
    )


def _min_age_advisory(
    pkg: Package, published: datetime, age: timedelta, min_age_days: int
) -> Advisory:
    hours = int(age.total_seconds() // 3600)
    age_text = f"{hours} hour(s)" if hours < 48 else f"{age.days} day(s)"
    return Advisory(
        id=MIN_AGE_RULE_ID,
        summary=(
            f"{pkg.name}@{pkg.version} was published {published.isoformat()} "
            f"({age_text} ago) — younger than the --min-age {min_age_days} day "
            f"cooling-off policy. Most hijacked releases are pulled within days; "
            f"wait, or pin the previous version."
        ),
        ecosystem=pkg.ecosystem.value,
        package=pkg.name,
        version=pkg.version,
        references=(),
        severity=Severity.HIGH,
        raw={
            "match_type": "min_age",
            "published_at": published.isoformat(),
            "age_seconds": int(age.total_seconds()),
            "min_age_days": min_age_days,
        },
    )
