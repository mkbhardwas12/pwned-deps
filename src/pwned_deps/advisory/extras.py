"""Repo-managed campaign feed.

`extras.json` ships inside the package and is updated by maintainers
when a supply-chain campaign is announced and OSV hasn't yet ingested
it. The schema is documented in CONTRIBUTING.md.

This module loads the bundled feed and any user-supplied feed paths
(allow-listed by the CLI). It produces synthetic ``Advisory`` records
(one per matching campaign x package) so the rest of the pipeline can
treat campaigns and OSV findings uniformly.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from pwned_deps.advisory.types import Advisory, Severity
from pwned_deps.advisory.version_match import matches as version_matches
from pwned_deps.parsers.base import Lockfile, Package


@dataclass(frozen=True)
class CampaignMatch:
    """A campaign hit bound to the package it matched.

    ``is_suspect`` distinguishes two confidence tiers:

    * False (default) — exact ``(name, version)`` match against the
      campaign's ``packages`` block. This is a CONFIRMED malicious
      install; renderer marks as MALICIOUS and CLI exits 1.
    * True — the package name appears in a ``compromised_maintainers``
      block but we cannot prove the *version* in the lockfile was the
      one published while the maintainer account was compromised
      (lockfiles don't carry publish timestamps). The user should
      treat this as a HIGH-severity warning to investigate, not a
      confirmed compromise. Renderer marks as SUSPECT and CLI exits 2.
    """

    package: Package
    advisory: Advisory
    campaign_name: str
    is_suspect: bool = False


class ExtrasFeed:
    """Holds parsed campaign records from one or more sources."""

    def __init__(self, campaigns: Sequence[dict[str, Any]]) -> None:
        self._campaigns: list[dict[str, Any]] = list(campaigns)

    @classmethod
    def from_bundled(
        cls,
        *,
        user_paths: Iterable[Path] = (),
    ) -> ExtrasFeed:
        """Load bundled `extras.json` plus optional user-supplied files.

        User feeds are gated by the caller (the CLI's
        ``--feed-url`` / ``--feed-file`` flags). This module accepts
        only filesystem paths; URL fetching is the CLI's job so the
        allow-list policy lives in one place.
        """

        bundle = resources.files("pwned_deps.extras_data").joinpath("extras.json")
        with bundle.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        campaigns = list(_iter_campaigns(data))
        for path in user_paths:
            campaigns.extend(_load_user_feed(path))
        return cls(campaigns)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExtrasFeed:
        return cls(list(_iter_campaigns(data)))

    @property
    def campaigns(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._campaigns)

    def find_matches(self, lockfile: Lockfile) -> list[CampaignMatch]:
        """Return campaign hits for the packages in ``lockfile``.

        Two match paths:

        1. Exact ``(name, version)`` against the campaign's ``packages``
           block — emitted as a CONFIRMED hit (``is_suspect=False``).
        2. Package name appears in any ``compromised_maintainers[].packages``
           list — emitted as a SUSPECT hit (``is_suspect=True``).

        Both paths can fire for the same package; deduplication by
        advisory id happens upstream in the matcher.
        """

        out: list[CampaignMatch] = []
        for campaign in self._campaigns:
            campaign_eco = campaign.get("ecosystem")
            out.extend(self._exact_version_matches(lockfile, campaign, campaign_eco))
            out.extend(self._maintainer_suspect_matches(lockfile, campaign, campaign_eco))
        return out

    def _exact_version_matches(
        self,
        lockfile: Lockfile,
        campaign: dict[str, Any],
        campaign_eco: Any,
    ) -> list[CampaignMatch]:
        out: list[CampaignMatch] = []
        packages_block = campaign.get("packages", [])
        if not isinstance(packages_block, list):
            return out
        for entry in packages_block:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name")
                versions = entry.get("versions")
                # Per-package ecosystem override: a single campaign may
                # cover packages on multiple ecosystems (e.g. Mini Shai-Hulud
                # follow-on — intercom-client on npm, lightning on PyPI).
                # If the entry doesn't specify, fall back to the campaign-
                # level value.
                ecosystem = entry.get("ecosystem", campaign_eco)
                if not isinstance(ecosystem, str):
                    continue
                if not isinstance(name, str) or not isinstance(versions, list):
                    continue
                for pkg in lockfile.packages:
                    if pkg.version_unspecified:
                        continue
                    if pkg.ecosystem.value != ecosystem:
                        continue
                    if pkg.name != name:
                        continue
                    if not _any_spec_matches(pkg.version, versions, ecosystem):
                        continue
                    out.append(
                        CampaignMatch(
                            package=pkg,
                            advisory=_advisory_from_campaign(campaign, entry, pkg),
                            campaign_name=str(campaign.get("name", campaign.get("id", "extras"))),
                        )
                    )
        return out

    def _maintainer_suspect_matches(
        self,
        lockfile: Lockfile,
        campaign: dict[str, Any],
        campaign_eco: Any,
    ) -> list[CampaignMatch]:
        out: list[CampaignMatch] = []
        block = campaign.get("compromised_maintainers", [])
        if not isinstance(block, list):
            return out
        # Collect already-confirmed (name, version) pairs in this campaign
        # so we don't double-emit a SUSPECT for something already CONFIRMED.
        confirmed_names: set[tuple[str, str]] = set()
        for entry in campaign.get("packages", []) or []:
            if not isinstance(entry, dict):
                continue
            n = entry.get("name")
            eco = entry.get("ecosystem", campaign_eco)
            if isinstance(n, str) and isinstance(eco, str):
                confirmed_names.add((eco, n))
        for maintainer in block:
            if not isinstance(maintainer, dict):
                continue
            ecosystem = maintainer.get("ecosystem", campaign_eco)
            if not isinstance(ecosystem, str):
                continue
            pkg_names = maintainer.get("packages", [])
            if not isinstance(pkg_names, list):
                continue
            wanted_names = {n for n in pkg_names if isinstance(n, str)}
            for pkg in lockfile.packages:
                if pkg.version_unspecified:
                    continue
                if pkg.ecosystem.value != ecosystem:
                    continue
                if pkg.name not in wanted_names:
                    continue
                if (ecosystem, pkg.name) in confirmed_names:
                    # Already covered by an exact-version entry; no need
                    # to additionally surface as SUSPECT.
                    continue
                out.append(
                    CampaignMatch(
                        package=pkg,
                        advisory=_suspect_advisory_from_maintainer(
                            campaign, maintainer, pkg
                        ),
                        campaign_name=str(
                            campaign.get("name", campaign.get("id", "extras"))
                        ),
                        is_suspect=True,
                    )
                )
        return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iter_campaigns(data: dict[str, Any]) -> Iterable[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    block = data.get("campaigns", [])
    if not isinstance(block, list):
        return []
    return [c for c in block if isinstance(c, dict)]


def _load_user_feed(path: Path) -> list[dict[str, Any]]:
    if not path.exists() or not path.is_file():
        return []
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []
    return list(_iter_campaigns(data))


def _any_spec_matches(version: str, specs: list[Any], ecosystem: str) -> bool:
    for spec in specs:
        if not isinstance(spec, str):
            continue
        if version_matches(version, spec, ecosystem=ecosystem):
            return True
    return False


def _advisory_from_campaign(
    campaign: dict[str, Any],
    package_entry: dict[str, Any],
    pkg: Package,
) -> Advisory:
    references = tuple(
        ref
        for ref in campaign.get("references", [])
        if isinstance(ref, str)
    )
    summary_parts = []
    name = campaign.get("name")
    summary = campaign.get("summary")
    if isinstance(name, str):
        summary_parts.append(name)
    if isinstance(summary, str):
        summary_parts.append(summary)
    return Advisory(
        id=str(campaign.get("id", "EXTRA")),
        summary=" — ".join(p for p in summary_parts if p),
        ecosystem=pkg.ecosystem.value,
        package=pkg.name,
        version=pkg.version,
        references=references,
        severity=Severity.CRITICAL,
        raw={
            "campaign": campaign,
            "package_entry": package_entry,
        },
    )


def _suspect_advisory_from_maintainer(
    campaign: dict[str, Any],
    maintainer: dict[str, Any],
    pkg: Package,
) -> Advisory:
    """Build a HIGH-severity advisory for a maintainer-suspect hit.

    Distinct ``id`` (``<campaign_id>-suspect-<maintainer>``) so it
    dedupes separately from the campaign's exact-version entries and
    so users can grep / mute it independently.
    """

    references = tuple(
        ref for ref in campaign.get("references", []) if isinstance(ref, str)
    )
    handle = maintainer.get("name", "unknown-maintainer")
    window = ""
    after = maintainer.get("compromised_after")
    until = maintainer.get("compromised_until")
    if isinstance(after, str) and isinstance(until, str):
        window = f" (compromised window {after} to {until})"
    elif isinstance(after, str):
        window = f" (compromised after {after})"
    summary = (
        f"SUSPECT: {pkg.name} was published by maintainer '{handle}' whose "
        f"account was compromised{window}. Versions installed during the "
        f"window should be treated as compromised; this lockfile does not "
        f"carry a publish timestamp so the match cannot be confirmed."
    )
    campaign_id = str(campaign.get("id", "EXTRA"))
    return Advisory(
        id=f"{campaign_id}-suspect-{handle}",
        summary=summary,
        ecosystem=pkg.ecosystem.value,
        package=pkg.name,
        version=pkg.version,
        references=references,
        severity=Severity.HIGH,
        raw={
            "campaign": campaign,
            "maintainer": maintainer,
            "match_type": "compromised_maintainer",
        },
    )
