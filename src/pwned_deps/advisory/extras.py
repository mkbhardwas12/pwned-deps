"""Repo-managed campaign feed.

`extras.json` ships inside the package and is updated by maintainers
when a supply-chain campaign is announced and OSV hasn't yet ingested
it. The schema is documented in BUILD_BRIEF §6.

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
    """A campaign hit bound to the package it matched."""

    package: Package
    advisory: Advisory
    campaign_name: str


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
        """Return campaign hits for the packages in ``lockfile``."""

        out: list[CampaignMatch] = []
        for campaign in self._campaigns:
            ecosystem = campaign.get("ecosystem")
            if not isinstance(ecosystem, str):
                continue
            packages_block = campaign.get("packages", [])
            if not isinstance(packages_block, list):
                continue
            for entry in packages_block:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name")
                versions = entry.get("versions")
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
