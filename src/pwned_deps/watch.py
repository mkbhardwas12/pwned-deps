"""``pwned-deps watch`` — baseline + delta alerting.

The watch workflow answers the question:

    "I scanned my lockfile yesterday and it was clean. Did anything I
    already have installed become flagged overnight?"

This is the recurring-value use case: run a fresh ``pwned-deps check``
once a day in CI; if any package version that was *already* in your
baseline is now flagged, fail the build. New compromises affecting
packages you don't depend on don't fire — only ones you actually have
installed.

Baseline file format (stable, JSON, schema_version 1):

    {
      "schema_version": "1.0",
      "generated_at": "2026-05-04T18:32:00Z",
      "tool": {"name": "pwned-deps", "version": "0.1.0"},
      "packages": [
        {"ecosystem": "npm", "name": "lodash", "version": "4.17.21"},
        ...
      ]
    }

Only the (ecosystem, name, version) tuple is stored — no path, no
hash, no machine-identifying data. The baseline is safe to commit to
the repo.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from pwned_deps.advisory.matcher import Finding
from pwned_deps.parsers.base import Lockfile, Package
from pwned_deps.report.text import ScanReport

SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class BaselinePackage:
    ecosystem: str
    name: str
    version: str

    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name, self.version)


@dataclass
class Baseline:
    generated_at: str
    tool_version: str
    packages: tuple[BaselinePackage, ...]

    @classmethod
    def from_lockfiles(
        cls,
        lockfiles: Iterable[Lockfile],
        *,
        tool_version: str,
        now: datetime | None = None,
    ) -> Baseline:
        seen: set[tuple[str, str, str]] = set()
        pkgs: list[BaselinePackage] = []
        for lf in lockfiles:
            for p in lf.packages:
                bp = BaselinePackage(
                    ecosystem=p.ecosystem.value,
                    name=p.name,
                    version=p.version or "",
                )
                if bp.key() in seen:
                    continue
                seen.add(bp.key())
                pkgs.append(bp)
        pkgs.sort(key=lambda p: p.key())
        ts = (now or datetime.now(tz=timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
        return cls(generated_at=ts, tool_version=tool_version, packages=tuple(pkgs))

    def to_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "generated_at": self.generated_at,
            "tool": {"name": "pwned-deps", "version": self.tool_version},
            "packages": [
                {"ecosystem": p.ecosystem, "name": p.name, "version": p.version}
                for p in self.packages
            ],
        }

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n")

    @classmethod
    def read(cls, path: Path) -> Baseline:
        data = json.loads(path.read_text())
        if data.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(
                f"baseline {path}: unsupported schema_version "
                f"{data.get('schema_version')!r}"
            )
        pkgs = tuple(
            BaselinePackage(
                ecosystem=p["ecosystem"], name=p["name"], version=p["version"]
            )
            for p in data.get("packages", [])
        )
        return cls(
            generated_at=data.get("generated_at", ""),
            tool_version=data.get("tool", {}).get("version", ""),
            packages=pkgs,
        )

    def keys(self) -> set[tuple[str, str, str]]:
        return {p.key() for p in self.packages}


@dataclass(frozen=True)
class WatchHit:
    """A finding for a package that was already in the baseline.

    These are the actionable signals: something you already shipped
    is now publicly flagged.
    """

    finding: Finding
    package: Package

    @property
    def key(self) -> tuple[str, str, str]:
        return (
            self.package.ecosystem.value,
            self.package.name,
            self.package.version or "",
        )


def diff(reports: Iterable[ScanReport], baseline: Baseline) -> list[WatchHit]:
    """Return findings whose (eco, pkg, ver) appears in the baseline.

    Findings on brand-new packages (not yet in the baseline) are
    intentionally NOT included — they belong to a regular ``check``
    run, not the watch workflow.
    """

    base_keys = baseline.keys()
    hits: list[WatchHit] = []
    for report in reports:
        for finding in report.findings:
            pkg = finding.package
            key = (pkg.ecosystem.value, pkg.name, pkg.version or "")
            if key in base_keys:
                hits.append(WatchHit(finding=finding, package=pkg))
    return hits
