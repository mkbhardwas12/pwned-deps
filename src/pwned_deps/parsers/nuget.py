"""NuGet ``packages.lock.json`` parser.

``dotnet restore --use-lock-file`` writes one block per target framework
under ``dependencies``, mapping each package ID to its resolution::

    {
      "version": 1,
      "dependencies": {
        "net8.0": {
          "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"},
          "System.Text.Json": {"type": "Transitive", "resolved": "8.0.4"}
        }
      }
    }

A multi-target project repeats most of its graph under every framework, so
``(id, version)`` pairs are deduplicated. Package IDs are case-insensitive,
hence the dedupe key is case-folded; the reported name keeps the casing the
lockfile used, which is the registry casing OSV advisories are keyed on.
``"type": "Project"`` entries are sibling projects in the same solution
rather than registry packages and carry no ``resolved`` version, so they
drop out. Parsing is inert; ``dotnet`` is never run.
"""

from __future__ import annotations

import json
from pathlib import Path

from pwned_deps.parsers.base import Ecosystem, Lockfile, Package, ParseError


def parse(path: str | Path) -> Lockfile:
    """Parse resolved NuGet packages from every target-framework block."""

    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ParseError(f"{path}: lockfile not found") from exc
    except OSError as exc:
        raise ParseError(f"{path}: could not read lockfile ({exc})") from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ParseError(
            f"{path}: not valid JSON ({exc.msg} at line {exc.lineno}, col {exc.colno})"
        ) from exc
    if not isinstance(data, dict):
        raise ParseError(f"{path}: top-level value must be a JSON object")

    frameworks = data.get("dependencies", {})
    if not isinstance(frameworks, dict):
        raise ParseError(f"{path}: 'dependencies' must be a JSON object")

    packages: list[Package] = []
    seen: set[tuple[str, str]] = set()
    for entries in frameworks.values():
        if not isinstance(entries, dict):
            continue
        for name, entry in entries.items():
            if not isinstance(name, str) or not name or not isinstance(entry, dict):
                continue
            version = entry.get("resolved")
            if not isinstance(version, str) or not version:
                continue
            key = (name.lower(), version)
            if key in seen:
                continue
            seen.add(key)
            packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.NUGET,
                    lockfile_path=str(path),
                )
            )

    return Lockfile(path=path, ecosystem=Ecosystem.NUGET, packages=tuple(packages))
