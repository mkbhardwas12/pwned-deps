"""Composer ``composer.lock`` parser.

The JSON lockfile stores registry packages in ``packages`` and development
dependencies in ``packages-dev``. Parsing is inert; Composer is never run.
"""

from __future__ import annotations

import json
from pathlib import Path

from pwned_deps.parsers.base import Ecosystem, Lockfile, Package, ParseError


def parse(path: str | Path) -> Lockfile:
    """Parse Composer package and development lockfile entries."""

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

    packages: list[Package] = []
    for section in ("packages", "packages-dev"):
        entries = data.get(section, [])
        if not isinstance(entries, list):
            raise ParseError(f"{path}: '{section}' must be a JSON array")
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            version = entry.get("version")
            if not isinstance(name, str) or not name:
                continue
            if not isinstance(version, str) or not version:
                continue
            version = version.removeprefix("v")
            if not version:
                continue
            packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.PACKAGIST,
                    lockfile_path=str(path),
                )
            )

    return Lockfile(path=path, ecosystem=Ecosystem.PACKAGIST, packages=tuple(packages))
