"""``pnpm-lock.yaml`` parser.

The interesting block is the top-level ``packages`` map. Older
schemas key entries as ``"/<name>/<version>"`` or
``"/<scope>/<name>/<version>"``. Newer (lockfileVersion 6+) schemas
use ``"<name>@<version>"`` directly. We tolerate both.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from pwned_deps.parsers.base import Ecosystem, Lockfile, Package, ParseError


def parse(path: str | Path) -> Lockfile:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ParseError(f"{path}: lockfile not found") from exc
    except OSError as exc:
        raise ParseError(f"{path}: could not read lockfile ({exc})") from exc
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ParseError(f"{path}: not valid YAML ({exc})") from exc
    if not isinstance(data, dict):
        raise ParseError(f"{path}: top-level value must be a YAML mapping")

    packages_map = data.get("packages")
    if packages_map is None:
        return Lockfile(path=path, ecosystem=Ecosystem.NPM, packages=())
    if not isinstance(packages_map, dict):
        raise ParseError(f"{path}: 'packages' must be a YAML mapping")

    out: list[Package] = []
    seen: set[tuple[str, str]] = set()
    for key, _entry in packages_map.items():
        if not isinstance(key, str):
            continue
        parsed = _split_pnpm_key(key)
        if parsed is None:
            continue
        name, version = parsed
        if (name, version) in seen:
            continue
        seen.add((name, version))
        out.append(
            Package(
                name=name,
                version=version,
                ecosystem=Ecosystem.NPM,
                lockfile_path=str(path),
            )
        )
    return Lockfile(path=path, ecosystem=Ecosystem.NPM, packages=tuple(out))


def _split_pnpm_key(key: str) -> tuple[str, str] | None:
    """Return ``(name, version)`` from a pnpm packages-map key.

    Variants seen in the wild:
      - ``/foo/1.2.3``               (lockfileVersion 5)
      - ``/@scope/name/1.2.3``       (lockfileVersion 5, scoped)
      - ``foo@1.2.3``                (lockfileVersion 6+)
      - ``@scope/name@1.2.3``        (lockfileVersion 6+, scoped)
      - ``foo@1.2.3(peer@4.5.6)``    (peer-dep suffix; we strip it)
    """

    # Strip the peer-dep suffix `(peer@version)` parens.
    if "(" in key:
        key = key.split("(", 1)[0]

    if key.startswith("/"):
        body = key[1:]
        # Find the last '/' — the version follows it.
        slash_idx = body.rfind("/")
        if slash_idx <= 0:
            return None
        name = body[:slash_idx]
        version = body[slash_idx + 1 :]
    else:
        # name@version or @scope/name@version
        if key.startswith("@"):
            # The version separator is the SECOND '@'.
            slash_idx = key.find("/")
            if slash_idx < 0:
                return None
            after_slash = key.find("@", slash_idx)
            if after_slash < 0:
                return None
            name = key[:after_slash]
            version = key[after_slash + 1 :]
        else:
            at_idx = key.find("@")
            if at_idx < 0:
                return None
            name = key[:at_idx]
            version = key[at_idx + 1 :]
    if not name or not version:
        return None
    return name, version
