"""``yarn.lock`` parser supporting both v1 (classic) and v2+ (Berry).

* **v1** is a custom DSL — keys are unquoted-ish, blocks are
  indented with two spaces, no quotes around scalar values:

      "lodash@^4.17.15", "lodash@^4.17.21":
        version "4.17.21"
        resolved "https://..."

* **v2+ (Berry)** is YAML with a leading ``__metadata`` block::

      __metadata:
        version: 6
        cacheKey: ...

      "lodash@npm:^4.17.21":
        version: 4.17.21
        resolution: ...

Detection: Berry begins with ``__metadata:`` somewhere near the top.
v1 begins with the ``# yarn lockfile v1`` comment.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from pwned_deps.parsers.base import Ecosystem, Lockfile, Package, ParseError

_VERSION_RE = re.compile(r'^\s*version\s+"?([^"\s]+)"?\s*$')


def parse(path: str | Path) -> Lockfile:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ParseError(f"{path}: lockfile not found") from exc
    except OSError as exc:
        raise ParseError(f"{path}: could not read lockfile ({exc})") from exc

    if "__metadata:" in text:
        return _parse_berry(path, text)
    return _parse_v1(path, text)


# ---------------------------------------------------------------------------
# v1 classic
# ---------------------------------------------------------------------------


def _parse_v1(path: Path, text: str) -> Lockfile:
    """Block scanner — keep state across lines.

    For each block:
      - The first non-comment line ending with ``:`` is the key
        block. The keys are quoted descriptors like
        ``"lodash@^4.17.15"`` separated by ``, ``.
      - Inside the block, the line ``  version "X.Y.Z"`` carries the
        resolved version.
    """

    out: list[Package] = []
    current_keys: list[str] = []
    current_version: str | None = None
    seen: set[tuple[str, str]] = set()

    def flush() -> None:
        nonlocal current_keys, current_version
        if current_version and current_keys:
            for descriptor in current_keys:
                name = _name_from_descriptor(descriptor)
                if not name:
                    continue
                key = (name, current_version)
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    Package(
                        name=name,
                        version=current_version,
                        ecosystem=Ecosystem.NPM,
                        lockfile_path=str(path),
                    )
                )
        current_keys = []
        current_version = None

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw.startswith(" "):
            # New block starts — flush the previous one.
            flush()
            line = raw.rstrip()
            if not line.endswith(":"):
                continue
            descriptor_part = line[:-1].strip()
            current_keys = _split_v1_descriptors(descriptor_part)
            continue
        version_match = _VERSION_RE.match(raw)
        if version_match:
            current_version = version_match.group(1)
    flush()

    return Lockfile(path=path, ecosystem=Ecosystem.NPM, packages=tuple(out))


def _split_v1_descriptors(line: str) -> list[str]:
    """Split a v1 block header like ``"a@^1", "b@^2"`` into descriptors."""

    out: list[str] = []
    for raw in line.split(","):
        s = raw.strip()
        if s.startswith('"') and s.endswith('"') and len(s) >= 2:
            s = s[1:-1]
        if s:
            out.append(s)
    return out


def _name_from_descriptor(descriptor: str) -> str | None:
    """``lodash@^4.17.15`` -> ``lodash``; ``@scope/n@^1`` -> ``@scope/n``."""

    if descriptor.startswith("@"):
        # Find the '@' AFTER the first '/'.
        slash = descriptor.find("/")
        if slash < 0:
            return None
        at_idx = descriptor.find("@", slash)
        if at_idx < 0:
            return descriptor or None
        return descriptor[:at_idx]
    at_idx = descriptor.find("@")
    if at_idx < 0:
        return descriptor or None
    return descriptor[:at_idx]


# ---------------------------------------------------------------------------
# Berry (yarn v2+)
# ---------------------------------------------------------------------------


def _parse_berry(path: Path, text: str) -> Lockfile:
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ParseError(f"{path}: not valid YAML ({exc})") from exc
    if not isinstance(data, dict):
        raise ParseError(f"{path}: top-level value must be a YAML mapping")

    out: list[Package] = []
    seen: set[tuple[str, str]] = set()
    for key, entry in data.items():
        if not isinstance(key, str) or key == "__metadata":
            continue
        if not isinstance(entry, dict):
            continue
        version = entry.get("version")
        if not isinstance(version, str) or not version:
            continue
        name = _name_from_berry_key(key)
        if not name:
            continue
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


def _name_from_berry_key(key: str) -> str | None:
    """Berry keys: ``"name@npm:^1.2.3"`` or ``"name@workspace:."``.

    Multiple descriptors join with ``, `` like in v1.
    """

    first_descriptor = key.split(",")[0].strip()
    if first_descriptor.startswith("@"):
        slash = first_descriptor.find("/")
        if slash < 0:
            return None
        at_idx = first_descriptor.find("@", slash)
        if at_idx < 0:
            return first_descriptor or None
        return first_descriptor[:at_idx]
    at_idx = first_descriptor.find("@")
    if at_idx < 0:
        return first_descriptor or None
    return first_descriptor[:at_idx]
