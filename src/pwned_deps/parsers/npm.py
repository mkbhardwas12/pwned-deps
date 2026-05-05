"""npm `package-lock.json` and `npm-shrinkwrap.json` parser.

Handles npm lockfile schemas v1, v2, and v3. Pure JSON parsing; never
executes anything from the file.

Schema overview:

* **v1** (npm <7) — top-level ``dependencies`` is a recursive tree;
  each node has ``version`` and may have nested ``dependencies``.
* **v2** (npm 7) — adds a flat ``packages`` map keyed by paths like
  ``"node_modules/<pkg>"`` or ``"node_modules/<scope>/<pkg>"``. The
  legacy ``dependencies`` block is also present for backwards
  compatibility. We prefer ``packages`` because it is fully resolved.
* **v3** (npm 9+) — ``packages`` only.
* **npm-shrinkwrap.json** shares the v2/v3 schema.

The schema version is stored in ``lockfileVersion`` (1, 2, or 3).
"""

from __future__ import annotations

import json
from pathlib import Path

from pwned_deps.parsers.base import Ecosystem, Lockfile, Package, ParseError


def parse(path: str | Path) -> Lockfile:
    """Parse an npm lockfile and return the contained packages.

    Args:
        path: filesystem path to ``package-lock.json`` or
            ``npm-shrinkwrap.json``.

    Returns:
        ``Lockfile`` with ``ecosystem == Ecosystem.NPM``.

    Raises:
        ParseError: file is missing, unreadable, malformed JSON, or
            an unsupported schema version.
    """

    path = Path(path)
    raw = _read_text(path)
    data = _parse_json(path, raw)

    version = data.get("lockfileVersion")
    if version not in (1, 2, 3):
        raise ParseError(
            f"{path}: unsupported lockfileVersion {version!r}. "
            "pwned-deps supports npm package-lock.json v1, v2, v3 and "
            "npm-shrinkwrap.json."
        )

    if version == 1:
        packages = _from_v1_dependencies(data, lockfile_path=str(path))
    else:
        packages = _from_v2_packages(data, lockfile_path=str(path))

    return Lockfile(path=path, ecosystem=Ecosystem.NPM, packages=tuple(packages))


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ParseError(f"{path}: lockfile not found") from exc
    except OSError as exc:
        raise ParseError(f"{path}: could not read lockfile ({exc})") from exc


def _parse_json(path: Path, raw: str) -> dict:
    try:
        data = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as exc:
        raise ParseError(
            f"{path}: not valid JSON ({exc.msg} at line {exc.lineno}, col {exc.colno})"
        ) from exc
    if not isinstance(data, dict):
        raise ParseError(f"{path}: top-level value must be a JSON object")
    return data


def _from_v2_packages(data: dict, *, lockfile_path: str) -> list[Package]:
    """Walk the flat ``packages`` map of a v2/v3 lockfile.

    Map keys are filesystem-style paths:
      - ``""`` is the project root — skip.
      - ``"node_modules/foo"`` is the `foo` package.
      - ``"node_modules/@scope/foo"`` is the scoped `@scope/foo` package.
      - Nested ``"node_modules/foo/node_modules/bar"`` carries
        information about the dependency chain. We extract the package
        name from the *last* `node_modules/` segment.

    Entries with ``"link": true`` are workspace symlinks — skip; they
    have no version and aren't installed packages.
    """

    packages_map = data.get("packages")
    if packages_map is None:
        return []
    if not isinstance(packages_map, dict):
        raise ParseError(
            f"{lockfile_path}: 'packages' must be a JSON object, got {type(packages_map).__name__}"
        )

    results: list[Package] = []
    for key, entry in packages_map.items():
        if key == "":
            continue  # the project root
        if not isinstance(entry, dict):
            continue
        if entry.get("link") is True:
            continue
        version = entry.get("version")
        if not isinstance(version, str) or not version:
            continue
        name = _name_from_packages_key(key)
        if name is None:
            continue
        results.append(
            Package(
                name=name,
                version=version,
                ecosystem=Ecosystem.NPM,
                lockfile_path=lockfile_path,
            )
        )
    return results


def _name_from_packages_key(key: str) -> str | None:
    """Extract the package name from a v2/v3 ``packages`` map key.

    The name is the suffix after the *last* ``node_modules/`` segment.
    For scoped packages, that suffix has two slash-separated parts.
    """

    marker = "node_modules/"
    idx = key.rfind(marker)
    if idx < 0:
        return None
    suffix = key[idx + len(marker) :]
    if not suffix:
        return None
    if suffix.startswith("@"):
        # scoped: "@scope/name"
        parts = suffix.split("/", 2)
        if len(parts) < 2 or not parts[1]:
            return None
        return parts[0] + "/" + parts[1]
    # unscoped: take everything up to the next slash
    return suffix.split("/", 1)[0]


def _from_v1_dependencies(data: dict, *, lockfile_path: str) -> list[Package]:
    """Walk the recursive ``dependencies`` tree of a v1 lockfile."""

    deps = data.get("dependencies")
    if deps is None:
        return []
    if not isinstance(deps, dict):
        raise ParseError(
            f"{lockfile_path}: 'dependencies' must be a JSON object, got {type(deps).__name__}"
        )

    out: list[Package] = []
    _walk_v1(deps, parents=(), out=out, lockfile_path=lockfile_path)
    return out


def _walk_v1(
    deps: dict,
    *,
    parents: tuple[str, ...],
    out: list[Package],
    lockfile_path: str,
) -> None:
    for name, entry in deps.items():
        if not isinstance(entry, dict):
            continue
        version = entry.get("version")
        if isinstance(version, str) and version:
            out.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.NPM,
                    lockfile_path=lockfile_path,
                    parents=parents,
                )
            )
        nested = entry.get("dependencies")
        if isinstance(nested, dict):
            _walk_v1(
                nested,
                parents=(*parents, name),
                out=out,
                lockfile_path=lockfile_path,
            )
