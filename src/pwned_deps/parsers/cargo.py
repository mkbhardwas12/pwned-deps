"""``Cargo.lock`` parser.

TOML format, an array of ``[[package]]`` tables, each with at least
``name`` and ``version``. Workspace virtual roots and path-only crates
have no source; we still report them with their declared version.
"""

from __future__ import annotations

from pathlib import Path

try:
    import tomllib as _toml
except ModuleNotFoundError:
    import tomli as _toml  # type: ignore[no-redef]

from pwned_deps.parsers.base import Ecosystem, Lockfile, Package, ParseError


def parse(path: str | Path) -> Lockfile:
    path = Path(path)
    try:
        with path.open("rb") as fh:
            data = _toml.load(fh)
    except FileNotFoundError as exc:
        raise ParseError(f"{path}: lockfile not found") from exc
    except OSError as exc:
        raise ParseError(f"{path}: could not read lockfile ({exc})") from exc
    except _toml.TOMLDecodeError as exc:
        raise ParseError(f"{path}: not valid TOML ({exc})") from exc

    package_block = data.get("package", [])
    if not isinstance(package_block, list):
        raise ParseError(f"{path}: 'package' must be an array of tables")

    out: list[Package] = []
    for entry in package_block:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        version = entry.get("version")
        if not isinstance(name, str) or not name:
            continue
        if not isinstance(version, str) or not version:
            continue
        out.append(
            Package(
                name=name,
                version=version,
                ecosystem=Ecosystem.CRATES,
                lockfile_path=str(path),
            )
        )
    return Lockfile(path=path, ecosystem=Ecosystem.CRATES, packages=tuple(out))
