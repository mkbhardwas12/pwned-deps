"""``go.sum`` parser.

Format: one entry per line —

    <module> <version> <hash>

Each module typically has *two* lines per (module, version): one for
the module zip itself and one for ``/go.mod``::

    example.com/foo v1.2.3 h1:abcd...
    example.com/foo v1.2.3/go.mod h1:abcd...

We dedup by ``(module, version)``. ``+incompatible`` suffixes are
preserved in the version field so OSV lookups match them verbatim.
"""

from __future__ import annotations

from pathlib import Path

from pwned_deps.parsers.base import Ecosystem, Lockfile, Package, ParseError


def parse(path: str | Path) -> Lockfile:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ParseError(f"{path}: lockfile not found") from exc
    except OSError as exc:
        raise ParseError(f"{path}: could not read lockfile ({exc})") from exc

    seen: set[tuple[str, str]] = set()
    out: list[Package] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        module = parts[0]
        version = parts[1]
        # Strip "/go.mod" suffix that doubles every entry.
        if version.endswith("/go.mod"):
            version = version[: -len("/go.mod")]
        if (module, version) in seen:
            continue
        seen.add((module, version))
        out.append(
            Package(
                name=module,
                version=version,
                ecosystem=Ecosystem.GO,
                lockfile_path=str(path),
            )
        )
    if not out and text.strip():
        # Got non-empty input but couldn't extract anything — flag.
        raise ParseError(
            f"{path}: no usable entries found. Each line should be "
            "`<module> <version> <hash>`."
        )
    return Lockfile(path=path, ecosystem=Ecosystem.GO, packages=tuple(out))
