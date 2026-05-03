"""``Gemfile.lock`` parser.

The file is a custom indented format with a handful of top-level
section headers. We parse the ``GEM`` block's ``specs:`` list — that
is where every concrete (gem, version) pair lives:

    GEM
      remote: https://rubygems.org/
      specs:
        rake (13.2.1)
        rspec-core (3.13.0)
        rspec-core (3.13.0)
          rspec-support (~> 3.13.0)

Lines indented exactly 4 spaces under ``specs:`` are top-level gems
(and carry the version in parentheses). Lines indented 6 spaces are
their dependencies and are ignored — they're already covered by
their own top-level entry. ``PATH`` and ``GIT`` blocks are skipped
(local / VCS-sourced gems are not in OSV's database).
"""

from __future__ import annotations

import re
from pathlib import Path

from pwned_deps.parsers.base import Ecosystem, Lockfile, Package, ParseError

_SPEC_RE = re.compile(r"^\s{4}([^\s(]+)\s+\(([^)]+)\)\s*$")


def parse(path: str | Path) -> Lockfile:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ParseError(f"{path}: lockfile not found") from exc
    except OSError as exc:
        raise ParseError(f"{path}: could not read lockfile ({exc})") from exc

    in_gem = False
    in_specs = False
    out: list[Package] = []
    seen: set[tuple[str, str]] = set()

    for raw in text.splitlines():
        # Top-level section header (no leading spaces).
        if raw and not raw.startswith(" "):
            in_gem = raw.strip() == "GEM"
            in_specs = False
            continue
        if not in_gem:
            continue
        if raw.strip() == "specs:":
            in_specs = True
            continue
        if not in_specs:
            continue
        match = _SPEC_RE.match(raw)
        if not match:
            continue
        name = match.group(1)
        version = match.group(2).strip()
        # The version captured between ()'s should be a concrete pin
        # (Gemfile.lock always pins). Reject anything containing a
        # pre-release operator just in case.
        if any(ch in version for ch in "<>~="):
            continue
        if (name, version) in seen:
            continue
        seen.add((name, version))
        out.append(
            Package(
                name=name,
                version=version,
                ecosystem=Ecosystem.RUBYGEMS,
                lockfile_path=str(path),
            )
        )
    return Lockfile(path=path, ecosystem=Ecosystem.RUBYGEMS, packages=tuple(out))
