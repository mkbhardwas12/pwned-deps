"""Shared dataclasses + ecosystem enum used by every parser.

Vocabulary matches OSV.dev so we can ship `(ecosystem, name, version)`
tuples straight to `POST /v1/querybatch` without translation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Ecosystem(str, Enum):
    """OSV-vocabulary ecosystem identifiers.

    Values are exactly the strings OSV expects in batch queries; do not
    rename casually. Subclassing `str` so ``Ecosystem.NPM == "npm"``
    holds and JSON serialisation is trivial.
    """

    NPM = "npm"
    PYPI = "PyPI"
    CRATES = "crates.io"
    GO = "Go"
    MAVEN = "Maven"
    RUBYGEMS = "RubyGems"

    def __str__(self) -> str:  # avoid ``Ecosystem.NPM`` in user output
        return self.value


@dataclass(frozen=True)
class Package:
    """A single pinned (name, version) entry from a lockfile.

    ``parents`` is the dependency chain from a top-level requirement
    down to this package. Empty tuple means a direct/top-level
    dependency. Used in reports so users can see why a flagged
    transitive dep is on disk.

    ``version_unspecified`` is True for entries we found in a manifest
    but couldn't pin (e.g. ``requests>=2`` in a requirements.txt).
    These are excluded from advisory matching but reported with a note.
    """

    name: str
    version: str
    ecosystem: Ecosystem
    lockfile_path: str
    parents: tuple[str, ...] = field(default_factory=tuple)
    version_unspecified: bool = False


@dataclass(frozen=True)
class Lockfile:
    """The parsed contents of a single lockfile."""

    path: Path
    ecosystem: Ecosystem
    packages: tuple[Package, ...]


class ParseError(Exception):
    """Raised when a lockfile cannot be parsed.

    Message text is user-facing — keep it friendly and actionable
    ("did you mean `pip-compile` output?", not "JSONDecodeError at
    line 42").
    """
