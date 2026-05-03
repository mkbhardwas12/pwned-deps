"""Lockfile parsers — one module per ecosystem.

Public surface re-exports the shared dataclasses + the per-ecosystem
``parse`` callables. Lockfile parsing is text/JSON only — we never
execute, install, or fetch anything from a parsed lockfile (BUILD_BRIEF
§2 rule 1).
"""

from pwned_deps.parsers import npm, pypi
from pwned_deps.parsers.base import (
    Ecosystem,
    Lockfile,
    Package,
    ParseError,
)

__all__ = [
    "Ecosystem",
    "Lockfile",
    "Package",
    "ParseError",
    "npm",
    "pypi",
]
