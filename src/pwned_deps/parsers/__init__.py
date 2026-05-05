"""Lockfile parsers — one module per ecosystem.

Public surface re-exports the shared dataclasses + the per-ecosystem
``parse`` callables. Lockfile parsing is text/JSON only — we never
execute, install, or fetch anything from a parsed lockfile.
"""

from pwned_deps.parsers import cargo, gem, go, maven, npm, pnpm, pypi, yarn
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
    "cargo",
    "gem",
    "go",
    "maven",
    "npm",
    "pnpm",
    "pypi",
    "yarn",
]
