"""Minimal range matcher used by ``extras.json`` campaigns.

A *spec* is one of:

* An exact version string (no leading operator) — matches that
  version exactly.
* A comma-separated list of clauses, each of which is an operator
  (``=``, ``==``, ``!=``, ``<``, ``<=``, ``>``, ``>=``) followed by
  a version. All clauses must hold (AND-joined).

Examples:

* ``"1.2.3"`` matches only ``1.2.3``.
* ``">=4.17.0,<4.17.21"`` matches ``4.17.15`` but not ``4.17.22``.
* ``"<2.0,!=1.4.2"`` matches ``1.5.0`` and ``1.6.0``, not ``1.4.2``.

PyPI versions are compared via :class:`packaging.version.Version`
(PEP 440). npm/Maven/Cargo/Go/RubyGems use a SemVer-flavoured tuple
comparison that handles pre-release tags conservatively (a
pre-release sorts below the corresponding stable version).

A scope here is intentionally narrow: this is *not* a full SemVer
ranges implementation. It exists to evaluate authored campaign rules
that have already been triaged by a maintainer. Anything we cannot
parse returns ``False`` rather than crashing — campaigns can use
explicit version lists if they need to.
"""

from __future__ import annotations

from dataclasses import dataclass

from packaging.version import InvalidVersion
from packaging.version import Version as PypiVersion

# Operators we recognise, longest-first so multi-char ones win.
_OPERATORS = ("==", "!=", "<=", ">=", "<", ">", "=")


@dataclass(frozen=True)
class _Clause:
    op: str  # one of: ==, !=, <=, >=, <, >, =
    version: str


def matches(version: str, spec: str, *, ecosystem: str = "") -> bool:
    """Return True iff ``version`` satisfies ``spec``."""

    spec = spec.strip()
    version = version.strip()
    if not spec or not version:
        return False
    clauses = _parse_spec(spec)
    if clauses is None:
        return False
    for clause in clauses:
        if not _evaluate(clause, version, ecosystem=ecosystem):
            return False
    return True


def _parse_spec(spec: str) -> list[_Clause] | None:
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    if not parts:
        return None
    out: list[_Clause] = []
    for part in parts:
        clause = _parse_clause(part)
        if clause is None:
            return None
        out.append(clause)
    return out


def _parse_clause(part: str) -> _Clause | None:
    for op in _OPERATORS:
        if part.startswith(op):
            return _Clause(op=op, version=part[len(op) :].strip())
    # No operator → treat as exact-version shorthand.
    return _Clause(op="==", version=part.strip())


def _evaluate(clause: _Clause, version: str, *, ecosystem: str) -> bool:
    """Apply ``clause`` to ``version`` for the given ecosystem."""

    cmp = _compare(version, clause.version, ecosystem=ecosystem)
    if cmp is None:
        return False
    if clause.op in ("==", "="):
        return cmp == 0
    if clause.op == "!=":
        return cmp != 0
    if clause.op == "<":
        return cmp < 0
    if clause.op == "<=":
        return cmp <= 0
    if clause.op == ">":
        return cmp > 0
    if clause.op == ">=":
        return cmp >= 0
    return False


def _compare(left: str, right: str, *, ecosystem: str) -> int | None:
    """Return ``-1``/``0``/``1`` or ``None`` if either side is unparseable."""

    if ecosystem == "PyPI":
        try:
            a = PypiVersion(left)
            b = PypiVersion(right)
        except InvalidVersion:
            return None
        if a < b:
            return -1
        if a > b:
            return 1
        return 0
    return _semver_compare(left, right)


def _semver_compare(left: str, right: str) -> int | None:
    """Conservative SemVer-flavoured compare.

    The release component is split into integer parts; any
    pre-release suffix sorts *below* the same release without one.
    """

    a_release, a_prerelease = _split_semver(left)
    b_release, b_prerelease = _split_semver(right)
    if a_release is None or b_release is None:
        return None

    cmp = _compare_release_tuples(a_release, b_release)
    if cmp != 0:
        return cmp
    return _compare_prerelease(a_prerelease, b_prerelease)


def _split_semver(value: str) -> tuple[tuple[int, ...] | None, str]:
    """Split a SemVer-shaped string into release-tuple + prerelease tail."""

    # Pull off build metadata (`+...`) — irrelevant to ordering.
    if "+" in value:
        value = value.split("+", 1)[0]
    prerelease = ""
    if "-" in value:
        value, prerelease = value.split("-", 1)
    parts = value.split(".")
    try:
        release = tuple(int(p) for p in parts)
    except ValueError:
        return None, prerelease
    return release, prerelease


def _compare_release_tuples(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    if a == b:
        return 0
    return -1 if a < b else 1


def _compare_prerelease(a: str, b: str) -> int:
    if a == b:
        return 0
    # Empty (= no prerelease) sorts ABOVE any prerelease.
    if not a:
        return 1
    if not b:
        return -1
    return -1 if a < b else 1
