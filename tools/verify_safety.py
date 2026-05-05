#!/usr/bin/env python3
"""Verify that no source file under the given roots contains a forbidden
symbol that could turn a parsed lockfile into executed code.

Why a Python script and not plain grep? The forbidden-symbol regex
includes a negative lookbehind (`(?<!re\\.)\\bcompile\\(`) so that
bare `compile(` calls trip the safety net while `re.compile(...)`
does not. POSIX BRE/ERE does not support lookbehinds, and BSD grep on
macOS errors out and exits 2 — which a Makefile `if` treats as
"no matches found" and silently returns success. Python's `re` module
honors the regex literally on every platform, so we use it.

This script lives outside src/ and tests/ so it is not itself scanned.

Usage:

    python3 tools/verify_safety.py src tests

Exit codes:
  0 — no forbidden symbols found
  1 — at least one forbidden symbol found (lines printed)
  2 — usage / IO error
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# (?<!re\.) mitigation so re.compile(...) is allowed without per-line
# noqa comments.
FORBIDDEN_PATTERN = (
    r"\.render\(|"
    r"\beval\(|"
    r"\bexec\(|"
    r"(?<!re\.)\bcompile\(|"
    r"\bos\.system\(|"
    r"\bos\.popen\(|"
    r"\bsubprocess\.|"
    r"pickle\.load|"
    r"pickle\.loads|"
    r"__import__\(|"
    r"getattr\(__builtins__|"
    r"importlib\.import_module"
)

FORBIDDEN_RE = re.compile(FORBIDDEN_PATTERN)


def scan(root: Path) -> list[tuple[Path, int, str, str]]:
    """Return list of (file, line_number, matched_token, full_line)."""
    hits: list[tuple[Path, int, str, str]] = []
    if not root.exists():
        return hits
    for py in sorted(root.rglob("*.py")):
        try:
            text = py.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            print(f"verify_safety: cannot read {py}: {exc}", file=sys.stderr)
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            m = FORBIDDEN_RE.search(line)
            if m is not None:
                hits.append((py, lineno, m.group(0), line.rstrip()))
    return hits


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: verify_safety.py <root> [<root>...]", file=sys.stderr)
        return 2
    roots = [Path(p) for p in argv[1:]]
    print(
        "[verify-safety] scanning "
        + ", ".join(str(p) for p in roots)
        + " for forbidden symbols..."
    )
    all_hits: list[tuple[Path, int, str, str]] = []
    for r in roots:
        all_hits.extend(scan(r))
    if all_hits:
        for path, lineno, token, line in all_hits:
            print(f"{path}:{lineno}: {token!r} in {line!r}")
        print()
        print(
            "FAIL: forbidden symbol(s) found above. The safety contract\n"
            "      forbids any code path that could turn parsed input\n"
            "      into execution. Refactor or, for the rare false\n"
            "      positive, add a per-line '# noqa: S' with rationale."
        )
        return 1
    print(
        "[verify-safety] OK — no forbidden symbols in "
        + ", ".join(str(p) for p in roots)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
