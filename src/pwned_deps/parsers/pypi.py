"""Python (PyPI) lockfile parsers.

Handles four common formats, auto-dispatched by filename:

* ``requirements.txt`` (or any ``*.txt`` we're handed) — line-based
  pip-style requirements. Only fully-pinned ``==`` entries are
  reported with concrete versions; loose entries (``>=``, ``~=``,
  ``<``, etc.) are emitted with ``version_unspecified=True`` so they
  appear in the report but are skipped by the matcher.
* ``Pipfile.lock`` — JSON, with ``default`` and ``develop`` sections.
* ``poetry.lock`` — TOML, ``[[package]]`` array of tables.
* ``uv.lock`` — TOML, ``[[package]]`` array of tables.

Pure parsing; we never run ``pip install`` or any other process on
contents (BUILD_BRIEF §2 rule 1).
"""

from __future__ import annotations

import json
from pathlib import Path

try:  # py3.11+
    import tomllib as _toml
except ModuleNotFoundError:  # py3.10
    import tomli as _toml  # type: ignore[no-redef]

from pwned_deps.parsers.base import Ecosystem, Lockfile, Package, ParseError


def parse(path: str | Path) -> Lockfile:
    """Parse a Python lockfile/requirements file by filename.

    Dispatches based on the filename:

    * ``requirements*.txt`` → pip-style requirements
    * ``Pipfile.lock`` → JSON Pipfile lock
    * ``poetry.lock`` → poetry TOML lock
    * ``uv.lock`` → uv TOML lock

    Anything else with a matching content shape can be parsed via the
    underlying helpers directly (exposed for tests).
    """

    path = Path(path)
    name = path.name.lower()
    if name == "pipfile.lock":
        return _parse_pipfile_lock(path)
    if name == "poetry.lock":
        return _parse_poetry_lock(path)
    if name == "uv.lock":
        return _parse_uv_lock(path)
    if name.startswith("requirements") and (
        name.endswith(".txt") or name.endswith(".lock") or name.endswith(".in")
    ):
        return _parse_requirements_txt(path)
    if name.endswith(".txt"):
        return _parse_requirements_txt(path)
    raise ParseError(
        f"{path}: unrecognised Python lockfile name. Supported: "
        "requirements*.txt, Pipfile.lock, poetry.lock, uv.lock."
    )


# ---------------------------------------------------------------------------
# requirements.txt
# ---------------------------------------------------------------------------


def _parse_requirements_txt(path: Path) -> Lockfile:
    raw = _read_text(path)

    out: list[Package] = []
    for raw_line in raw.splitlines():
        line = _strip_inline_comment(raw_line).strip()
        if not line:
            continue
        # Skip option lines like "-r other.txt", "-e .", "--hash=sha...".
        # `--hash=` continuations on the previous line are also a no-op
        # for our purposes since we only care about the package pin.
        if line.startswith(("-", "--")):
            continue
        # Skip URL or local-path direct references.
        if "://" in line:
            continue
        if line.startswith(("./", "../", "/")):
            continue
        # Strip line continuation backslashes.
        if line.endswith("\\"):
            line = line[:-1].rstrip()
        # Strip extras: `pkg[extra1,extra2]==1.2.3` → `pkg==1.2.3`.
        line = _drop_extras(line)
        # Try to find an exact-pin operator.
        if "==" in line:
            name, _, rest = line.partition("==")
            name = name.strip()
            version = rest.strip()
            # Trim trailing markers / environment selectors like
            # `; python_version < "3.12"`.
            if ";" in version:
                version = version.split(";", 1)[0].strip()
            if not name or not version:
                continue
            out.append(
                Package(
                    name=_canonicalise(name),
                    version=version,
                    ecosystem=Ecosystem.PYPI,
                    lockfile_path=str(path),
                )
            )
            continue
        # Loose pin or no pin at all — emit unspecified.
        loose = _extract_name_loose(line)
        if loose:
            out.append(
                Package(
                    name=_canonicalise(loose),
                    version="",
                    ecosystem=Ecosystem.PYPI,
                    lockfile_path=str(path),
                    version_unspecified=True,
                )
            )

    return Lockfile(path=path, ecosystem=Ecosystem.PYPI, packages=tuple(out))


def _strip_inline_comment(line: str) -> str:
    """Strip ``#`` comments unless the ``#`` is inside a URL (handled
    separately) or part of a hash digest. We never preserve URL lines
    anyway so we can be conservative here."""

    if "#" in line:
        # Allow `# sha256:...` comment after a pinned package, but
        # `--hash=sha...` does not contain `#`, so simple split is fine.
        return line.split("#", 1)[0]
    return line


def _drop_extras(line: str) -> str:
    if "[" in line and "]" in line:
        before, _, rest = line.partition("[")
        _, _, after = rest.partition("]")
        return before + after
    return line


_NAME_BOUNDARY = "<>=!~ "


def _extract_name_loose(line: str) -> str | None:
    name_chars: list[str] = []
    for ch in line:
        if ch in _NAME_BOUNDARY:
            break
        name_chars.append(ch)
    name = "".join(name_chars).strip()
    return name or None


def _canonicalise(name: str) -> str:
    """Return PEP 503-canonical name (lowercase, runs of [-_.] → '-').

    OSV requires this normalisation for PyPI lookups.
    """

    out: list[str] = []
    last_was_sep = False
    for ch in name.lower():
        if ch in "-_.":
            if not last_was_sep:
                out.append("-")
            last_was_sep = True
        else:
            out.append(ch)
            last_was_sep = False
    return "".join(out).strip("-")


# ---------------------------------------------------------------------------
# Pipfile.lock
# ---------------------------------------------------------------------------


def _parse_pipfile_lock(path: Path) -> Lockfile:
    raw = _read_text(path)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ParseError(
            f"{path}: not valid JSON ({exc.msg} at line {exc.lineno}, col {exc.colno})"
        ) from exc
    if not isinstance(data, dict):
        raise ParseError(f"{path}: top-level value must be a JSON object")

    out: list[Package] = []
    for section in ("default", "develop"):
        block = data.get(section, {})
        if not isinstance(block, dict):
            continue
        for name, entry in block.items():
            if not isinstance(entry, dict):
                continue
            version_raw = entry.get("version")
            if not isinstance(version_raw, str) or not version_raw:
                continue
            # Pipfile.lock stores versions as "==1.2.3"; strip the prefix.
            version = version_raw[2:] if version_raw.startswith("==") else version_raw
            out.append(
                Package(
                    name=_canonicalise(name),
                    version=version,
                    ecosystem=Ecosystem.PYPI,
                    lockfile_path=str(path),
                )
            )
    return Lockfile(path=path, ecosystem=Ecosystem.PYPI, packages=tuple(out))


# ---------------------------------------------------------------------------
# poetry.lock
# ---------------------------------------------------------------------------


def _parse_poetry_lock(path: Path) -> Lockfile:
    data = _read_toml(path)
    packages_block = data.get("package", [])
    if not isinstance(packages_block, list):
        raise ParseError(f"{path}: 'package' must be an array of tables")

    out: list[Package] = []
    for entry in packages_block:
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
                name=_canonicalise(name),
                version=version,
                ecosystem=Ecosystem.PYPI,
                lockfile_path=str(path),
            )
        )
    return Lockfile(path=path, ecosystem=Ecosystem.PYPI, packages=tuple(out))


# ---------------------------------------------------------------------------
# uv.lock
# ---------------------------------------------------------------------------


def _parse_uv_lock(path: Path) -> Lockfile:
    data = _read_toml(path)
    packages_block = data.get("package", [])
    if not isinstance(packages_block, list):
        raise ParseError(f"{path}: 'package' must be an array of tables")

    out: list[Package] = []
    for entry in packages_block:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        version = entry.get("version")
        if not isinstance(name, str) or not name:
            continue
        # Workspace roots in uv.lock have no version — skip silently.
        if not isinstance(version, str) or not version:
            continue
        # Skip entries whose source is a local workspace member.
        source = entry.get("source")
        if isinstance(source, dict) and (
            source.get("virtual") or source.get("editable") or source.get("directory")
        ):
            continue
        out.append(
            Package(
                name=_canonicalise(name),
                version=version,
                ecosystem=Ecosystem.PYPI,
                lockfile_path=str(path),
            )
        )
    return Lockfile(path=path, ecosystem=Ecosystem.PYPI, packages=tuple(out))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ParseError(f"{path}: lockfile not found") from exc
    except OSError as exc:
        raise ParseError(f"{path}: could not read lockfile ({exc})") from exc


def _read_toml(path: Path) -> dict:
    try:
        with path.open("rb") as handle:
            return _toml.load(handle)
    except FileNotFoundError as exc:
        raise ParseError(f"{path}: lockfile not found") from exc
    except OSError as exc:
        raise ParseError(f"{path}: could not read lockfile ({exc})") from exc
    except _toml.TOMLDecodeError as exc:
        raise ParseError(f"{path}: not valid TOML ({exc})") from exc
