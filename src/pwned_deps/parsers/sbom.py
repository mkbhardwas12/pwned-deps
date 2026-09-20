"""CycloneDX / SPDX SBOM parser.

Pipelines already emit an SBOM per build (syft, cdxgen, Trivy), so accepting
one lets ``pwned-deps check bom.json`` scan what actually shipped without
needing the source tree. Plain JSON, same safety contract as every other
parser. Package identity comes from the **purl** (``pkg:npm/chalk@5.6.1``),
the only field in either format naming an ecosystem; an SBOM can mix them,
so each ``Package`` carries its own and the header reports the commonest."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import unquote

from pwned_deps.parsers.base import Ecosystem, Lockfile, Package, ParseError

# Shared so an SBOM and a requirements.txt yield identical PyPI names.
from pwned_deps.parsers.pypi import canonicalise

# purl type -> OSV ecosystem string.
_PURL_ECOSYSTEMS: dict[str, Ecosystem] = {
    "npm": Ecosystem.NPM,
    "pypi": Ecosystem.PYPI,
    "cargo": Ecosystem.CRATES,
    "golang": Ecosystem.GO,
    "maven": Ecosystem.MAVEN,
    "gem": Ecosystem.RUBYGEMS,
}


def looks_like_sbom(path: str | Path) -> bool:
    """True when ``path`` is a CycloneDX or SPDX document (a read or decode problem answers False)."""

    try:
        with Path(path).open(encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return False
    return _flavour(data) is not None


def parse(path: str | Path) -> Lockfile:
    path = Path(path)
    try:
        with path.open(encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError as exc:
        raise ParseError(f"{path}: SBOM not found") from exc
    except OSError as exc:
        raise ParseError(f"{path}: could not read SBOM ({exc})") from exc
    except ValueError as exc:
        raise ParseError(f"{path}: not valid JSON ({exc})") from exc

    flavour = _flavour(data)
    if flavour is None:
        raise ParseError(
            f'{path}: not an SBOM. Expected a top-level "bomFormat" or "spdxVersion" key.'
        )
    cyclonedx = flavour == "cyclonedx"
    declared = _as_list(data.get("components" if cyclonedx else "packages"))
    purls = _cyclonedx_purls(data) if cyclonedx else _spdx_purls(data)

    seen: set[tuple[str, str, Ecosystem]] = set()
    out: list[Package] = []
    for purl in purls:
        entry = _from_purl(purl)
        if entry is None or entry in seen:
            continue
        seen.add(entry)
        name, version, ecosystem = entry
        out.append(
            Package(
                name=name,
                version=version,
                ecosystem=ecosystem,
                lockfile_path=str(path),
                version_unspecified=not version,
            )
        )
    if not out and declared:
        # Components exist but none is checkable; silence would read as clean.
        raise ParseError(
            f"{path}: no component in this SBOM carries a purl in an ecosystem "
            "we check (npm, PyPI, crates.io, Go, Maven, RubyGems)."
        )
    ecosystem = Counter(p.ecosystem for p in out).most_common(1)[0][0] if out else Ecosystem.NPM
    return Lockfile(path=path, ecosystem=ecosystem, packages=tuple(out))


def _flavour(data: object) -> str | None:
    if not isinstance(data, dict):
        return None
    cyclonedx = str(data.get("bomFormat", "")).lower() == "cyclonedx"
    return "cyclonedx" if cyclonedx else "spdx" if "spdxVersion" in data else None


def _cyclonedx_purls(data: dict) -> Iterator[str]:
    # Every `components[].purl`, nested sub-components included.
    # `metadata.component` is the artifact itself, not a dependency of it.
    stack = [c for c in _as_list(data.get("components")) if isinstance(c, dict)]
    while stack:
        component = stack.pop()
        stack.extend(c for c in _as_list(component.get("components")) if isinstance(c, dict))
        purl = component.get("purl")
        if isinstance(purl, str):
            yield purl


def _spdx_purls(data: dict) -> Iterator[str]:
    # The purl `externalRefs` of every `packages[]` entry.
    for package in _as_list(data.get("packages")):
        if not isinstance(package, dict):
            continue
        for ref in _as_list(package.get("externalRefs")):
            if not isinstance(ref, dict):
                continue
            if str(ref.get("referenceType", "")).lower() != "purl":
                continue
            locator = ref.get("referenceLocator")
            if isinstance(locator, str):
                yield locator


def _as_list(value: object) -> list:
    return value if isinstance(value, list) else []


def _from_purl(purl: str) -> tuple[str, str, Ecosystem] | None:
    """``pkg:npm/%40scope/foo@1.2.3?arch=x64#sub`` -> ``("@scope/foo", "1.2.3", NPM)``."""

    if not purl.startswith("pkg:"):
        return None
    body = purl[len("pkg:") :].split("#", 1)[0].split("?", 1)[0]
    purl_type, _, rest = body.partition("/")
    ecosystem = _PURL_ECOSYSTEMS.get(purl_type.strip().lower())
    if ecosystem is None or not rest:
        return None
    head, sep, version = rest.rpartition("@")
    if not sep:
        head, version = rest, ""
    name = "/".join(unquote(segment) for segment in head.split("/") if segment)
    if not name:
        return None
    if ecosystem is Ecosystem.MAVEN:
        # purl carries the groupId as a namespace; OSV wants "group:artifact".
        group, _, artifact = name.rpartition("/")
        if not group:
            return None
        name = f"{group}:{artifact}"
    elif ecosystem is Ecosystem.PYPI:
        name = canonicalise(name)
        if not name:
            return None
    return name, unquote(version).strip(), ecosystem
