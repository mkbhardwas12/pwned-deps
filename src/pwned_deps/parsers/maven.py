"""``pom.xml`` parser.

Maven coordinates take the form ``groupId:artifactId``. OSV expects
the same shape as the package name. We handle two top-level blocks:

* ``<dependencies>`` — the project's direct dependencies.
* ``<dependencyManagement><dependencies>`` — central version
  management, often where versions actually live.

Property variables (e.g. ``${spring.version}``) are surfaced as
``version_unspecified=True`` rather than resolved — full POM
inheritance + ``<properties>`` resolution is out of scope for V1
(``mvn dependency:tree`` is the right tool for that, and we only
parse text).

XML parsing uses stdlib :mod:`xml.etree.ElementTree`. We do **not**
turn on entity resolution; ``ElementTree`` defaults to a
non-resolving parser, which keeps the safety contract intact.
"""

from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree as ET

from pwned_deps.parsers.base import Ecosystem, Lockfile, Package, ParseError

# Maven POM elements live in this namespace.
_NS = {"m": "http://maven.apache.org/POM/4.0.0"}


def parse(path: str | Path) -> Lockfile:
    path = Path(path)
    try:
        tree = ET.parse(path)  # noqa: S314 — entity resolution off by default
    except FileNotFoundError as exc:
        raise ParseError(f"{path}: lockfile not found") from exc
    except OSError as exc:
        raise ParseError(f"{path}: could not read pom.xml ({exc})") from exc
    except ET.ParseError as exc:
        raise ParseError(f"{path}: not valid XML ({exc})") from exc

    root = tree.getroot()
    out: list[Package] = []
    seen: set[tuple[str, str]] = set()

    for dep in _iter_dependencies(root):
        record = _dep_to_package(dep, lockfile_path=str(path))
        if record is None:
            continue
        key = (record.name, record.version)
        if key in seen:
            continue
        seen.add(key)
        out.append(record)

    return Lockfile(path=path, ecosystem=Ecosystem.MAVEN, packages=tuple(out))


def _iter_dependencies(root: ET.Element):
    """Yield every <dependency> under <dependencies> AND
    <dependencyManagement><dependencies>."""

    # Find <dependencies> direct children of root.
    for deps in _find_all(root, "dependencies"):
        # Skip <dependencies> nested in <dependencyManagement> here —
        # we'll handle that block separately so we know which set
        # an entry came from. (Today the result is the same either
        # way.)
        for dep in _find_all(deps, "dependency"):
            yield dep
    for dm in _find_all(root, "dependencyManagement"):
        for deps in _find_all(dm, "dependencies"):
            for dep in _find_all(deps, "dependency"):
                yield dep


def _dep_to_package(dep: ET.Element, *, lockfile_path: str) -> Package | None:
    group = _text(dep, "groupId")
    artifact = _text(dep, "artifactId")
    version = _text(dep, "version") or ""
    if not group or not artifact:
        return None
    name = f"{group}:{artifact}"
    if not version or _is_property_ref(version):
        return Package(
            name=name,
            version="",
            ecosystem=Ecosystem.MAVEN,
            lockfile_path=lockfile_path,
            version_unspecified=True,
        )
    return Package(
        name=name,
        version=version,
        ecosystem=Ecosystem.MAVEN,
        lockfile_path=lockfile_path,
    )


def _is_property_ref(version: str) -> bool:
    return version.startswith("${") and version.endswith("}")


def _find_all(element: ET.Element, tag: str):
    """Match ``tag`` regardless of whether the document is namespaced."""

    yield from element.findall(f"m:{tag}", _NS)
    yield from element.findall(tag)


def _text(element: ET.Element, tag: str) -> str | None:
    candidate = element.find(f"m:{tag}", _NS)
    if candidate is None:
        candidate = element.find(tag)
    if candidate is None:
        return None
    text = (candidate.text or "").strip()
    return text or None
