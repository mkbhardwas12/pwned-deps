"""Walk a directory tree and match files against the campaign feed's
``file_iocs`` blocks. See ``pwned_deps.audit`` package docstring for
the rationale.

Matching levels (most-confident first):

* ``sha256+path`` — the file's SHA-256 is in the feed AND its relative
  path ends in the IoC's ``path_hint``. Highest confidence, exit 1.
* ``sha256`` — SHA-256 only. Highest confidence, exit 1.
* ``path`` — only the path hint matched (file content has been
  modified or it's a fresh variant). Suggestive, exit 2.

Symlinks are never followed (loop + escape risk). Files larger than
``max_file_bytes`` are skipped \u2014 the bundled IoCs are all under
12 MB, but users can raise the cap with ``--max-bytes`` for
deeper sweeps.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from pwned_deps.advisory.extras import ExtrasFeed

# Names of directories we never descend into. These are noise / vendored
# code / build outputs; if a malicious file landed in node_modules, the
# lockfile scan caught it via the package version. The audit command is
# specifically for IDE-persistence drops *outside* the package tree.
DEFAULT_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "bower_components",
        ".venv",
        "venv",
        "env",
        ".env",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "dist",
        "build",
        "target",
        "out",
        ".tox",
        ".nox",
        ".idea",
    }
)

DEFAULT_MAX_FILE_BYTES: int = 50 * 1024 * 1024  # 50 MiB


@dataclass(frozen=True)
class FileIoc:
    """A single ``file_iocs`` entry, normalised across the feed."""

    path_hint: str | None
    sha256: str | None
    size_bytes: int | None
    description: str
    campaign_id: str
    campaign_name: str
    source: str | None


@dataclass(frozen=True)
class FileHit:
    """An on-disk file matched against the feed."""

    path: Path
    sha256: str
    matched_by: str  # "sha256", "path", or "sha256+path"
    ioc: FileIoc

    @property
    def is_confirmed(self) -> bool:
        """SHA-256 matched \u2014 not just a suspicious path."""

        return "sha256" in self.matched_by


def collect_file_iocs(extras: ExtrasFeed) -> list[FileIoc]:
    """Flatten the bundled + user-supplied feed into ``FileIoc`` records."""

    out: list[FileIoc] = []
    for campaign in extras.campaigns:
        cid = str(campaign.get("id", ""))
        cname = str(campaign.get("name", cid))
        block = campaign.get("file_iocs", [])
        if not isinstance(block, list):
            continue
        for entry in block:
            if not isinstance(entry, dict):
                continue
            sha256 = entry.get("sha256")
            path_hint = entry.get("path_hint")
            if not isinstance(sha256, str) and not isinstance(path_hint, str):
                continue
            size_bytes = entry.get("size_bytes")
            out.append(
                FileIoc(
                    path_hint=path_hint if isinstance(path_hint, str) else None,
                    sha256=sha256.lower() if isinstance(sha256, str) else None,
                    size_bytes=size_bytes if isinstance(size_bytes, int) else None,
                    description=str(entry.get("description", "")),
                    campaign_id=cid,
                    campaign_name=cname,
                    source=entry.get("source") if isinstance(entry.get("source"), str) else None,
                )
            )
    return out


def _walk_files(
    root: Path,
    skip_dirs: set[str],
    max_bytes: int,
) -> Iterator[Path]:
    """Yield candidate files. Skips noise dirs, symlinks, oversized files."""

    if root.is_file():
        try:
            if root.stat().st_size <= max_bytes:
                yield root
        except OSError:
            return
        return
    if not root.is_dir():
        return

    stack: list[Path] = [root]
    while stack:
        current = stack.pop()
        try:
            children = list(current.iterdir())
        except (OSError, PermissionError):
            continue
        for child in children:
            try:
                if child.is_symlink():
                    # Never follow symlinks. A symlinked malicious file
                    # outside the audit root would mislead the report.
                    continue
                if child.is_dir():
                    if child.name in skip_dirs:
                        continue
                    stack.append(child)
                    continue
                if not child.is_file():
                    continue
                if child.stat().st_size > max_bytes:
                    continue
                yield child
            except (OSError, PermissionError):
                continue


def _sha256_file(path: Path) -> str | None:
    """Stream-hash a file. Returns ``None`` on read error."""

    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def audit_repo(
    root: Path,
    extras: ExtrasFeed,
    *,
    skip_dirs: Iterable[str] = DEFAULT_SKIP_DIRS,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> list[FileHit]:
    """Walk ``root`` and return a list of file hits against the feed.

    The function is read-only. It never modifies, deletes, or executes
    any file it discovers.
    """

    iocs = collect_file_iocs(extras)
    if not iocs:
        return []

    by_sha: dict[str, FileIoc] = {i.sha256: i for i in iocs if i.sha256}
    path_iocs: list[FileIoc] = [i for i in iocs if i.path_hint]
    skip = set(skip_dirs)

    hits: list[FileHit] = []
    for f in _walk_files(root, skip, max_file_bytes):
        rel_path: str
        try:
            rel_path = str(f.relative_to(root)).replace("\\", "/")
        except ValueError:
            rel_path = str(f).replace("\\", "/")

        # Cheap path-hint check first \u2014 skip files with no chance of
        # matching anything.
        path_match: FileIoc | None = None
        for ioc in path_iocs:
            hint = ioc.path_hint or ""
            if rel_path.endswith(hint) or rel_path.endswith("/" + hint.lstrip("/")):
                path_match = ioc
                break

        # Hash only if at least one matcher might fire. ``by_sha`` is
        # usually small (a dozen entries), so we do hash every walked
        # file when it's non-empty; that's the desired behavior for a
        # forensic sweep.
        if not by_sha and path_match is None:
            continue

        digest = _sha256_file(f)
        if digest is None:
            continue

        sha_match = by_sha.get(digest)
        if sha_match is not None and path_match is not None and sha_match is path_match:
            hits.append(
                FileHit(path=f, sha256=digest, matched_by="sha256+path", ioc=sha_match)
            )
        elif sha_match is not None:
            hits.append(FileHit(path=f, sha256=digest, matched_by="sha256", ioc=sha_match))
        elif path_match is not None:
            hits.append(FileHit(path=f, sha256=digest, matched_by="path", ioc=path_match))

    # Stable order: confirmed first, then by path string.
    hits.sort(key=lambda h: (0 if h.is_confirmed else 1, str(h.path)))
    return hits
