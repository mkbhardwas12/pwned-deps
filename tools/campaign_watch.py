"""Daily campaign watch: turn the GHSA malware firehose into a short list.

Reads the JSON produced by ``gh api graphql`` (see
``.github/workflows/campaign-watch.yml``), then asks the registry how
old each affected package is. A package that existed for weeks before
its malware advisory is almost always an *account hijack* of a real
project — exactly the events that belong in ``extras.json`` as a
``compromised_maintainers`` window and that users need to hear about
in the first hour. Brand-new packages are typosquats: OSV/GHSA already
cover them and they are rarely worth a feed entry.

Output: Markdown on stdout (for the sticky issue + step summary).
Exit 0 always; the workflow decides what to do with the text.

Stdlib only so the workflow needs nothing but ``gh`` and Python.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

USER_AGENT = "pwned-deps-campaign-watch (+https://github.com/mkbhardwas12/pwned-deps)"
HIJACK_MIN_AGE = timedelta(days=30)
TIMEOUT = 15


@dataclass
class Advisory:
    ghsa_id: str
    summary: str
    published_at: datetime
    ecosystem: str  # GHSA vocabulary: NPM / PIP / ...
    package: str
    version_range: str
    created_at: datetime | None = None
    versions: int | None = None

    @property
    def age_at_advisory(self) -> timedelta | None:
        if self.created_at is None:
            return None
        return self.published_at - self.created_at

    @property
    def likely_hijack(self) -> bool:
        age = self.age_at_advisory
        return age is not None and age >= HIJACK_MIN_AGE


def _parse_ts(value: str) -> datetime | None:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).astimezone(timezone.utc)
    except ValueError:
        return None


def _get_json(url: str) -> dict | None:
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https URL: {url}")
    req = urllib.request.Request(  # noqa: S310 - scheme checked above, fixed hosts
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310
            data = json.load(resp)
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
        return None
    return data if isinstance(data, dict) else None


def enrich(adv: Advisory) -> None:
    """Fill ``created_at`` / ``versions`` from the registry, if reachable."""

    if adv.ecosystem == "NPM":
        doc = _get_json(f"https://registry.npmjs.org/{urllib.parse.quote(adv.package, safe='@')}")
        if not doc:
            return
        times = doc.get("time") if isinstance(doc.get("time"), dict) else {}
        created = times.get("created")
        adv.created_at = _parse_ts(created) if isinstance(created, str) else None
        adv.versions = len(doc.get("versions") or {})
    elif adv.ecosystem == "PIP":
        doc = _get_json(f"https://pypi.org/pypi/{urllib.parse.quote(adv.package)}/json")
        if not doc:
            return
        releases = doc.get("releases") if isinstance(doc.get("releases"), dict) else {}
        stamps = [
            _parse_ts(f.get("upload_time_iso_8601", ""))
            for files in releases.values()
            if isinstance(files, list)
            for f in files
            if isinstance(f, dict)
        ]
        stamps = [s for s in stamps if s is not None]
        adv.created_at = min(stamps) if stamps else None
        adv.versions = len(releases)


def load(payload: dict, since: datetime) -> list[Advisory]:
    nodes = payload.get("data", {}).get("securityAdvisories", {}).get("nodes", [])
    out: list[Advisory] = []
    seen: set[tuple[str, str, str]] = set()
    for node in nodes:
        published = _parse_ts(node.get("publishedAt", ""))
        if published is None or published < since:
            continue
        vulns = node.get("vulnerabilities", {}).get("nodes", [])
        for v in vulns:
            pkg = v.get("package") or {}
            key = (node.get("ghsaId", "?"), str(pkg.get("ecosystem")), str(pkg.get("name")))
            if key in seen:
                continue
            seen.add(key)
            out.append(
                Advisory(
                    ghsa_id=node.get("ghsaId", "?"),
                    summary=node.get("summary", ""),
                    published_at=published,
                    ecosystem=str(pkg.get("ecosystem", "?")),
                    package=str(pkg.get("name", "?")),
                    version_range=str(v.get("vulnerableVersionRange", "")),
                )
            )
    return out


def render(advs: list[Advisory], since: datetime, now: datetime) -> str:
    hijacks = sorted(
        (a for a in advs if a.likely_hijack),
        key=lambda a: (a.age_at_advisory or timedelta()),
        reverse=True,
    )
    fresh = [a for a in advs if not a.likely_hijack]
    lines = [
        f"## Campaign watch — {now:%Y-%m-%d}",
        "",
        f"GHSA malware advisories published since {since:%Y-%m-%d %H:%M} UTC: "
        f"**{len(advs)}** ({len(hijacks)} likely hijacks of existing packages, "
        f"{len(fresh)} new/typosquat).",
        "",
    ]
    if hijacks:
        lines += [
            "### Likely account hijacks — candidates for `extras.json`",
            "",
            "Package existed ≥30 days before the advisory. Check the maintainer, "
            "find the compromise window, and add a `compromised_maintainers` entry "
            "(see CONTRIBUTING.md). These are the ones to release + post about.",
            "",
            "| Package | Age at advisory | Versions | Range | Advisory |",
            "|---|---:|---:|---|---|",
        ]
        for a in hijacks:
            age = a.age_at_advisory or timedelta()
            lines.append(
                f"| `{a.ecosystem.lower()}:{a.package}` | {age.days} d | {a.versions or '?'} "
                f"| `{a.version_range}` | [{a.ghsa_id}](https://github.com/advisories/{a.ghsa_id}) |"
            )
        lines.append("")
    if fresh:
        lines += [
            "<details><summary>New / typosquat packages (OSV already covers these)</summary>",
            "",
        ]
        for a in fresh[:60]:
            lines.append(
                f"- `{a.ecosystem.lower()}:{a.package}` — "
                f"[{a.ghsa_id}](https://github.com/advisories/{a.ghsa_id})"
            )
        if len(fresh) > 60:
            lines.append(f"- …and {len(fresh) - 60} more")
        lines += ["", "</details>", ""]
    lines += [
        "_Generated by `.github/workflows/campaign-watch.yml`. Hijack heuristic: "
        "registry first-publish date ≥30 days before the GHSA publish date._",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        sys.stderr.write("usage: campaign_watch.py <advisories.json> <hours>\n")
        return 64
    payload = json.loads(open(argv[1], encoding="utf-8").read())
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=int(argv[2]))
    advs = load(payload, since)
    for adv in advs:
        enrich(adv)
    sys.stdout.write(render(advs, since, now))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv))
