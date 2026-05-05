"""Render a sticky PR comment from `pwned-deps check --format json` output.

Usage:

    pwned-deps check . --format json > scan.json
    python tools/pr_comment.py scan.json > comment.md
    gh pr comment "$PR" --body-file comment.md --edit-last \
        || gh pr comment "$PR" --body-file comment.md

The comment body always starts with a magic marker line so a follow-up
run can find and edit (rather than spam) the existing comment with
`gh pr comment --edit-last` or the GitHub REST API.

Exit codes:
    0 — comment written, no compromised packages
    1 — comment written, at least one MAL-* / EXTRA-* finding
    2 — comment written, only HIGH/CRITICAL CVE findings
    3 — input JSON could not be parsed

The script is dependency-free (stdlib only) so consumers can curl it
into a workflow without provisioning a Python environment beyond the
one already running pwned-deps.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable
from pathlib import Path

MARKER = "<!-- pwned-deps:pr-comment:v1 -->"


def render(payload: dict) -> tuple[str, int]:
    """Return ``(markdown_body, exit_code)``.

    ``payload`` is the parsed object produced by ``pwned-deps check
    --format json``. Output starts with ``MARKER`` so subsequent runs
    can locate and edit the existing comment.
    """

    summary = payload.get("summary", {}) or {}
    lockfiles = payload.get("lockfiles", []) or []
    tool = payload.get("tool", {}) or {}
    tool_version = tool.get("version", "?")

    compromised = int(summary.get("compromised", 0) or 0)
    high_critical = int(summary.get("high_critical", 0) or 0)
    total_packages = int(summary.get("total_packages", 0) or 0)

    if compromised:
        exit_code = 1
        headline = f"🚨 **{compromised} compromised package(s)** detected"
    elif high_critical:
        exit_code = 2
        headline = f"⚠️ **{high_critical} HIGH/CRITICAL CVE(s)** detected"
    else:
        exit_code = 0
        headline = f"✅ Clean — no compromised packages in {total_packages} pinned dependencies."

    lines: list[str] = [
        MARKER,
        "## pwned-deps scan",
        "",
        headline,
        "",
        f"_Scanned {total_packages} pinned packages across "
        f"{len(lockfiles)} lockfile(s) with pwned-deps `{tool_version}`._",
        "",
    ]

    if compromised or high_critical:
        lines.extend(_render_findings_table(lockfiles))

    return "\n".join(lines).rstrip() + "\n", exit_code


def _render_findings_table(lockfiles: Iterable[dict]) -> list[str]:
    rows: list[str] = []
    for lf in lockfiles:
        for finding in lf.get("findings", []) or []:
            tag = "MALICIOUS" if finding.get("is_malicious") else finding.get(
                "severity", "?"
            )
            campaign = finding.get("campaign_name") or ""
            adv_id = finding.get("id", "?")
            refs = finding.get("references") or []
            ref_link = f" [↗]({refs[0]})" if refs else ""
            rows.append(
                f"| `{tag}` | `{finding.get('ecosystem', '?')}:"
                f"{finding.get('package', '?')}@{finding.get('version', '?')}` "
                f"| `{adv_id}`{ref_link} | {campaign} |"
            )
    if not rows:
        return []
    return [
        "| Severity | Package | Advisory | Campaign |",
        "|---|---|---|---|",
        *rows,
        "",
        "_Re-run `pwned-deps check` locally to reproduce. "
        "See [pwned-deps](https://github.com/mkbhardwas12/pwned-deps) for triage guidance._",
    ]


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write("usage: pr_comment.py <scan.json>\n")
        return 64
    src = Path(argv[1])
    try:
        payload = json.loads(src.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"could not read JSON from {src}: {exc}\n")
        return 3
    body, exit_code = render(payload)
    sys.stdout.write(body)
    return exit_code


if __name__ == "__main__":  # pragma: no cover - thin CLI wrapper
    raise SystemExit(main(sys.argv))
