"""Terminal-friendly renderer using ``rich``.

Prints a header per scanned lockfile, then groups findings into:

* 🚨 COMPROMISED  — any MAL-* / EXTRA-* finding (`is_malicious`).
* ⚠ HIGH/CRITICAL — non-malicious advisories with severity ≥ HIGH.
* OTHER          — MEDIUM / LOW / UNKNOWN (only shown with --verbose
  in a future build; for now collapsed into a one-line summary).

Output is deterministic when ``ci=True`` so CI logs diff cleanly.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from rich.console import Console
from rich.text import Text

from pwned_deps.advisory.matcher import Finding
from pwned_deps.advisory.osv_client import Unchecked
from pwned_deps.advisory.types import Severity
from pwned_deps.parsers.base import Lockfile

EXIT_CLEAN = 0
EXIT_MALICIOUS = 1
EXIT_ATTENTION = 2
EXIT_PARSE_ERROR = 3
EXIT_INCOMPLETE = 4


@dataclass
class ScanReport:
    """One element per lockfile scanned in this invocation."""

    lockfile: Lockfile
    findings: list[Finding]
    parse_error: str | None = None
    # Pinned packages whose advisory lookup did not complete. These
    # are never "clean" — see ``exit_code_for``.
    unchecked: list[Unchecked] = field(default_factory=list)

    @property
    def unpinned_count(self) -> int:
        return sum(1 for p in self.lockfile.packages if p.version_unspecified)

    @property
    def checked_count(self) -> int:
        return len(self.lockfile.packages) - self.unpinned_count - len(self.unchecked)


def exit_code_for(reports: Sequence[ScanReport]) -> int:
    """Single source of truth for the CLI exit code.

    Findings win over incompleteness: a confirmed compromise is exit 1
    even if other packages went unchecked. Only when nothing at all was
    found do we distinguish "all checked, clean" (0) from "some pinned
    packages were never looked up" (4).
    """

    if any(r.parse_error for r in reports):
        return EXIT_PARSE_ERROR
    findings = [f for r in reports for f in r.findings]
    if any(f.is_malicious for f in findings):
        return EXIT_MALICIOUS
    if any(
        not f.is_malicious and f.severity in (Severity.HIGH, Severity.CRITICAL)
        for f in findings
    ):
        return EXIT_ATTENTION
    if any(r.unchecked for r in reports):
        return EXIT_INCOMPLETE
    return EXIT_CLEAN


def render_text(
    reports: Sequence[ScanReport],
    *,
    version: str,
    ci: bool = False,
    no_color: bool = False,
    verbose: bool = False,
) -> int:
    """Render ``reports`` to stdout. Return the exit code (see ``cli`` module)."""

    console = Console(
        no_color=no_color or ci,
        force_terminal=False if ci else None,
        highlight=False,
        emoji=not ci,
        # Avoid arbitrary wrapping in non-TTY contexts (CI logs, tests).
        # 200 columns fits any modern path without truncating identifiers.
        width=200,
    )

    if any(r.parse_error for r in reports):
        for report in reports:
            if report.parse_error:
                console.print(f"[red]parse error:[/] {report.parse_error}")
        return EXIT_PARSE_ERROR

    total_packages = sum(len(r.lockfile.packages) for r in reports)
    unpinned = sum(r.unpinned_count for r in reports)
    unchecked = [u for r in reports for u in r.unchecked]
    checked = total_packages - unpinned - len(unchecked)
    all_findings = [f for r in reports for f in r.findings]
    malicious = [f for f in all_findings if f.is_malicious]
    policy = [f for f in all_findings if not f.is_malicious and f.is_policy]
    high_critical = [
        f
        for f in all_findings
        if not f.is_malicious
        and not f.is_policy
        and f.severity in (Severity.HIGH, Severity.CRITICAL)
    ]
    other = [
        f
        for f in all_findings
        if not f.is_malicious
        and not f.is_policy
        and f.severity in (Severity.MEDIUM, Severity.LOW, Severity.UNKNOWN)
    ]

    for report in reports:
        console.print(
            f"pwned-deps {version} — checking {report.lockfile.path} "
            f"({report.lockfile.ecosystem})"
        )

    if malicious:
        console.print()
        marker = "[bold red]COMPROMISED[/]" if not ci else "COMPROMISED"
        console.print(f"{marker} — {len(malicious)} package(s)")
        for finding in malicious:
            _print_finding(console, finding, malicious=True, ci=ci)

    if high_critical:
        console.print()
        marker = "[bold yellow]HIGH/CRITICAL[/]" if not ci else "HIGH/CRITICAL"
        console.print(f"{marker} — {len(high_critical)} package(s)")
        for finding in high_critical:
            _print_finding(console, finding, malicious=False, ci=ci)

    if policy:
        console.print()
        marker = "[bold yellow]TOO NEW[/]" if not ci else "TOO NEW"
        console.print(f"{marker} — {len(policy)} package(s) violate the --min-age policy")
        for finding in policy:
            _print_finding(console, finding, malicious=False, ci=ci)

    if other and verbose:
        console.print()
        console.print(f"OTHER — {len(other)} finding(s)")
        for finding in other:
            _print_finding(console, finding, malicious=False, ci=ci)

    if unchecked:
        console.print()
        marker = "[bold yellow]UNCHECKED[/]" if not ci else "UNCHECKED"
        console.print(
            f"{marker} — {len(unchecked)} pinned package(s) could not be looked up"
        )
        by_reason: dict[str, list[str]] = {}
        for u in unchecked:
            by_reason.setdefault(u.reason, []).append(f"{u.package.name}@{u.package.version}")
        for reason, names in by_reason.items():
            preview = ", ".join(names[:5])
            more = "" if len(names) <= 5 else f" (+{len(names) - 5} more)"
            console.print(f"  {reason}: {preview}{more}")

    console.print()
    if not all_findings and not unchecked:
        line = Text(f"All {checked} pinned packages clean.", style="green" if not ci else "")
        if not ci:
            console.print(":white_check_mark:", line)
        else:
            console.print(line)
    elif not all_findings:
        line = Text(
            f"INCOMPLETE — {checked} of {checked + len(unchecked)} pinned packages "
            f"checked, no findings among them; {len(unchecked)} unchecked.",
            style="yellow" if not ci else "",
        )
        console.print(line)
    else:
        summary = (
            f"{total_packages} packages scanned · "
            f"{len(malicious)} compromised · "
            f"{len(high_critical)} high/critical · "
            f"{len(other)} low/medium"
        )
        if policy:
            summary += f" · {len(policy)} too new"
        if unchecked:
            summary += f" · {len(unchecked)} unchecked"
        console.print(summary)
    if unpinned:
        console.print(
            f"note: {unpinned} unpinned entr{'y' if unpinned == 1 else 'ies'} "
            f"(no exact version) not checked — pin them to get coverage."
        )

    return exit_code_for(reports)


def _print_finding(
    console: Console,
    finding: Finding,
    *,
    malicious: bool,
    ci: bool,
) -> None:
    pkg = finding.package
    adv = finding.advisory
    header = f"  {pkg.name}@{pkg.version}"
    if not ci:
        console.print(header)
    else:
        console.print(header)

    badge = adv.id
    if finding.campaign_name:
        badge = f"{adv.id}  {finding.campaign_name}"
    elif malicious:
        badge = f"{adv.id}  (malicious)"

    console.print(f"    {badge}")
    if adv.summary:
        console.print(f"    {adv.summary}")

    # For EXTRA-* campaign hits, surface forensic data the user can
    # act on right now: the tarball SHA-256 (so they can grep their
    # artifact stores / container images) and the campaign-level IoCs
    # (rogue repo descriptions, IDE-persistence files, C2 domains).
    raw = adv.raw if isinstance(adv.raw, dict) else {}
    package_entry = raw.get("package_entry") if isinstance(raw, dict) else None
    if isinstance(package_entry, dict):
        tarball_sha256 = package_entry.get("tarball_sha256")
        if isinstance(tarball_sha256, str) and tarball_sha256:
            console.print(f"    tarball sha256: {tarball_sha256}")

    campaign = raw.get("campaign") if isinstance(raw, dict) else None
    if isinstance(campaign, dict):
        iocs = campaign.get("iocs")
        if isinstance(iocs, list) and iocs:
            console.print("    additional indicators to hunt for:")
            for ioc in iocs:
                if isinstance(ioc, str):
                    console.print(f"      • {ioc}")

    if adv.references:
        ref_preview = ", ".join(adv.references[:3])
        more = "" if len(adv.references) <= 3 else f" (+{len(adv.references) - 3} more)"
        console.print(f"    refs: {ref_preview}{more}")
