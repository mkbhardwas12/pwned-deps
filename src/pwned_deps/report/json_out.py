"""Machine-readable JSON output.

Minimal shape: ``--format json`` yields valid JSON parseable by
``json.loads`` with the keys consumers depend on. SARIF
(``report/sarif.py``) is the richer machine format for tools that
speak it.
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from pwned_deps.advisory.types import Severity
from pwned_deps.report.text import ScanReport, exit_code_for

_SCHEMA_VERSION = "1.1"


def render_json(reports: Sequence[ScanReport], *, version: str) -> tuple[str, int]:
    """Return ``(json_string, exit_code)``."""

    payload = {
        "schema_version": _SCHEMA_VERSION,
        "tool": {"name": "pwned-deps", "version": version},
        "lockfiles": [],
        "summary": {
            "total_packages": 0,
            "checked": 0,
            "unchecked": 0,
            "unpinned": 0,
            "compromised": 0,
            "high_critical": 0,
            "other": 0,
        },
    }

    for report in reports:
        lockfile_block = {
            "path": str(report.lockfile.path),
            "ecosystem": report.lockfile.ecosystem.value,
            "package_count": len(report.lockfile.packages),
            "parse_error": report.parse_error,
            "findings": [],
            "unchecked": [
                {
                    "package": u.package.name,
                    "version": u.package.version,
                    "ecosystem": u.package.ecosystem.value,
                    "reason": u.reason,
                }
                for u in report.unchecked
            ],
        }
        for finding in report.findings:
            adv_raw = finding.advisory.raw if isinstance(finding.advisory.raw, dict) else {}
            package_entry = adv_raw.get("package_entry") if isinstance(adv_raw, dict) else None
            campaign = adv_raw.get("campaign") if isinstance(adv_raw, dict) else None

            tarball_sha256: str | None = None
            if isinstance(package_entry, dict):
                value = package_entry.get("tarball_sha256")
                if isinstance(value, str) and value:
                    tarball_sha256 = value

            iocs: list[str] = []
            if isinstance(campaign, dict):
                raw_iocs = campaign.get("iocs")
                if isinstance(raw_iocs, list):
                    iocs = [s for s in raw_iocs if isinstance(s, str)]

            lockfile_block["findings"].append(
                {
                    "id": finding.advisory.id,
                    "package": finding.package.name,
                    "version": finding.package.version,
                    "ecosystem": finding.package.ecosystem.value,
                    "severity": finding.advisory.severity.value,
                    "summary": finding.advisory.summary,
                    "references": list(finding.advisory.references),
                    "is_malicious": finding.is_malicious,
                    "campaign_name": finding.campaign_name,
                    "tarball_sha256": tarball_sha256,
                    "iocs": iocs,
                }
            )
            if finding.is_malicious:
                payload["summary"]["compromised"] += 1
            elif finding.advisory.severity in (Severity.HIGH, Severity.CRITICAL):
                payload["summary"]["high_critical"] += 1
            else:
                payload["summary"]["other"] += 1
        payload["lockfiles"].append(lockfile_block)
        payload["summary"]["total_packages"] += len(report.lockfile.packages)
        if not report.parse_error:
            payload["summary"]["checked"] += report.checked_count
            payload["summary"]["unchecked"] += len(report.unchecked)
            payload["summary"]["unpinned"] += report.unpinned_count

    return json.dumps(payload, indent=2, sort_keys=True), exit_code_for(reports)
