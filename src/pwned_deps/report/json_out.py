"""Machine-readable JSON output.

Step 8 will firm this up with a documented schema; today's shape is the
minimum needed by the Step 6 CLI gate ("--format json yields valid
JSON parseable by json.loads with the expected keys").
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from pwned_deps.advisory.types import Severity
from pwned_deps.report.text import ScanReport

_SCHEMA_VERSION = "1.0"


def render_json(reports: Sequence[ScanReport], *, version: str) -> tuple[str, int]:
    """Return ``(json_string, exit_code)``."""

    payload = {
        "schema_version": _SCHEMA_VERSION,
        "tool": {"name": "pwned-deps", "version": version},
        "lockfiles": [],
        "summary": {
            "total_packages": 0,
            "compromised": 0,
            "high_critical": 0,
            "other": 0,
        },
    }
    exit_code = 0
    parse_failed = False
    high_or_critical_seen = False
    malicious_seen = False

    for report in reports:
        lockfile_block = {
            "path": str(report.lockfile.path),
            "ecosystem": report.lockfile.ecosystem.value,
            "package_count": len(report.lockfile.packages),
            "parse_error": report.parse_error,
            "findings": [],
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
                malicious_seen = True
                payload["summary"]["compromised"] += 1
            elif finding.advisory.severity in (Severity.HIGH, Severity.CRITICAL):
                high_or_critical_seen = True
                payload["summary"]["high_critical"] += 1
            else:
                payload["summary"]["other"] += 1
        payload["lockfiles"].append(lockfile_block)
        payload["summary"]["total_packages"] += len(report.lockfile.packages)
        if report.parse_error:
            parse_failed = True

    if parse_failed:
        exit_code = 3
    elif malicious_seen:
        exit_code = 1
    elif high_or_critical_seen:
        exit_code = 2

    return json.dumps(payload, indent=2, sort_keys=True), exit_code
