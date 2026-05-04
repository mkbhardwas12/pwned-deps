"""SARIF v2.1.0 output for GitHub Code Scanning ingestion.

Schema mapping (BUILD_BRIEF §7 Step 8):

* ``runs[0].tool.driver.name`` = ``"pwned-deps"``
* ``runs[0].tool.driver.version`` = ``pwned_deps.__version__``
* ``runs[0].tool.driver.informationUri`` =
  ``"https://github.com/mkbhardwas12/pwned-deps"``
* ``runs[0].tool.driver.rules[]`` — one entry per unique advisory
  ID seen in this run.
* ``runs[0].results[].level`` —
  - MAL-* / EXTRA-* (malicious) → ``"error"``
  - severity CRITICAL / HIGH    → ``"error"``
  - severity MEDIUM             → ``"warning"``
  - severity LOW / UNKNOWN      → ``"note"``
* ``runs[0].results[].locations[].physicalLocation.artifactLocation.uri``
  is the lockfile path.
* ``runs[0].results[].partialFingerprints.primaryLocationLineHash``
  is a stable SHA-256 of ``rule_id|package|version|lockfile``,
  letting GitHub Code Scanning dedup the same finding across runs.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import Any

from pwned_deps.advisory.types import Severity
from pwned_deps.report.text import ScanReport

INFORMATION_URI = "https://github.com/mkbhardwas12/pwned-deps"
SARIF_SCHEMA_URI = (
    "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"
)


def render_sarif(reports: Sequence[ScanReport], *, version: str) -> tuple[str, int]:
    """Return ``(sarif_json_text, exit_code)``."""

    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    parse_failed = False
    high_or_critical_seen = False
    malicious_seen = False

    for report in reports:
        if report.parse_error:
            parse_failed = True
            continue
        for finding in report.findings:
            advisory = finding.advisory
            rule_id = advisory.id
            rules.setdefault(rule_id, _rule_for(advisory, finding.is_malicious))
            results.append(_result_for(report, finding))
            if finding.is_malicious:
                malicious_seen = True
            elif advisory.severity in (Severity.HIGH, Severity.CRITICAL):
                high_or_critical_seen = True

    sarif: dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pwned-deps",
                        "version": version,
                        "informationUri": INFORMATION_URI,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    if parse_failed:
        exit_code = 3
    elif malicious_seen:
        exit_code = 1
    elif high_or_critical_seen:
        exit_code = 2
    else:
        exit_code = 0

    return json.dumps(sarif, indent=2, sort_keys=True), exit_code


def _rule_for(advisory: Any, is_malicious: bool) -> dict[str, Any]:
    short = advisory.summary or f"{advisory.package}@{advisory.version}"
    text = (
        advisory.summary
        or f"Advisory {advisory.id} affects {advisory.package}@{advisory.version}."
    )
    return {
        "id": advisory.id,
        "name": _camel(advisory.id),
        "shortDescription": {"text": _truncate(short, 240)},
        "fullDescription": {"text": text},
        "defaultConfiguration": {
            "level": _level_from(advisory.severity, is_malicious=is_malicious),
        },
        "helpUri": advisory.references[0] if advisory.references else INFORMATION_URI,
        "properties": {
            "ecosystem": advisory.ecosystem,
            "is_malicious": is_malicious,
            "severity": advisory.severity.value,
        },
    }


def _result_for(report: ScanReport, finding: Any) -> dict[str, Any]:
    advisory = finding.advisory
    fingerprint_basis = (
        f"{advisory.id}|{advisory.package}|{advisory.version}|{report.lockfile.path}"
    )
    fingerprint = hashlib.sha256(fingerprint_basis.encode("utf-8")).hexdigest()
    return {
        "ruleId": advisory.id,
        "level": _level_from(advisory.severity, is_malicious=finding.is_malicious),
        "message": {
            "text": _result_message(finding),
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": str(report.lockfile.path),
                    },
                }
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": fingerprint,
        },
        "properties": {
            "package": advisory.package,
            "version": advisory.version,
            "ecosystem": advisory.ecosystem,
            "campaign_name": finding.campaign_name,
            "is_malicious": finding.is_malicious,
        },
    }


def _result_message(finding: Any) -> str:
    advisory = finding.advisory
    parts = [f"{advisory.package}@{advisory.version}: {advisory.id}"]
    if finding.campaign_name:
        parts.append(f"({finding.campaign_name})")
    if advisory.summary:
        parts.append("—")
        parts.append(_truncate(advisory.summary, 400))
    return " ".join(parts)


def _level_from(severity: Severity, *, is_malicious: bool) -> str:
    if is_malicious:
        return "error"
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity is Severity.MEDIUM:
        return "warning"
    return "note"


def _camel(advisory_id: str) -> str:
    """Approximate SARIF rule names: alphanumeric, no separators."""

    return "".join(ch for ch in advisory_id if ch.isalnum())


def _truncate(text: str, limit: int) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"
