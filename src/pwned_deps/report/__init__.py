"""Reporters — turn ``Finding`` lists into something humans/machines can consume.

* ``text`` — colourful terminal output via ``rich``.
* ``json_out`` — minimal JSON dump.
* ``sarif`` — SARIF v2.1.0 for GitHub Code Scanning.
"""

from pwned_deps.report.json_out import render_json
from pwned_deps.report.sarif import render_sarif
from pwned_deps.report.text import render_text

__all__ = ["render_json", "render_sarif", "render_text"]
