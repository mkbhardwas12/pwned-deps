"""Static HTML dashboard for ``pwned-deps`` scan results.

Reads one or more JSON scan documents (the output of
``pwned-deps check --format json``) and renders a single self-contained
HTML file. Inline CSS, no external assets, no JavaScript dependencies,
no server required. Drop the file into S3, GitHub Pages, or just
``open`` it locally.

Aggregation: when given multiple scan files (e.g. CI artifacts from
many repos in an org) the dashboard surfaces:

* Top-level KPIs: total scans, packages, MALICIOUS hits, HIGH/CRITICAL
  CVE hits, distinct ecosystems.
* Per-campaign rollup: same advisory id appearing across multiple
  repos = high-priority cross-org incident.
* Per-finding table with severity / ecosystem / campaign filters.

Security: every campaign-supplied string (summary, IoCs, references,
package names) is HTML-escaped at render time. The matcher's JSON
output may carry attacker-influenced text (registry metadata, repo
descriptions); we never trust it raw. References are additionally
validated to begin with ``http://`` or ``https://`` before becoming
``<a href>`` targets.
"""

from __future__ import annotations

import html
import json
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DASHBOARD_SCHEMA_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Data shaping
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Finding:
    scan_source: str
    lockfile_path: str
    ecosystem: str
    package: str
    version: str
    advisory_id: str
    severity: str
    summary: str
    references: tuple[str, ...]
    is_malicious: bool
    campaign_name: str | None
    iocs: tuple[str, ...]


@dataclass
class _Aggregate:
    scans: list[dict[str, Any]] = field(default_factory=list)
    findings: list[_Finding] = field(default_factory=list)
    total_packages: int = 0
    parse_errors: int = 0

    @property
    def malicious_count(self) -> int:
        return sum(1 for f in self.findings if f.is_malicious)

    @property
    def high_critical_count(self) -> int:
        return sum(
            1
            for f in self.findings
            if not f.is_malicious and f.severity in ("HIGH", "CRITICAL")
        )

    @property
    def ecosystems(self) -> list[str]:
        return sorted({f.ecosystem for f in self.findings})

    @property
    def campaigns(self) -> list[tuple[str, int, list[_Finding]]]:
        """Return ``[(advisory_id, hit_count, findings), ...]`` sorted by hits desc."""
        bucket: dict[str, list[_Finding]] = defaultdict(list)
        for f in self.findings:
            bucket[f.advisory_id].append(f)
        rows = [(adv_id, len(hits), hits) for adv_id, hits in bucket.items()]
        rows.sort(key=lambda r: (-r[1], r[0]))
        return rows


def _coerce_iter(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(s for s in value if isinstance(s, str))


def _ingest(scan: dict[str, Any], source_label: str, agg: _Aggregate) -> None:
    """Fold one scan document into the aggregate."""
    summary = scan.get("summary", {}) or {}
    agg.total_packages += int(summary.get("total_packages", 0) or 0)
    agg.scans.append(
        {
            "source": source_label,
            "tool_version": (scan.get("tool", {}) or {}).get("version", "?"),
            "lockfile_count": len(scan.get("lockfiles", []) or []),
            "package_count": int(summary.get("total_packages", 0) or 0),
            "compromised": int(summary.get("compromised", 0) or 0),
            "high_critical": int(summary.get("high_critical", 0) or 0),
        }
    )
    for lockfile in scan.get("lockfiles", []) or []:
        if lockfile.get("parse_error"):
            agg.parse_errors += 1
        for raw in lockfile.get("findings", []) or []:
            agg.findings.append(
                _Finding(
                    scan_source=source_label,
                    lockfile_path=str(lockfile.get("path", "?")),
                    ecosystem=str(raw.get("ecosystem", "?")),
                    package=str(raw.get("package", "?")),
                    version=str(raw.get("version", "?")),
                    advisory_id=str(raw.get("id", "?")),
                    severity=str(raw.get("severity", "?")),
                    summary=str(raw.get("summary", "")),
                    references=_coerce_iter(raw.get("references")),
                    is_malicious=bool(raw.get("is_malicious", False)),
                    campaign_name=raw.get("campaign_name"),
                    iocs=_coerce_iter(raw.get("iocs")),
                )
            )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def render_dashboard(
    scans: Sequence[tuple[str, dict[str, Any]]],
    *,
    title: str = "pwned-deps dashboard",
    generated_at: datetime | None = None,
) -> str:
    """Render a single HTML document for ``scans``.

    ``scans`` is a sequence of ``(source_label, scan_payload)`` tuples
    where ``scan_payload`` is the parsed JSON produced by
    ``pwned-deps check --format json``. ``source_label`` is shown
    verbatim in the per-finding table (typically the file path or repo
    name).
    """
    agg = _Aggregate()
    for label, scan in scans:
        _ingest(scan, label, agg)

    when = (generated_at or datetime.now(timezone.utc)).strftime(
        "%Y-%m-%d %H:%M UTC"
    )
    return _PAGE_TEMPLATE.format(
        title=html.escape(title),
        generated=html.escape(when),
        schema=DASHBOARD_SCHEMA_VERSION,
        kpi_cards=_render_kpis(agg),
        scans_table=_render_scans_table(agg),
        campaigns_table=_render_campaigns_table(agg),
        findings_table=_render_findings_table(agg),
        css=_CSS,
    )


def render_dashboard_from_paths(
    paths: Iterable[Path],
    *,
    title: str = "pwned-deps dashboard",
) -> str:
    """Convenience wrapper: load JSON from each path and render.

    Skips files that are not valid JSON or not pwned-deps scan
    documents (silently; surface a count via the dashboard's "scans"
    table).
    """
    scans: list[tuple[str, dict[str, Any]]] = []
    for path in paths:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict) or "lockfiles" not in payload:
            continue
        scans.append((str(path), payload))
    return render_dashboard(scans, title=title)


# ---------------------------------------------------------------------------
# Renderers (small, hand-written; no template engine dep)
# ---------------------------------------------------------------------------


def _render_kpis(agg: _Aggregate) -> str:
    cards = [
        ("Scans", len(agg.scans), "neutral"),
        ("Packages scanned", agg.total_packages, "neutral"),
        ("Compromised", agg.malicious_count, "red" if agg.malicious_count else "green"),
        (
            "HIGH/CRITICAL CVEs",
            agg.high_critical_count,
            "yellow" if agg.high_critical_count else "green",
        ),
        ("Ecosystems", len(agg.ecosystems), "neutral"),
        ("Parse errors", agg.parse_errors, "yellow" if agg.parse_errors else "green"),
    ]
    parts = []
    for label, value, tone in cards:
        parts.append(
            f'<div class="kpi kpi-{tone}">'
            f'<div class="kpi-num">{html.escape(str(value))}</div>'
            f'<div class="kpi-lbl">{html.escape(label)}</div>'
            f"</div>"
        )
    return "".join(parts)


def _render_scans_table(agg: _Aggregate) -> str:
    if not agg.scans:
        return "<p class=empty>No scan files supplied.</p>"
    rows = []
    for s in agg.scans:
        rows.append(
            "<tr>"
            f"<td><code>{html.escape(s['source'])}</code></td>"
            f"<td>{html.escape(s['tool_version'])}</td>"
            f"<td class=num>{s['lockfile_count']}</td>"
            f"<td class=num>{s['package_count']}</td>"
            f"<td class='num {'bad' if s['compromised'] else ''}'>{s['compromised']}</td>"
            f"<td class='num {'warn' if s['high_critical'] else ''}'>{s['high_critical']}</td>"
            "</tr>"
        )
    return (
        "<table class=t><thead><tr>"
        "<th>Source</th><th>Tool</th>"
        "<th class=num>Lockfiles</th><th class=num>Packages</th>"
        "<th class=num>MAL</th><th class=num>HIGH/CRIT</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _render_campaigns_table(agg: _Aggregate) -> str:
    rows_data = agg.campaigns
    if not rows_data:
        return "<p class=empty>No findings — clean across all scans.</p>"
    rows = []
    for adv_id, hit_count, findings in rows_data:
        sample = findings[0]
        eco_set = sorted({f.ecosystem for f in findings})
        sources = sorted({f.scan_source for f in findings})
        kind_cls = "bad" if sample.is_malicious else (
            "warn" if sample.severity in ("HIGH", "CRITICAL") else "neutral"
        )
        kind_label = "MALICIOUS" if sample.is_malicious else sample.severity
        rows.append(
            "<tr>"
            f"<td><code>{html.escape(adv_id)}</code></td>"
            f"<td><span class='pill pill-{kind_cls}'>{html.escape(kind_label)}</span></td>"
            f"<td>{html.escape(sample.campaign_name or '')}</td>"
            f"<td>{html.escape(', '.join(eco_set))}</td>"
            f"<td class=num>{hit_count}</td>"
            f"<td class=num>{len(sources)}</td>"
            "</tr>"
        )
    return (
        "<table class=t><thead><tr>"
        "<th>Advisory</th><th>Kind</th><th>Campaign</th>"
        "<th>Ecosystems</th><th class=num>Hits</th><th class=num>Sources</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _render_findings_table(agg: _Aggregate) -> str:
    if not agg.findings:
        return ""

    # Sort: malicious first, then severity rank, then ecosystem/name.
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "?": 9}
    sorted_findings = sorted(
        agg.findings,
        key=lambda f: (
            0 if f.is_malicious else 1,
            sev_rank.get(f.severity, 9),
            f.ecosystem,
            f.package,
            f.version,
        ),
    )

    # Build filter chips.
    eco_chips = _filter_chips("eco", sorted({f.ecosystem for f in sorted_findings}))
    sev_chips = _filter_chips(
        "sev", ["MALICIOUS", *sorted({f.severity for f in sorted_findings})]
    )

    rows = []
    for f in sorted_findings:
        kind_cls = "bad" if f.is_malicious else (
            "warn" if f.severity in ("HIGH", "CRITICAL") else "neutral"
        )
        kind_label = "MALICIOUS" if f.is_malicious else f.severity
        ref_links = " ".join(
            f'<a href="{html.escape(r)}" rel="noopener noreferrer" target="_blank">[ref]</a>'
            for r in f.references
            if r.startswith(("http://", "https://"))
        )
        sev_attr = "MALICIOUS" if f.is_malicious else f.severity
        rows.append(
            f'<tr data-eco="{html.escape(f.ecosystem)}" data-sev="{html.escape(sev_attr)}">'
            f"<td><span class='pill pill-{kind_cls}'>{html.escape(kind_label)}</span></td>"
            f"<td><code>{html.escape(f.ecosystem)}:{html.escape(f.package)}@{html.escape(f.version)}</code></td>"
            f"<td><code>{html.escape(f.advisory_id)}</code> {ref_links}</td>"
            f"<td>{html.escape(f.campaign_name or '')}</td>"
            f"<td><code>{html.escape(f.lockfile_path)}</code></td>"
            f"<td><code>{html.escape(f.scan_source)}</code></td>"
            "</tr>"
        )

    table = (
        "<table class='t findings-table'><thead><tr>"
        "<th>Kind</th><th>Package</th><th>Advisory</th>"
        "<th>Campaign</th><th>Lockfile</th><th>Source</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )

    return f"""
<div class=filters>
  <div class=filter-group>
    <span class=filter-label>Severity:</span>{sev_chips}
  </div>
  <div class=filter-group>
    <span class=filter-label>Ecosystem:</span>{eco_chips}
  </div>
</div>
{table}
{_FILTER_JS}
"""


def _filter_chips(kind: str, values: Iterable[str]) -> str:
    safe_values = [v for v in values if v]
    parts = [
        f'<button class="chip chip-active" data-filter="{kind}" data-value="">all</button>'
    ]
    counts: Counter[str] = Counter(safe_values)
    for v in sorted(set(safe_values)):
        parts.append(
            f'<button class="chip" data-filter="{kind}" '
            f'data-value="{html.escape(v)}">{html.escape(v)}</button>'
        )
    _ = counts  # reserved for future per-chip counts
    return "".join(parts)


# ---------------------------------------------------------------------------
# Inline assets
# ---------------------------------------------------------------------------


_CSS = """
:root {
  --fg: #0f172a; --muted: #64748b; --bg: #f8fafc; --card: #fff;
  --border: #e2e8f0; --bad: #dc2626; --bad-bg: #fef2f2; --warn: #d97706;
  --warn-bg: #fffbeb; --good: #16a34a; --good-bg: #f0fdf4;
  --accent: #0369a1;
}
* { box-sizing: border-box; }
body { font-family: -apple-system, system-ui, "Segoe UI", Roboto, sans-serif;
       margin: 0; padding: 0; background: var(--bg); color: var(--fg); }
header { background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
         color: #fff; padding: 2rem 2rem 1.5rem; }
header h1 { margin: 0 0 .25rem; font-size: 1.6rem; letter-spacing: -.01em; }
header .sub { color: #94a3b8; font-size: .9rem; }
main { max-width: 1280px; margin: 0 auto; padding: 1.5rem 2rem 4rem; }
h2 { font-size: 1.05rem; text-transform: uppercase; letter-spacing: .05em;
     color: var(--muted); margin: 2rem 0 .75rem; font-weight: 600; }

.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
        gap: 1rem; margin-top: -2.5rem; position: relative; z-index: 2; }
.kpi { background: var(--card); border: 1px solid var(--border);
       border-radius: 10px; padding: 1rem 1.25rem; box-shadow: 0 1px 2px rgba(0,0,0,.04); }
.kpi-num { font-size: 2rem; font-weight: 700; line-height: 1; letter-spacing: -.02em; }
.kpi-lbl { color: var(--muted); font-size: .8rem; text-transform: uppercase;
           letter-spacing: .05em; margin-top: .35rem; }
.kpi-red .kpi-num { color: var(--bad); }
.kpi-yellow .kpi-num { color: var(--warn); }
.kpi-green .kpi-num { color: var(--good); }

.t { width: 100%; border-collapse: collapse; background: var(--card);
     border: 1px solid var(--border); border-radius: 8px; overflow: hidden;
     font-size: .9rem; }
.t th, .t td { padding: .55rem .85rem; text-align: left;
               border-bottom: 1px solid var(--border); vertical-align: top; }
.t th { background: #f1f5f9; font-weight: 600; color: var(--muted);
        text-transform: uppercase; font-size: .72rem; letter-spacing: .04em; }
.t tr:last-child td { border-bottom: 0; }
.t tr:hover td { background: #f8fafc; }
.t .num { text-align: right; font-variant-numeric: tabular-nums; }
.t code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
          font-size: .85em; background: #f1f5f9; padding: 1px 5px; border-radius: 4px; }
.t .bad { color: var(--bad); font-weight: 600; }
.t .warn { color: var(--warn); font-weight: 600; }
.t a { color: var(--accent); text-decoration: none; font-size: .8em; }
.t a:hover { text-decoration: underline; }

.pill { display: inline-block; padding: 2px 8px; border-radius: 99px;
        font-size: .72rem; font-weight: 700; letter-spacing: .03em; }
.pill-bad { background: var(--bad-bg); color: var(--bad); }
.pill-warn { background: var(--warn-bg); color: var(--warn); }
.pill-neutral { background: #f1f5f9; color: var(--muted); }

.filters { display: flex; flex-wrap: wrap; gap: 1.25rem; margin: .75rem 0; }
.filter-group { display: flex; align-items: center; gap: .5rem; flex-wrap: wrap; }
.filter-label { color: var(--muted); font-size: .8rem; font-weight: 600;
                text-transform: uppercase; letter-spacing: .04em; }
.chip { background: var(--card); border: 1px solid var(--border); padding: 3px 10px;
        border-radius: 99px; cursor: pointer; font-size: .78rem; color: var(--fg);
        font-family: inherit; }
.chip:hover { border-color: var(--accent); color: var(--accent); }
.chip-active { background: var(--accent); color: #fff; border-color: var(--accent); }
.chip-active:hover { color: #fff; }

.empty { padding: 2rem; text-align: center; color: var(--muted);
         background: var(--card); border: 1px dashed var(--border); border-radius: 8px; }
footer { color: var(--muted); font-size: .8rem; text-align: center;
         padding: 1rem; border-top: 1px solid var(--border); }
footer a { color: var(--accent); }
"""


_FILTER_JS = """
<script>
(() => {
  const state = { sev: '', eco: '' };
  const apply = () => {
    document.querySelectorAll('.findings-table tbody tr').forEach(tr => {
      const sevOk = !state.sev || tr.dataset.sev === state.sev
        || (state.sev === 'MALICIOUS' && tr.dataset.sev === 'MALICIOUS');
      const ecoOk = !state.eco || tr.dataset.eco === state.eco;
      tr.style.display = (sevOk && ecoOk) ? '' : 'none';
    });
  };
  document.querySelectorAll('.chip').forEach(b => {
    b.addEventListener('click', () => {
      const f = b.dataset.filter, v = b.dataset.value;
      state[f] = v;
      document.querySelectorAll(`.chip[data-filter="${f}"]`).forEach(x =>
        x.classList.toggle('chip-active', x.dataset.value === v));
      apply();
    });
  });
})();
</script>
"""


_PAGE_TEMPLATE = """<!doctype html>
<html lang=en>
<head>
<meta charset=utf-8>
<meta name=viewport content="width=device-width, initial-scale=1">
<meta name=generator content="pwned-deps dashboard {schema}">
<title>{title}</title>
<style>{css}</style>
</head>
<body>
<header>
  <h1>{title}</h1>
  <div class=sub>Generated {generated} · static report · no telemetry</div>
</header>
<main>
  <div class=kpis>{kpi_cards}</div>

  <h2>Scan sources</h2>
  {scans_table}

  <h2>Campaign rollup</h2>
  {campaigns_table}

  <h2>All findings</h2>
  {findings_table}
</main>
<footer>
  Generated by <a href="https://github.com/mkbhardwas12/pwned-deps">pwned-deps</a>
  · static HTML, no JS dependencies, no external assets, no analytics.
</footer>
</body>
</html>
"""
