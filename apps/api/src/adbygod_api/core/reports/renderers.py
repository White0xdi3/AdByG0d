from __future__ import annotations

import csv
from datetime import datetime, timezone
from html import escape as html_escape
import io
import json
from typing import Any, Iterable

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    LongTable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents


_BRAND = colors.HexColor("#0EA5E9")
_BRAND_DARK = colors.HexColor("#082F49")
_TEXT = colors.HexColor("#111827")
_MUTED = colors.HexColor("#4B5563")
_LINE = colors.HexColor("#D1D5DB")
_SOFT = colors.HexColor("#F8FAFC")
_PANEL = colors.HexColor("#F1F5F9")
_CRIT = colors.HexColor("#991B1B")
_HIGH = colors.HexColor("#C2410C")
_MED = colors.HexColor("#A16207")
_LOW = colors.HexColor("#166534")
_INFO = colors.HexColor("#334155")


PDF_SECTION_LIMITS: dict[str, dict[str, Any]] = {
    "module_breakdown": {"threshold": 40, "max_rows": 25, "label": "module breakdown rows"},
    "coverage_assurance": {"threshold": 40, "max_rows": 25, "label": "module coverage rows"},
    "risk_themes": {"threshold": 40, "max_rows": 25, "label": "risk theme rows"},
    "graph_edge_types": {"threshold": 50, "max_rows": 30, "label": "graph edge-type rows"},
    "pki_posture": {"threshold": 80, "max_rows": 25, "label": "certificate templates"},
    "trust_posture": {"threshold": 80, "max_rows": 25, "label": "trust relationships"},
    "service_accounts": {"threshold": 100, "max_rows": 30, "label": "service accounts"},
    "validation": {"threshold": 80, "max_rows": 30, "label": "validation runs"},
    "evidence_appendix": {"threshold": 80, "max_rows": 40, "label": "evidence records"},
}


def _rank_value(value: Any, ranks: dict[str, int], default: int = 99) -> int:
    return ranks.get(str(value or "").upper(), default)


def _pki_sort_key(row: list[Any]) -> tuple[Any, ...]:
    flags = str(row[2] or "")
    vulnerable = str(row[3] or "").lower() == "yes"
    return (
        0 if vulnerable else 1,
        0 if "ESC1" in flags else 1,
        0 if "ESC4" in flags else 1,
        0 if flags != "-" else 1,
        str(row[0] or "").lower(),
        str(row[1] or "").lower(),
    )


def _trust_sort_key(row: list[Any]) -> tuple[Any, ...]:
    return (
        _rank_value(row[3], {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}),
        0 if str(row[4] or "").lower() == "no" else 1,
        0 if str(row[5] or "").lower() == "no" else 1,
        str(row[1] or "").lower(),
        str(row[0] or "").lower(),
    )


def _service_account_sort_key(row: list[Any]) -> tuple[Any, ...]:
    try:
        password_age = int(float(row[6] or 0))
    except (TypeError, ValueError):
        password_age = 0
    return (
        _rank_value(row[0], {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}),
        0 if str(row[3] or "").lower() == "yes" else 1,
        0 if str(row[4] or "").lower() == "yes" else 1,
        0 if str(row[5] or "").lower() == "yes" else 1,
        -password_age,
        str(row[1] or "").lower(),
    )


def _evidence_sort_key(row: list[Any]) -> tuple[Any, ...]:
    return (
        _rank_value(row[0], {"COLLECTED": 0, "IMPORTED": 1, "INFERRED": 2, "SIMULATED": 3}),
        str(row[1] or "").lower(),
        str(row[2] or "").lower(),
    )


def compact_rows_for_pdf(
    section_id: str,
    rows: Iterable[list[Any]],
    *,
    sort_key: Any | None = None,
    limits: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return PDF-safe rows plus explicit compaction metadata.

    Small sections are left untouched. Large sections are deterministically
    sorted, capped, and accompanied by disclosure text so PDF exports remain
    analyst-facing reports rather than raw inventory dumps.
    """
    row_list = list(rows)
    policy = (limits or PDF_SECTION_LIMITS).get(section_id, {})
    threshold = int(policy.get("threshold", len(row_list)))
    max_rows = int(policy.get("max_rows", threshold))
    label = str(policy.get("label") or "rows")
    total = len(row_list)

    if total <= threshold:
        return {
            "rows": row_list,
            "total_count": total,
            "displayed_count": total,
            "omitted_count": 0,
            "is_compacted": False,
            "disclosure": "",
        }

    ordered = sorted(row_list, key=sort_key) if sort_key else row_list
    displayed = ordered[:max_rows]
    omitted = max(0, total - len(displayed))
    return {
        "rows": displayed,
        "total_count": total,
        "displayed_count": len(displayed),
        "omitted_count": omitted,
        "is_compacted": True,
        "disclosure": (
            f"This section is summarized for PDF readability. Showing {len(displayed):,} "
            f"of {total:,} {label}. Rows omitted from PDF: {omitted:,}. "
            "Full inventory remains available in structured exports, the API, and the assessment UI."
        ),
    }


def _section_ids(payload: dict[str, Any]) -> set[str]:
    return set(payload.get("report_meta", {}).get("sections", {}).get("included", []) or [])


def _safe_text(value: Any, fallback: str = "-") -> str:
    if value is None:
        return fallback
    text = str(value).replace("\x00", " ").strip()
    return text or fallback


def _h(value: Any, fallback: str = "-") -> str:
    return html_escape(_safe_text(value, fallback))


def _fmt_number(value: Any, decimals: int | None = None) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "0"
    if decimals is None:
        if number.is_integer():
            return f"{int(number):,}"
        return f"{number:,.2f}"
    return f"{number:,.{decimals}f}"


def _fmt_bool(value: Any) -> str:
    return "Yes" if bool(value) else "No"


def _compact_json(value: Any, limit: int = 420) -> str:
    try:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except Exception:
        text = _safe_text(value)
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _sanitize_csv_cell(value: Any) -> str:
    s = str(value) if value is not None else ""
    return ("'" + s) if s and s[0] in _FORMULA_PREFIXES else s


def render_csv_report(payload: dict[str, Any]) -> str:
    """Render a complete findings register CSV.

    CSV is intentionally focused on the finding register so analysts can import it
    into ticketing, spreadsheets, or triage workflows without losing provenance.
    The JSON/PDF/HTML outputs carry the richer multi-section dossier.
    """
    out = io.StringIO()
    fields = [
        "finding_id",
        "severity",
        "score",
        "status",
        "origin",
        "risk_themes",
        "module",
        "finding_type",
        "title",
        "affected_count",
        "confidence",
        "technical_severity",
        "reachability_score",
        "evidence_count",
        "fix_complexity",
        "estimated_effort",
        "description",
        "root_cause",
        "remediation",
        "remediation_steps",
        "cve_ids",
        "mitre_attack_ids",
        "references",
        "first_seen",
        "last_seen",
    ]
    writer = csv.DictWriter(out, fieldnames=fields)
    writer.writeheader()
    detail_map = {str(item.get("id")): item for item in payload.get("finding_details", [])}
    for finding in payload.get("findings_register", []):
        detail = detail_map.get(str(finding.get("id")), {})
        writer.writerow(
            {
                "finding_id": finding.get("id"),
                "severity": _sanitize_csv_cell(finding.get("severity")),
                "score": finding.get("composite_score"),
                "status": _sanitize_csv_cell(finding.get("status")),
                "origin": _sanitize_csv_cell(finding.get("origin")),
                "risk_themes": _sanitize_csv_cell(" | ".join(finding.get("risk_themes", []) or [])),
                "module": _sanitize_csv_cell(finding.get("module")),
                "finding_type": _sanitize_csv_cell(finding.get("finding_type")),
                "title": _sanitize_csv_cell(finding.get("title")),
                "affected_count": finding.get("affected_count"),
                "confidence": _sanitize_csv_cell(finding.get("confidence")),
                "technical_severity": _sanitize_csv_cell(finding.get("technical_severity")),
                "reachability_score": finding.get("reachability_score"),
                "evidence_count": finding.get("evidence_count"),
                "fix_complexity": _sanitize_csv_cell(finding.get("fix_complexity")),
                "estimated_effort": _sanitize_csv_cell(finding.get("estimated_effort")),
                "description": _sanitize_csv_cell(detail.get("description", "")),
                "root_cause": _sanitize_csv_cell(detail.get("root_cause", "")),
                "remediation": _sanitize_csv_cell(detail.get("remediation", "")),
                "remediation_steps": _compact_json(detail.get("remediation_steps", []), 1600),
                "cve_ids": _compact_json(detail.get("cve_ids") or finding.get("cve_ids", []), 800),
                "mitre_attack_ids": _compact_json(detail.get("mitre_attack_ids") or finding.get("mitre_attack_ids", []), 800),
                "references": _compact_json(detail.get("references", []), 800),
                "first_seen": finding.get("first_seen"),
                "last_seen": finding.get("last_seen"),
            }
        )
    return out.getvalue()


def _html_table(headers: Iterable[str], rows: Iterable[Iterable[Any]], *, cls: str = "") -> str:
    header_html = "".join(f"<th>{_h(header)}</th>" for header in headers)
    row_html = []
    for row in rows:
        row_html.append("<tr>" + "".join(f"<td>{_h(cell)}</td>" for cell in row) + "</tr>")
    class_attr = f' class="{html_escape(cls)}"' if cls else ""
    return f"<table{class_attr}><thead><tr>{header_html}</tr></thead><tbody>{''.join(row_html)}</tbody></table>"


def _html_badge(text: str, kind: str = "neutral") -> str:
    return f'<span class="badge badge-{html_escape(kind)}">{_h(text)}</span>'


def _html_metric(label: str, value: Any, hint: Any = "") -> str:
    return (
        '<div class="metric">'
        f'<div class="metric-label">{_h(label)}</div>'
        f'<div class="metric-value">{_h(value)}</div>'
        f'<div class="metric-hint">{_h(hint, "")}</div>'
        '</div>'
    )


def _html_bar_rows(rows: Iterable[tuple[Any, Any]], *, max_value: float | None = None) -> str:
    rendered: list[str] = []
    normalized = [(_safe_text(label), max(0.0, float(value or 0))) for label, value in rows]
    denominator = max_value if max_value is not None else max((value for _label, value in normalized), default=0.0)
    denominator = denominator or 1.0
    for label, value in normalized:
        pct = min(100.0, max(0.0, value / denominator * 100.0))
        rendered.append(
            '<div class="bar-row">'
            f'<div class="bar-label">{_h(label)}</div>'
            '<div class="bar-track">'
            f'<div class="bar-fill" style="width:{pct:.1f}%"></div>'
            '</div>'
            f'<div class="bar-value">{_h(_fmt_number(value, 0))}</div>'
            '</div>'
        )
    return ''.join(rendered) or '<p class="muted">No data recorded.</p>'


def render_html_report(payload: dict[str, Any]) -> str:
    sections = _section_ids(payload)
    assessment = payload.get("assessment", {})
    exposure = payload.get("exposure", {})
    risk = payload.get("risk_analysis", {})
    coverage = payload.get("coverage_assurance", {})
    quality = payload.get("data_quality", {})
    themes = payload.get("risk_theme_summary", {})
    action_board = payload.get("priority_action_board", {})
    meta = payload.get("report_meta", {})

    chunks: list[str] = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>AdByG0d Report - {_h(assessment.get('domain'), 'assessment')}</title>",
        "<style>",
        """
        :root { --ink:#0f172a; --muted:#475569; --line:#cbd5e1; --panel:#f8fafc; --brand:#0284c7; --brand-2:#0f172a; --crit:#991b1b; --high:#c2410c; --med:#a16207; --low:#166534; }
        * { box-sizing:border-box; }
        body { margin:0; font-family:Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color:var(--ink); background:#fff; line-height:1.45; }
        .wrap { width:min(1240px, calc(100vw - 48px)); margin:0 auto; padding:36px 0 72px; }
        .hero { border:1px solid var(--line); border-radius:28px; overflow:hidden; background:linear-gradient(135deg,#082f49,#0f172a); color:#fff; padding:36px; box-shadow:0 24px 80px rgba(2,8,23,.16); }
        .eyebrow { text-transform:uppercase; letter-spacing:.22em; font-size:12px; opacity:.82; }
        h1 { margin:16px 0 8px; font-size:42px; line-height:1.05; }
        h2 { margin:0 0 16px; font-size:28px; }
        h3 { margin:22px 0 10px; font-size:19px; }
        p { margin:8px 0; }
        .hero-grid, .metrics, .two-col { display:grid; gap:18px; }
        .hero-grid { grid-template-columns: 1.4fr .8fr; align-items:end; margin-top:22px; }
        .metrics { grid-template-columns:repeat(4,1fr); margin-top:24px; }
        .metric { border:1px solid rgba(255,255,255,.18); border-radius:20px; padding:16px; background:rgba(255,255,255,.08); }
        .metric-label { font-size:12px; letter-spacing:.14em; text-transform:uppercase; opacity:.78; }
        .metric-value { margin-top:10px; font-size:28px; font-weight:700; }
        .metric-hint { margin-top:4px; color:rgba(255,255,255,.78); font-size:13px; }
        .section { margin-top:28px; border:1px solid var(--line); border-radius:24px; padding:26px; background:#fff; box-shadow:0 18px 45px rgba(15,23,42,.05); }
        .panel { padding:18px; border:1px solid var(--line); border-radius:18px; background:var(--panel); }
        .two-col { grid-template-columns:repeat(2,1fr); }
        .pill-row { display:flex; flex-wrap:wrap; gap:8px; margin-top:14px; }
        .badge { display:inline-flex; align-items:center; border-radius:999px; border:1px solid var(--line); padding:4px 10px; font-size:12px; font-weight:600; background:#fff; }
        .badge-critical { color:var(--crit); border-color:#fecaca; background:#fef2f2; }
        .badge-high { color:var(--high); border-color:#fed7aa; background:#fff7ed; }
        .badge-medium { color:var(--med); border-color:#fde68a; background:#fefce8; }
        .badge-low { color:var(--low); border-color:#bbf7d0; background:#f0fdf4; }
        .badge-neutral { color:var(--brand-2); background:#f8fafc; }
        table { width:100%; border-collapse:collapse; margin-top:14px; font-size:13px; table-layout:auto; }
        th, td { padding:10px 12px; vertical-align:top; border-bottom:1px solid #e2e8f0; text-align:left; word-break:break-word; }
        th { color:#0f172a; text-transform:uppercase; letter-spacing:.08em; font-size:11px; background:#f8fafc; }
        tr:last-child td { border-bottom:none; }
        .finding { border:1px solid var(--line); border-radius:18px; padding:18px; margin-top:14px; }
        .finding-title { display:flex; justify-content:space-between; align-items:flex-start; gap:16px; }
        .finding-title h3 { margin:0; }
        .mono { font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace; font-size:12px; white-space:pre-wrap; word-break:break-word; }
        .muted { color:var(--muted); }
        .footer-note { margin-top:28px; padding:18px; border-radius:18px; background:#f8fafc; border:1px solid var(--line); color:var(--muted); }
        .assurance-banner { margin-top:18px; display:flex; flex-wrap:wrap; gap:12px; align-items:center; justify-content:space-between; padding:16px 18px; border:1px solid rgba(255,255,255,.18); border-radius:20px; background:rgba(255,255,255,.08); }
        .assurance-banner strong { font-size:15px; }
        .signal-grid { display:grid; gap:14px; grid-template-columns:repeat(4,1fr); margin-top:16px; }
        .signal { border:1px solid var(--line); border-radius:18px; padding:16px; background:var(--panel); }
        .signal-label { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.16em; }
        .signal-value { margin-top:8px; font-size:24px; line-height:1; font-weight:700; color:var(--brand-2); }
        .signal-hint { margin-top:6px; color:var(--muted); font-size:12px; }
        .bar-list { margin-top:14px; display:grid; gap:10px; }
        .bar-row { display:grid; grid-template-columns:minmax(150px, 1.3fr) 2.2fr 56px; gap:12px; align-items:center; }
        .bar-label { font-size:13px; color:var(--ink); }
        .bar-track { height:12px; border-radius:999px; background:#e2e8f0; overflow:hidden; }
        .bar-fill { height:100%; border-radius:999px; background:linear-gradient(90deg,#0ea5e9,#2563eb); }
        .bar-value { text-align:right; font-size:12px; font-weight:700; color:var(--muted); }
        .timeline-grid { display:grid; gap:14px; grid-template-columns:repeat(3,1fr); margin-top:16px; }
        .timeline-card { border:1px solid var(--line); border-radius:18px; padding:16px; background:var(--panel); }
        .timeline-card h3 { margin:0 0 10px; font-size:16px; }
        .timeline-card ul { margin:0; padding-left:18px; color:var(--muted); font-size:13px; }
        .timeline-card li + li { margin-top:6px; }
        .theme-chip { display:inline-flex; margin:2px 4px 2px 0; border-radius:999px; border:1px solid #bae6fd; background:#f0f9ff; color:#075985; padding:3px 9px; font-size:11px; font-weight:600; }
        @media (max-width: 960px) { .hero-grid, .metrics, .two-col, .signal-grid, .timeline-grid { grid-template-columns:1fr; } .bar-row { grid-template-columns:1fr; } .bar-value { text-align:left; } .wrap { width:min(100vw - 24px, 1240px); } h1 { font-size:34px; } }
        @media print { body { background:#fff; } .wrap { width:auto; margin:0; padding:0; } .hero, .section { box-shadow:none; page-break-inside:avoid; } .section { page-break-before:auto; } }
        """,
        "</style>",
        "</head>",
        "<body>",
        '<main class="wrap">',
        '<section class="hero">',
        '<div class="eyebrow">AdByG0d Assessment Report</div>',
        f"<h1>{_h(assessment.get('name'), 'Assessment')}</h1>",
        f"<p>{_h(assessment.get('domain'), 'Unknown domain')} - generated {_h(meta.get('generated_at'), '')}</p>",
        '<div class="hero-grid">',
        '<div class="panel">',
        f"<strong>Report posture:</strong> {_h(risk.get('rating'), 'UNKNOWN')} risk, graph-backed score {_h(_fmt_number(assessment.get('exposure_score'), 1))}.",
        f"<p class=\"muted\">{_h(meta.get('provenance_policy'), '')}</p>",
        '</div>',
        '<div class="panel">',
        f"<div><strong>Status:</strong> {_h(assessment.get('status'), 'UNKNOWN')}</div>",
        f"<div><strong>Collection mode:</strong> {_h(assessment.get('collection_mode'), 'UNKNOWN')}</div>",
        f"<div><strong>Modules run:</strong> {_h(', '.join(assessment.get('modules_run') or []) or 'Not recorded')}</div>",
        '</div>',
        '</div>',
        '<div class="metrics">',
        _html_metric("Exposure Score", _fmt_number(assessment.get("exposure_score"), 1), risk.get("rating", "UNKNOWN")),
        _html_metric("Findings", _fmt_number(exposure.get("total_findings", 0)), "Every stored finding reconciled"),
        _html_metric("Coverage", coverage.get("integrity_status", "UNKNOWN"), f"{_fmt_number(coverage.get('finding_count_reconciliation', {}).get('unreported_payload_rows', 0))} payload gaps"),
        _html_metric("Readiness", quality.get("readiness_grade", "-"), f"{_fmt_number(quality.get('readiness_score', 0), 1)} / 100"),
        '</div>',
        '<div class="assurance-banner">',
        f'<strong>Finding coverage integrity: {_h(coverage.get("integrity_status"), "UNKNOWN")}</strong>',
        f'<span>{_h(coverage.get("coverage_statement"), "Coverage reconciliation was not recorded.")}</span>',
        '</div>',
        '</section>',
    ]

    if "exec_summary" in sections:
        top_rows = [
            [
                finding.get("severity"),
                _fmt_number(finding.get("composite_score"), 1),
                finding.get("title"),
                finding.get("module"),
                finding.get("origin"),
            ]
            for finding in payload.get("top_findings", [])[:10]
        ]
        chunks.extend(
            [
                '<section class="section">',
                "<h2>Executive Summary</h2>",
                f"<p>AdByG0d identified <strong>{_h(exposure.get('total_findings', 0))}</strong> findings across the selected assessment. The global exposure score is <strong>{_h(_fmt_number(assessment.get('exposure_score'), 1))}</strong> with a <strong>{_h(risk.get('rating'), 'UNKNOWN')}</strong> rating. The report integrity ledger is <strong>{_h(coverage.get('integrity_status'), 'UNKNOWN')}</strong>, and the export readiness grade is <strong>{_h(quality.get('readiness_grade'), '-')}</strong>.</p>",
                _html_table(["Severity", "Score", "Finding", "Module", "Origin"], top_rows),
                "</section>",
            ]
        )

    if "scope_methodology" in sections:
        rows = [
            ["Assessment ID", assessment.get("id")],
            ["Domain", assessment.get("domain")],
            ["Domain Controller", assessment.get("dc_ip") or "Not recorded"],
            ["Created", assessment.get("created_at")],
            ["Started", assessment.get("started_at")],
            ["Completed", assessment.get("completed_at")],
            ["Modules", ", ".join(assessment.get("modules_run") or []) or "Not recorded"],
        ]
        chunks.extend(
            [
                '<section class="section">',
                "<h2>Scope and Methodology</h2>",
                _html_table(["Field", "Value"], rows),
                f'<div class="footer-note">{_h(meta.get("redaction_policy"), "")}</div>',
                "</section>",
            ]
        )

    if "risk_posture" in sections:
        severity_rows = [[severity, count] for severity, count in (exposure.get("severity_counts") or {}).items()]
        origin_rows = [[origin, count] for origin, count in (exposure.get("origin_counts") or {}).items()]
        module_rows_raw = [[item.get("module"), item.get("total")] for item in payload.get("module_breakdown", [])]
        module_compact = compact_rows_for_pdf("module_breakdown", module_rows_raw, sort_key=lambda row: (-int(row[1] or 0), str(row[0] or "").lower()))
        module_rows = module_compact["rows"]
        chunks.extend(
            [
                '<section class="section">',
                "<h2>Risk Posture</h2>",
                '<div class="two-col">',
                '<div class="panel"><h3>Severity Distribution</h3>',
                _html_table(["Severity", "Count"], severity_rows),
                '</div>',
                '<div class="panel"><h3>Provenance Distribution</h3>',
                _html_table(["Origin", "Count"], origin_rows),
                '</div>',
                '</div>',
                '<h3>Module Breakdown</h3>',
                _html_table(["Module", "Findings"], module_rows),
                "</section>",
            ]
        )

    if "coverage_assurance" in sections:
        reconciliation = coverage.get("finding_count_reconciliation", {})
        module_rows = [
            [
                item.get("module"),
                item.get("findings"),
                item.get("critical_high"),
                item.get("evidence_linked"),
                item.get("remediation_ready"),
            ]
            for item in coverage.get("module_coverage", [])
        ]
        chunks.extend(
            [
                '<section class="section">',
                "<h2>Finding Coverage Assurance</h2>",
                f"<p><strong>{_h(coverage.get('integrity_status'), 'UNKNOWN')}</strong> — {_h(coverage.get('coverage_statement'), '')}</p>",
                '<div class="signal-grid">',
                f'<div class="signal"><div class="signal-label">Stored findings</div><div class="signal-value">{_h(reconciliation.get("stored_findings", 0))}</div><div class="signal-hint">Assessment source of truth</div></div>',
                f'<div class="signal"><div class="signal-label">Register rows</div><div class="signal-value">{_h(reconciliation.get("finding_register_rows", 0))}</div><div class="signal-hint">Export register coverage</div></div>',
                f'<div class="signal"><div class="signal-label">Detailed rows</div><div class="signal-value">{_h(reconciliation.get("detailed_finding_rows", 0))}</div><div class="signal-hint">Finding dossier coverage</div></div>',
                f'<div class="signal"><div class="signal-label">Payload gaps</div><div class="signal-value">{_h(reconciliation.get("unreported_payload_rows", 0))}</div><div class="signal-hint">Should remain zero</div></div>',
                '</div>',
                '<h3>Module coverage ledger</h3>',
                _html_table(["Module", "Findings", "Critical/High", "Evidence Linked", "Remediation Ready"], module_rows),
                '<div class="footer-note">',
                f"Findings without linked evidence: {_h(len(coverage.get('findings_without_linked_evidence', [])))}. Findings without remediation text/steps: {_h(len(coverage.get('findings_without_remediation', [])))}. Modules run without emitted findings: {_h(', '.join(coverage.get('modules_run_without_findings', [])) or 'None')}",
                '</div>',
                '</section>',
            ]
        )

    if "risk_themes" in sections:
        theme_rows = [
            [
                item.get("theme"),
                item.get("finding_count"),
                item.get("critical_high_count"),
                _fmt_number(item.get("max_score"), 1),
                ", ".join(finding.get("title") or "" for finding in item.get("top_findings", [])[:3]) or "-",
            ]
            for item in themes.get("themes", [])
        ]
        theme_bars = _html_bar_rows([(item.get("theme"), item.get("finding_count", 0)) for item in themes.get("themes", [])])
        chunks.extend(
            [
                '<section class="section">',
                "<h2>Risk Themes</h2>",
                f"<p>{_h(themes.get('classification_policy'), '')}</p>",
                '<div class="two-col">',
                '<div class="panel"><h3>Theme concentration</h3><div class="bar-list">',
                theme_bars,
                '</div></div>',
                f'<div class="panel"><h3>Theme coverage</h3><p><strong>Themes:</strong> {_h(themes.get("theme_count", 0))}</p><p><strong>Findings tagged:</strong> {_h(themes.get("unique_findings_covered", 0))}</p><p class="muted">A finding may carry multiple report themes when it crosses risk domains.</p></div>',
                '</div>',
                _html_table(["Theme", "Findings", "Critical/High", "Max Score", "Representative Findings"], theme_rows),
                '</section>',
            ]
        )

    if "priority_action_board" in sections:
        board_rows = [
            [
                item.get("wave"),
                item.get("priority"),
                item.get("severity"),
                _fmt_number(item.get("score"), 1),
                item.get("title"),
                item.get("estimated_effort"),
                ", ".join(item.get("risk_themes", []) or []) or "-",
            ]
            for item in action_board.get("items", [])[:36]
        ]
        chunks.extend(
            [
                '<section class="section">',
                "<h2>Priority Action Board</h2>",
                f"<p>{_h(action_board.get('planning_note'), '')}</p>",
                '<div class="timeline-grid">',
                f'<div class="timeline-card"><h3>Immediate</h3><strong>{_h(action_board.get("immediate_actions", 0))}</strong><ul><li>Contain critical/highest-score exposures.</li><li>Prefer actions with direct Tier-0 impact.</li></ul></div>',
                f'<div class="timeline-card"><h3>Near-term</h3><strong>{_h(action_board.get("near_term_actions", 0))}</strong><ul><li>Retire high-scoring configuration paths.</li><li>Close high-confidence hygiene debt.</li></ul></div>',
                f'<div class="timeline-card"><h3>Planned</h3><strong>{_h(action_board.get("planned_actions", 0))}</strong><ul><li>Schedule remaining medium/low work.</li><li>Retest after control changes.</li></ul></div>',
                '</div>',
                _html_table(["Wave", "#", "Severity", "Score", "Finding", "Effort", "Themes"], board_rows),
                '</section>',
            ]
        )

    if "data_quality" in sections:
        flags = quality.get("quality_flags", {})
        quality_rows = [
            ["Findings with linked evidence", quality.get("findings_with_linked_evidence", 0), f"{_fmt_number(quality.get('finding_evidence_linkage_pct', 0), 1)}%"],
            ["Average finding confidence", _fmt_number(quality.get("average_finding_confidence", 0), 3), "Normalized 0.0-1.0"],
            ["Corroborated evidence records", quality.get("corroborated_evidence_records", 0), f"{_fmt_number(quality.get('corroborated_evidence_pct', 0), 1)}%"],
            ["Description completeness", f"{_fmt_number(quality.get('description_ready_pct', 0), 1)}%", f"{_h(flags.get('missing_description', 0))} gaps"],
            ["Remediation completeness", f"{_fmt_number(quality.get('remediation_ready_pct', 0), 1)}%", f"{_h(flags.get('missing_remediation', 0))} gaps"],
        ]
        chunks.extend(
            [
                '<section class="section">',
                "<h2>Data Quality and Confidence</h2>",
                f"<p>Report readiness grade: <strong>{_h(quality.get('readiness_grade'), '-')}</strong> ({_h(_fmt_number(quality.get('readiness_score', 0), 1))}/100). {_h(quality.get('scoring_note'), '')}</p>",
                '<div class="signal-grid">',
                f'<div class="signal"><div class="signal-label">Readiness grade</div><div class="signal-value">{_h(quality.get("readiness_grade"), "-")}</div><div class="signal-hint">{_h(_fmt_number(quality.get("readiness_score", 0), 1))}/100</div></div>',
                f'<div class="signal"><div class="signal-label">Evidence linked</div><div class="signal-value">{_h(_fmt_number(quality.get("finding_evidence_linkage_pct", 0), 1))}%</div><div class="signal-hint">Finding linkage coverage</div></div>',
                f'<div class="signal"><div class="signal-label">Avg confidence</div><div class="signal-value">{_h(_fmt_number(quality.get("average_finding_confidence", 0), 2))}</div><div class="signal-hint">Finding-level score</div></div>',
                f'<div class="signal"><div class="signal-label">Evidence records</div><div class="signal-value">{_h(quality.get("evidence_records", 0))}</div><div class="signal-hint">Redacted in appendix</div></div>',
                '</div>',
                _html_table(["Signal", "Value", "Interpretation"], quality_rows),
                '</section>',
            ]
        )

    if "finding_register" in sections:
        rows = [
            [
                finding.get("severity"),
                _fmt_number(finding.get("composite_score"), 1),
                finding.get("status"),
                finding.get("origin"),
                ", ".join(finding.get("risk_themes", []) or []) or "-",
                finding.get("module"),
                finding.get("title"),
                finding.get("affected_count"),
                finding.get("evidence_count"),
            ]
            for finding in payload.get("findings_register", [])
        ]
        chunks.extend(
            [
                '<section class="section">',
                "<h2>Complete Finding Register</h2>",
                _html_table(["Severity", "Score", "Status", "Origin", "Themes", "Module", "Title", "Affected", "Evidence"], rows),
                "</section>",
            ]
        )

    if "detailed_findings" in sections:
        chunks.extend(['<section class="section">', "<h2>Detailed Findings</h2>"])
        for finding in payload.get("finding_details", []):
            severity_kind = str(finding.get("severity", "neutral")).lower()
            evidence_rows = [
                [
                    evidence.get("origin"),
                    evidence.get("source_type"),
                    evidence.get("collection_method"),
                    _fmt_number(evidence.get("confidence"), 2),
                    evidence.get("relevance") or "-",
                ]
                for evidence in finding.get("evidence", [])[:20]
            ]
            chunks.extend(
                [
                    '<article class="finding">',
                    '<div class="finding-title">',
                    f"<h3>{_h(finding.get('title'), 'Untitled finding')}</h3>",
                    _html_badge(str(finding.get("severity", "INFO")), severity_kind),
                    '</div>',
                    '<div class="pill-row">',
                    _html_badge(str(finding.get("status", "OPEN"))),
                    _html_badge(str(finding.get("origin", "INFERRED"))),
                    _html_badge(str(finding.get("module", "Unknown"))),
                    _html_badge(f"Score {_fmt_number(finding.get('composite_score'), 1)}"),
                    '</div>',
                    f"<p><strong>Description:</strong> {_h(finding.get('description'), 'No description recorded.')}</p>",
                    f"<p><strong>Risk themes:</strong> {_h(', '.join(finding.get('risk_themes', []) or []) or 'General Exposure / Needs Classification')}</p>",
                    f"<p><strong>Root cause:</strong> {_h(finding.get('root_cause'), 'Not recorded.')}</p>",
                    f"<p><strong>Remediation:</strong> {_h(finding.get('remediation'), 'No remediation text recorded.')}</p>",
                    f"<p><strong>MITRE ATT&CK:</strong> <span class=\"mono\">{_h(_compact_json(finding.get('mitre_attack_ids', []), 500))}</span></p>",
                    f"<p><strong>CVEs:</strong> <span class=\"mono\">{_h(_compact_json(finding.get('cve_ids', []), 500))}</span></p>",
                    f"<p><strong>Attack path:</strong> <span class=\"mono\">{_h(_compact_json(finding.get('attack_path', []), 900))}</span></p>",
                    f"<p><strong>Affected objects:</strong> <span class=\"mono\">{_h(_compact_json(finding.get('affected_objects', []), 900))}</span></p>",
                    f"<p><strong>Remediation steps:</strong> <span class=\"mono\">{_h(_compact_json(finding.get('remediation_steps', []), 900))}</span></p>",
                    "<h3>Linked Evidence</h3>",
                    _html_table(["Origin", "Source", "Method", "Confidence", "Relevance"], evidence_rows) if evidence_rows else '<p class="muted">No linked evidence records were attached.</p>',
                    '</article>',
                ]
            )
        chunks.append("</section>")

    if "attack_paths" in sections:
        attack = payload.get("attack_paths", {})
        rows = [
            [
                path.get("risk_level"),
                _fmt_number(path.get("path_score"), 1),
                path.get("hop_count"),
                path.get("target_tier"),
                path.get("path_type"),
                path.get("explanation"),
            ]
            for path in attack.get("top_paths", [])
        ]
        chunks.extend(
            [
                '<section class="section">',
                "<h2>Attack Paths</h2>",
                f"<p>{_h(attack.get('total_paths', 0))} persisted exposure paths are available for this assessment.</p>",
                _html_table(["Risk", "Score", "Hops", "Tier", "Path Type", "Explanation"], rows),
                "</section>",
            ]
        )

    if "graph_posture" in sections:
        graph = payload.get("graph_posture", {})
        edge_rows = [[edge_type, count] for edge_type, count in (graph.get("edge_type_counts") or {}).items()]
        chunks.extend(
            [
                '<section class="section">',
                "<h2>Graph Posture</h2>",
                '<div class="two-col">',
                f'<div class="panel"><h3>Graph Scale</h3><p><strong>Nodes:</strong> {_h(graph.get("node_count", 0))}</p><p><strong>Edges:</strong> {_h(graph.get("edge_count", 0))}</p><p><strong>High-risk edges:</strong> {_h(graph.get("high_risk_edge_count", 0))}</p></div>',
                '<div class="panel"><h3>Relationship Concentration</h3>',
                _html_table(["Edge Type", "Count"], edge_rows),
                '</div>',
                '</div>',
                "</section>",
            ]
        )

    if "identity_inventory" in sections:
        identity = payload.get("identity_inventory", {})
        count_rows = [[entity_type, count] for entity_type, count in (identity.get("entity_counts") or {}).items()]
        tier_rows = [[item.get("entity_type"), item.get("label"), _fmt_bool(item.get("crown_jewel"))] for item in identity.get("tier0_examples", [])]
        chunks.extend(
            [
                '<section class="section">',
                "<h2>Identity Inventory</h2>",
                '<div class="two-col">',
                '<div class="panel"><h3>Entity Counts</h3>',
                _html_table(["Type", "Count"], count_rows),
                '</div>',
                f'<div class="panel"><h3>Privileged Summary</h3><p><strong>Tier-0:</strong> {_h(identity.get("tier0_entities", 0))}</p><p><strong>Crown jewels:</strong> {_h(identity.get("crown_jewels", 0))}</p><p><strong>Admin-count:</strong> {_h(identity.get("admin_count_entities", 0))}</p></div>',
                '</div>',
                '<h3>Tier-0 Examples</h3>',
                _html_table(["Type", "Label", "Crown Jewel"], tier_rows),
                "</section>",
            ]
        )

    if "pki_posture" in sections:
        pki = payload.get("pki_posture", {})
        rows = [[template.get("name"), template.get("ca_name"), ", ".join(template.get("esc_flags", [])) or "-", _fmt_bool(template.get("vulnerable"))] for template in pki.get("templates", [])]
        chunks.extend(
            [
                '<section class="section">',
                "<h2>PKI Posture</h2>",
                f"<p>{_h(pki.get('vulnerable_templates', 0))} vulnerable templates across {_h(pki.get('total_templates', 0))} templates.</p>",
                _html_table(["Template", "CA", "ESC Flags", "Vulnerable"], rows),
                "</section>",
            ]
        )

    if "trust_posture" in sections:
        trust = payload.get("trust_posture", {})
        rows = [[item.get("source"), item.get("target"), item.get("trust_type"), item.get("risk"), _fmt_bool(item.get("sid_filtering")), _fmt_bool(item.get("selective_auth"))] for item in trust.get("trusts", [])]
        chunks.extend(
            [
                '<section class="section">',
                "<h2>Trust Posture</h2>",
                f"<p>{_h(trust.get('total_trusts', 0))} trust objects, {_h(trust.get('sid_filtering_off', 0))} with SID filtering disabled.</p>",
                _html_table(["Source", "Target", "Type", "Risk", "SID Filtering", "Selective Auth"], rows),
                "</section>",
            ]
        )

    if "service_accounts" in sections:
        service = payload.get("service_account_posture", {})
        rows = [[item.get("risk"), item.get("sam_account_name"), item.get("entity_type"), _fmt_bool(item.get("kerberoastable")), _fmt_bool(item.get("asrep_roastable")), _fmt_bool(item.get("unconstrained_delegation")), item.get("password_age_days")] for item in service.get("accounts", [])]
        chunks.extend(
            [
                '<section class="section">',
                "<h2>Service Account Posture</h2>",
                f"<p>{_h(service.get('total', 0))} tracked service accounts, {_h(service.get('kerberoastable', 0))} Kerberoastable, {_h(service.get('asrep_roastable', 0))} AS-REP roastable.</p>",
                _html_table(["Risk", "Account", "Type", "Kerberoast", "AS-REP", "Unconstrained Delegation", "Pwd Age (d)"], rows),
                "</section>",
            ]
        )

    if "validation" in sections:
        validation = payload.get("validation_posture", {})
        rows = [[item.get("module_id"), item.get("status"), item.get("final_verdict"), item.get("execution_mode"), _fmt_bool(item.get("simulated")), item.get("origin"), item.get("created_at")] for item in validation.get("runs", [])]
        chunks.extend(
            [
                '<section class="section">',
                "<h2>Validation History</h2>",
                f"<p>{_h(validation.get('total_runs', 0))} validation runs are summarized here. Simulated runs remain explicitly labeled.</p>",
                _html_table(["Module", "Status", "Verdict", "Mode", "Simulated", "Origin", "Created"], rows),
                "</section>",
            ]
        )

    if "remediation_plan" in sections:
        remediation = payload.get("remediation_plan", {})
        rows = [[item.get("priority"), item.get("severity"), item.get("status"), _fmt_number(item.get("score"), 1), item.get("title"), item.get("estimated_effort")] for item in remediation.get("items", [])]
        chunks.extend(
            [
                '<section class="section">',
                "<h2>Remediation Workplan</h2>",
                f"<p>{_h(remediation.get('actionable_findings', 0))} actionable findings are prioritized for remediation.</p>",
                _html_table(["#", "Severity", "Status", "Score", "Finding", "Effort"], rows),
                "</section>",
            ]
        )

    if "evidence_appendix" in sections:
        appendix = payload.get("evidence_appendix", {})
        rows = [[item.get("origin"), item.get("source_type"), item.get("collection_method"), _fmt_number(item.get("confidence"), 2), _fmt_bool(item.get("is_corroborated")), _compact_json(item.get("raw_data_redacted"), 320)] for item in appendix.get("records", [])]
        chunks.extend(
            [
                '<section class="section">',
                "<h2>Evidence Appendix</h2>",
                f"<p>{_h(appendix.get('redaction_policy'), '')}</p>",
                _html_table(["Origin", "Source", "Method", "Confidence", "Corroborated", "Redacted Preview"], rows),
                "</section>",
            ]
        )

    if "execution_summary" in sections:
        execution = payload.get("execution_summary", {})
        status_rows = [[status, count] for status, count in (execution.get("status_counts") or {}).items()]
        loot_rows = [[loot_type, count] for loot_type, count in (execution.get("loot_item_counts_by_type") or {}).items()]
        chunks.extend(
            [
                '<section class="section">',
                "<h2>Execution Summary</h2>",
                f"<p>{_h(execution.get('redaction_notice'), '')}</p>",
                '<div class="two-col">',
                '<div class="panel"><h3>Chain Status</h3>',
                _html_table(["Status", "Chains"], status_rows),
                '</div>',
                '<div class="panel"><h3>Loot Counts by Type</h3>',
                _html_table(["Loot Type", "Items"], loot_rows),
                '</div>',
                '</div>',
                "</section>",
            ]
        )

    if "raw_context" in sections:
        raw = payload.get("raw_context", {})
        chunks.extend(
            [
                '<section class="section">',
                "<h2>Raw Context</h2>",
                '<div class="panel mono">',
                _h(_compact_json(raw, 4000)),
                '</div>',
                "</section>",
            ]
        )

    chunks.extend(
        [
            '<div class="footer-note">',
            f"Report engine: {_h(meta.get('generator'), 'AdByG0d Reporting Engine')} {_h(meta.get('generator_version'), '')}. {_h(meta.get('redaction_policy'), '')}",
            '</div>',
            "</main>",
            "</body>",
            "</html>",
        ]
    )
    return "".join(chunks)


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    body = ParagraphStyle(
        "Body",
        parent=base["BodyText"],
        fontName="Helvetica",
        fontSize=8.7,
        leading=11.5,
        textColor=_TEXT,
        spaceAfter=5,
    )
    small = ParagraphStyle(
        "Small",
        parent=body,
        fontSize=7.2,
        leading=9.2,
        textColor=_MUTED,
    )
    mono = ParagraphStyle(
        "Mono",
        parent=small,
        fontName="Courier",
        fontSize=6.7,
        leading=8.4,
        wordWrap="CJK",
    )
    title = ParagraphStyle(
        "ReportTitle",
        parent=base["Title"],
        fontName="Helvetica-Bold",
        fontSize=25,
        leading=29,
        alignment=TA_LEFT,
        textColor=colors.white,
        spaceAfter=10,
    )
    subtitle = ParagraphStyle(
        "ReportSubtitle",
        parent=body,
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#E0F2FE"),
        spaceAfter=6,
    )
    h1 = ParagraphStyle(
        "SectionHeading",
        parent=base["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=16,
        leading=20,
        textColor=_BRAND_DARK,
        spaceBefore=8,
        spaceAfter=10,
    )
    h2 = ParagraphStyle(
        "SubHeading",
        parent=base["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=11.5,
        leading=14,
        textColor=_TEXT,
        spaceBefore=8,
        spaceAfter=5,
    )
    finding = ParagraphStyle(
        "FindingHeading",
        parent=h2,
        fontSize=10.5,
        leading=13,
        textColor=_TEXT,
        spaceBefore=7,
        spaceAfter=4,
    )
    center = ParagraphStyle(
        "Center",
        parent=body,
        alignment=TA_CENTER,
    )
    return {
        "body": body,
        "small": small,
        "mono": mono,
        "title": title,
        "subtitle": subtitle,
        "h1": h1,
        "h2": h2,
        "finding": finding,
        "center": center,
    }



def _plain_p(value: Any, style: ParagraphStyle, fallback: str = "-") -> Paragraph:
    text = html_escape(_safe_text(value, fallback)).replace("\n", "<br/>")
    return Paragraph(text, style)


def _pdf_compaction_notice(compacted: dict[str, Any], styles: dict[str, ParagraphStyle]) -> Paragraph | None:
    if not compacted.get("is_compacted"):
        return None
    return _plain_p(compacted.get("disclosure"), styles["small"])


def _table(
    headers: list[str],
    rows: list[list[Any]],
    styles: dict[str, ParagraphStyle],
    *,
    col_widths: list[float] | None = None,
    small: bool = True,
) -> LongTable:
    cell_style = styles["small"] if small else styles["body"]
    data: list[list[Any]] = [[_plain_p(header, styles["small"]) for header in headers]]
    for row in rows:
        data.append([_plain_p(cell, cell_style) for cell in row])
    table = LongTable(data, colWidths=col_widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), _BRAND_DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.25, _LINE),
                ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _SOFT]),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _kv_table(rows: list[tuple[str, Any]], styles: dict[str, ParagraphStyle], *, widths: tuple[float, float] | None = None) -> Table:
    data = [[_plain_p(label, styles["small"]), _plain_p(value, styles["body"])] for label, value in rows]
    table = Table(data, colWidths=list(widths) if widths else None, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), _PANEL),
                ("TEXTCOLOR", (0, 0), (0, -1), _BRAND_DARK),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.25, _LINE),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def _metric_cards(metrics: list[tuple[str, Any, Any]], styles: dict[str, ParagraphStyle], total_width: float) -> Table:
    cells = []
    for label, value, hint in metrics:
        cells.append(
            Table(
                [
                    [_plain_p(label, styles["small"])],
                    [_plain_p(value, ParagraphStyle("MetricValue", parent=styles["body"], fontSize=13, leading=16, textColor=_BRAND_DARK, fontName="Helvetica-Bold"))],
                    [_plain_p(hint, styles["small"])],
                ],
                colWidths=[(total_width - 18) / max(1, len(metrics))],
            )
        )
    table = Table([cells], colWidths=[(total_width - 18) / max(1, len(metrics))] * len(metrics), hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), _PANEL),
                ("BOX", (0, 0), (-1, -1), 0.35, _LINE),
                ("INNERPADDING", (0, 0), (-1, -1), 0),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    return table




class _ReportDocTemplate(SimpleDocTemplate):
    """SimpleDocTemplate with TOC/bookmark notifications for section headings."""

    def afterFlowable(self, flowable: Any) -> None:  # noqa: N802 - ReportLab callback name
        if not isinstance(flowable, Paragraph):
            return
        if getattr(flowable.style, "name", "") != "SectionHeading":
            return
        title = flowable.getPlainText()
        slug = "".join(char.lower() if char.isalnum() else "-" for char in title).strip("-")
        key = f"section-{slug[:72] or 'report'}"
        try:
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(title, key, level=0, closed=False)
        except Exception:
            key = None
        if key:
            self.notify("TOCEntry", (0, title, self.page, key))
        else:
            self.notify("TOCEntry", (0, title, self.page))


def _pdf_bar_chart(rows: Iterable[tuple[Any, Any]], total_width: float, *, max_rows: int = 8) -> Drawing:
    normalized = [(_safe_text(label), max(0.0, float(value or 0))) for label, value in rows][:max_rows]
    if not normalized:
        normalized = [("No data recorded", 0.0)]
    max_value = max((value for _label, value in normalized), default=0.0) or 1.0
    height = 18 + len(normalized) * 18
    drawing = Drawing(total_width, height)
    label_width = min(190, total_width * 0.42)
    track_x = label_width + 6
    track_width = max(80, total_width - track_x - 40)
    for index, (label, value) in enumerate(normalized):
        y = height - 17 - index * 18
        drawing.add(String(0, y + 2, label[:46], fontName="Helvetica", fontSize=6.8, fillColor=_TEXT))
        drawing.add(Rect(track_x, y, track_width, 8, fillColor=_PANEL, strokeColor=_LINE, strokeWidth=0.2, rx=3, ry=3))
        fill_width = max(0.0, track_width * min(1.0, value / max_value))
        drawing.add(Rect(track_x, y, fill_width, 8, fillColor=_BRAND, strokeColor=None, rx=3, ry=3))
        drawing.add(String(track_x + track_width + 6, y + 2, _fmt_number(value, 0), fontName="Helvetica-Bold", fontSize=6.8, fillColor=_MUTED))
    return drawing


def _section(story: list[Any], title: str, styles: dict[str, ParagraphStyle]) -> None:
    story.append(Spacer(1, 9))
    story.append(_plain_p(title, styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=0.8, color=_BRAND, spaceBefore=0, spaceAfter=8))


def _draw_first_page(canvas, doc, payload: dict[str, Any]) -> None:
    width, height = A4
    canvas.saveState()
    canvas.setFillColor(_BRAND_DARK)
    canvas.rect(0, 0, width, height, stroke=0, fill=1)
    canvas.setFillColor(_BRAND)
    canvas.rect(0, height - 12, width, 12, stroke=0, fill=1)
    canvas.restoreState()


def _draw_later_pages(canvas, doc, payload: dict[str, Any]) -> None:
    width, height = A4
    assessment = payload.get("assessment", {})
    canvas.saveState()
    canvas.setStrokeColor(_LINE)
    canvas.setLineWidth(0.35)
    canvas.line(42, height - 34, width - 42, height - 34)
    canvas.setFillColor(_MUTED)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(42, height - 26, f"AdByG0d Report - {_safe_text(assessment.get('domain'), 'assessment')}")
    canvas.drawRightString(width - 42, 26, f"Page {doc.page}")
    canvas.drawString(42, 26, "Provenance-safe assessment export")
    canvas.restoreState()


def render_pdf_report(payload: dict[str, Any]) -> bytes:
    sections = _section_ids(payload)
    styles = _styles()
    assessment = payload.get("assessment", {})
    exposure = payload.get("exposure", {})
    risk = payload.get("risk_analysis", {})
    coverage = payload.get("coverage_assurance", {})
    quality = payload.get("data_quality", {})
    themes = payload.get("risk_theme_summary", {})
    action_board = payload.get("priority_action_board", {})
    meta = payload.get("report_meta", {})

    buffer = io.BytesIO()
    doc = _ReportDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=42,
        rightMargin=42,
        topMargin=48,
        bottomMargin=42,
        title=f"AdByG0d Report - {_safe_text(assessment.get('domain'), 'assessment')}",
        author="White0xdi3",
        subject="Active Directory identity exposure assessment report",
    )
    total_width = A4[0] - doc.leftMargin - doc.rightMargin
    story: list[Any] = []
    section_number = 0

    def _numbered_section(title: str) -> int:
        nonlocal section_number
        section_number += 1
        _section(story, f"{section_number}. {title}", styles)
        return section_number

    story.append(Spacer(1, 58))
    story.append(_plain_p("AdByG0d Assessment Report", styles["subtitle"]))
    story.append(_plain_p(assessment.get("name") or "Assessment", styles["title"]))
    story.append(_plain_p(f"Domain: {_safe_text(assessment.get('domain'), 'Unknown domain')}", styles["subtitle"]))
    story.append(_plain_p(f"Generated: {_safe_text(meta.get('generated_at'), datetime.now(timezone.utc).isoformat())}", styles["subtitle"]))
    story.append(Spacer(1, 18))
    cover_table = _kv_table(
        [
            ("Status", assessment.get("status") or "UNKNOWN"),
            ("Collection Mode", assessment.get("collection_mode") or "UNKNOWN"),
            ("Exposure Score", f"{_fmt_number(assessment.get('exposure_score'), 1)} ({risk.get('rating', 'UNKNOWN')})"),
            ("Findings", exposure.get("total_findings", 0)),
            ("Finding Coverage", coverage.get("integrity_status") or "UNKNOWN"),
            ("Report Readiness", f"{quality.get('readiness_grade', '-')} ({_fmt_number(quality.get('readiness_score', 0), 1)}/100)"),
            ("Modules Run", ", ".join(assessment.get("modules_run") or []) or "Not recorded"),
        ],
        styles,
        widths=(1.55 * inch, total_width - 1.55 * inch),
    )
    cover_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (1, 0), (-1, -1), colors.white),
                ("TEXTCOLOR", (1, 0), (-1, -1), _TEXT),
                ("BOX", (0, 0), (-1, -1), 0.45, colors.HexColor("#E2E8F0")),
            ]
        )
    )
    story.append(cover_table)
    story.append(Spacer(1, 18))
    story.append(_plain_p(meta.get("provenance_policy") or "Provenance labeling is preserved throughout this report.", styles["subtitle"]))
    story.append(_plain_p(meta.get("redaction_policy") or "Sensitive values are redacted in exported evidence previews.", styles["subtitle"]))
    story.append(PageBreak())
    toc = TableOfContents()
    toc.levelStyles = [
        ParagraphStyle(
            "TOCLevel1",
            parent=styles["body"],
            fontSize=9.2,
            leading=13,
            leftIndent=0,
            firstLineIndent=0,
            textColor=_TEXT,
            spaceBefore=3,
            spaceAfter=3,
        )
    ]
    story.append(_plain_p("Table of Contents", styles["h2"]))
    story.append(_plain_p("Sections below are generated from the selected report dossier configuration.", styles["body"]))
    story.append(toc)
    story.append(PageBreak())

    if "exec_summary" in sections:
        _numbered_section("Executive Summary")
        story.append(
            _plain_p(
                f"This assessment recorded {_fmt_number(exposure.get('total_findings', 0))} findings. The graph-backed exposure score is {_fmt_number(assessment.get('exposure_score'), 1)} with a {risk.get('rating', 'UNKNOWN')} rating. Coverage integrity is {coverage.get('integrity_status', 'UNKNOWN')} and report readiness is {quality.get('readiness_grade', '-')} ({_fmt_number(quality.get('readiness_score', 0), 1)}/100). The summary below prioritizes high-signal issues while preserving provenance labels.",
                styles["body"],
            )
        )
        story.append(
            _metric_cards(
                [
                    ("Exposure Score", _fmt_number(assessment.get("exposure_score"), 1), risk.get("rating", "UNKNOWN")),
                    ("Findings", _fmt_number(exposure.get("total_findings", 0)), "Total"),
                    ("Coverage", coverage.get("integrity_status", "UNKNOWN"), "Payload ledger"),
                    ("Readiness", quality.get("readiness_grade", "-"), f"{_fmt_number(quality.get('readiness_score', 0), 1)}/100"),
                ],
                styles,
                total_width,
            )
        )
        story.append(Spacer(1, 9))
        rows = [
            [
                item.get("severity"),
                _fmt_number(item.get("composite_score"), 1),
                item.get("title"),
                item.get("module"),
                item.get("origin"),
            ]
            for item in payload.get("top_findings", [])[:12]
        ]
        story.append(_table(["Severity", "Score", "Finding", "Module", "Origin"], rows, styles, col_widths=[0.67 * inch, 0.52 * inch, 2.7 * inch, 1.08 * inch, 0.8 * inch]))

    if "scope_methodology" in sections:
        _numbered_section("Scope and Methodology")
        story.append(
            _kv_table(
                [
                    ("Assessment ID", assessment.get("id")),
                    ("Domain", assessment.get("domain")),
                    ("Domain Controller", assessment.get("dc_ip") or "Not recorded"),
                    ("Created", assessment.get("created_at") or "Not recorded"),
                    ("Started", assessment.get("started_at") or "Not recorded"),
                    ("Completed", assessment.get("completed_at") or "Not recorded"),
                    ("Modules", ", ".join(assessment.get("modules_run") or []) or "Not recorded"),
                ],
                styles,
                widths=(1.65 * inch, total_width - 1.65 * inch),
            )
        )
        story.append(Spacer(1, 8))
        story.append(_plain_p(meta.get("provenance_policy") or "", styles["body"]))
        story.append(_plain_p(meta.get("redaction_policy") or "", styles["body"]))
        story.append(_plain_p("PDF summarization policy: large raw inventories are summarized for readability with displayed, total, and omitted row counts. Complete machine-readable inventories remain available through JSON/CSV exports, the API, and the assessment UI. Finding registers and detailed finding dossiers remain complete.", styles["small"]))

    if "risk_posture" in sections:
        _numbered_section("Risk Posture")
        severity_rows = [[severity, count] for severity, count in (exposure.get("severity_counts") or {}).items()]
        origin_rows = [[origin, count] for origin, count in (exposure.get("origin_counts") or {}).items()]
        module_rows_raw = [[item.get("module"), item.get("total")] for item in payload.get("module_breakdown", [])]
        module_compact = compact_rows_for_pdf(
            "module_breakdown",
            module_rows_raw,
            sort_key=lambda row: (-int(row[1] or 0), str(row[0] or "").lower()),
        )
        module_rows = module_compact["rows"]
        story.append(_plain_p("Finding severity distribution", styles["h2"]))
        story.append(_table(["Severity", "Count"], severity_rows, styles, col_widths=[1.7 * inch, 1.0 * inch]))
        story.append(Spacer(1, 6))
        story.append(_pdf_bar_chart([(row[0], row[1]) for row in severity_rows], total_width))
        story.append(Spacer(1, 8))
        story.append(_plain_p("Finding provenance distribution", styles["h2"]))
        story.append(_table(["Origin", "Count"], origin_rows, styles, col_widths=[1.7 * inch, 1.0 * inch]))
        story.append(Spacer(1, 8))
        story.append(_plain_p("Module breakdown", styles["h2"]))
        notice = _pdf_compaction_notice(module_compact, styles)
        if notice:
            story.append(notice)
        story.append(_table(["Module", "Findings"], module_rows, styles, col_widths=[3.4 * inch, 1.0 * inch]))
        story.append(Spacer(1, 6))
        story.append(_pdf_bar_chart([(row[0], row[1]) for row in module_rows], total_width))

    if "coverage_assurance" in sections:
        _numbered_section("Finding Coverage Assurance")
        reconciliation = coverage.get("finding_count_reconciliation", {})
        story.append(_plain_p(coverage.get("coverage_statement") or "Coverage reconciliation was not recorded.", styles["body"]))
        story.append(
            _metric_cards(
                [
                    ("Stored", _fmt_number(reconciliation.get("stored_findings", 0)), "Findings"),
                    ("Register", _fmt_number(reconciliation.get("finding_register_rows", 0)), "Rows"),
                    ("Details", _fmt_number(reconciliation.get("detailed_finding_rows", 0)), "Rows"),
                    ("Gaps", _fmt_number(reconciliation.get("unreported_payload_rows", 0)), coverage.get("integrity_status", "UNKNOWN")),
                ],
                styles,
                total_width,
            )
        )
        story.append(Spacer(1, 8))
        coverage_rows_raw = [
            [item.get("module"), item.get("findings"), item.get("critical_high"), item.get("evidence_linked"), item.get("remediation_ready")]
            for item in coverage.get("module_coverage", [])
        ]
        coverage_compact = compact_rows_for_pdf("coverage_assurance", coverage_rows_raw, sort_key=lambda row: (-int(row[2] or 0), -int(row[1] or 0), str(row[0] or "").lower()))
        notice = _pdf_compaction_notice(coverage_compact, styles)
        if notice:
            story.append(notice)
        coverage_rows = coverage_compact["rows"]
        story.append(_table(["Module", "Findings", "Crit/High", "Evidence", "Remediation"], coverage_rows, styles, col_widths=[2.15 * inch, 0.58 * inch, 0.62 * inch, 0.62 * inch, 0.78 * inch]))
        story.append(Spacer(1, 6))
        story.append(_plain_p(f"Missing linked evidence: {len(coverage.get('findings_without_linked_evidence', []))}; missing remediation: {len(coverage.get('findings_without_remediation', []))}; modules run without findings: {', '.join(coverage.get('modules_run_without_findings', [])) or 'None'}.", styles["small"]))

    if "risk_themes" in sections:
        _numbered_section("Risk Themes")
        story.append(_plain_p(themes.get("classification_policy") or "Risk themes organize findings for reporting.", styles["body"]))
        theme_rows_raw = [
            [item.get("theme"), item.get("finding_count"), item.get("critical_high_count"), _fmt_number(item.get("max_score"), 1), ", ".join(finding.get("title") or "" for finding in item.get("top_findings", [])[:3]) or "-"]
            for item in themes.get("themes", [])
        ]
        theme_compact = compact_rows_for_pdf("risk_themes", theme_rows_raw, sort_key=lambda row: (-int(row[2] or 0), -float(row[3] or 0), str(row[0] or "").lower()))
        story.append(_pdf_bar_chart([(row[0], row[1]) for row in theme_compact["rows"]], total_width))
        story.append(Spacer(1, 8))
        notice = _pdf_compaction_notice(theme_compact, styles)
        if notice:
            story.append(notice)
        theme_rows = theme_compact["rows"]
        story.append(_table(["Theme", "Findings", "Crit/High", "Max", "Representative Findings"], theme_rows, styles, col_widths=[1.55 * inch, 0.52 * inch, 0.62 * inch, 0.45 * inch, 2.72 * inch]))

    if "priority_action_board" in sections:
        _numbered_section("Priority Action Board")
        story.append(_plain_p(action_board.get("planning_note") or "Actions are ranked from current finding severity and score.", styles["body"]))
        story.append(
            _metric_cards(
                [
                    ("Immediate", _fmt_number(action_board.get("immediate_actions", 0)), "0-7 days"),
                    ("Near-term", _fmt_number(action_board.get("near_term_actions", 0)), "8-30 days"),
                    ("Planned", _fmt_number(action_board.get("planned_actions", 0)), "31-90 days"),
                    ("Total", _fmt_number(action_board.get("total_actions", 0)), "Actions"),
                ],
                styles,
                total_width,
            )
        )
        story.append(Spacer(1, 8))
        board_rows = [
            [item.get("wave"), item.get("priority"), item.get("severity"), _fmt_number(item.get("score"), 1), item.get("title"), item.get("estimated_effort")]
            for item in action_board.get("items", [])[:36]
        ]
        story.append(_table(["Wave", "#", "Severity", "Score", "Finding", "Effort"], board_rows, styles, col_widths=[1.18 * inch, 0.32 * inch, 0.58 * inch, 0.45 * inch, 3.05 * inch, 0.7 * inch]))

    if "data_quality" in sections:
        _numbered_section("Data Quality and Confidence")
        story.append(_plain_p(f"Report readiness grade {quality.get('readiness_grade', '-')} ({_fmt_number(quality.get('readiness_score', 0), 1)}/100). {quality.get('scoring_note', '')}", styles["body"]))
        story.append(
            _metric_cards(
                [
                    ("Grade", quality.get("readiness_grade", "-"), "Readiness"),
                    ("Evidence", f"{_fmt_number(quality.get('finding_evidence_linkage_pct', 0), 1)}%", "Linked"),
                    ("Confidence", _fmt_number(quality.get("average_finding_confidence", 0), 2), "Average"),
                    ("Corroborated", f"{_fmt_number(quality.get('corroborated_evidence_pct', 0), 1)}%", "Evidence"),
                ],
                styles,
                total_width,
            )
        )
        story.append(Spacer(1, 8))
        flags = quality.get("quality_flags", {})
        quality_rows = [
            ["Missing linked evidence", flags.get("missing_evidence", 0)],
            ["Missing description", flags.get("missing_description", 0)],
            ["Missing root cause", flags.get("missing_root_cause", 0)],
            ["Missing remediation", flags.get("missing_remediation", 0)],
        ]
        story.append(_table(["Quality Flag", "Count"], quality_rows, styles, col_widths=[2.6 * inch, 0.8 * inch]))

    if "finding_register" in sections:
        _numbered_section("Complete Finding Register")
        rows = [
            [
                finding.get("severity"),
                _fmt_number(finding.get("composite_score"), 1),
                finding.get("status"),
                finding.get("origin"),
                finding.get("module"),
                finding.get("title"),
                finding.get("affected_count"),
                finding.get("evidence_count"),
            ]
            for finding in payload.get("findings_register", [])
        ]
        story.append(_table(["Severity", "Score", "Status", "Origin", "Module", "Title", "Affected", "Evidence"], rows, styles, col_widths=[0.58 * inch, 0.45 * inch, 0.75 * inch, 0.68 * inch, 0.78 * inch, 2.25 * inch, 0.48 * inch, 0.48 * inch]))

    if "detailed_findings" in sections:
        detailed_section_number = _numbered_section("Detailed Findings")
        for index, finding in enumerate(payload.get("finding_details", []), start=1):
            block: list[Any] = []
            block.append(_plain_p(f"{detailed_section_number}.{index} {finding.get('title', 'Untitled finding')}", styles["finding"]))
            block.append(
                _kv_table(
                    [
                        ("Severity", finding.get("severity")),
                        ("Score", _fmt_number(finding.get("composite_score"), 1)),
                        ("Status", finding.get("status")),
                        ("Origin", finding.get("origin")),
                        ("Themes", ", ".join(finding.get("risk_themes", []) or []) or "General Exposure / Needs Classification"),
                        ("Module", finding.get("module")),
                        ("Affected", finding.get("affected_count")),
                        ("Evidence", finding.get("evidence_count")),
                    ],
                    styles,
                    widths=(1.35 * inch, total_width - 1.35 * inch),
                )
            )
            block.append(_plain_p(f"Description: {_safe_text(finding.get('description'), 'No description recorded.')}", styles["body"]))
            block.append(_plain_p(f"Root cause: {_safe_text(finding.get('root_cause'), 'Not recorded.')}", styles["body"]))
            block.append(_plain_p(f"Remediation: {_safe_text(finding.get('remediation'), 'No remediation text recorded.')}", styles["body"]))
            block.append(_plain_p(f"MITRE ATT&CK: {_compact_json(finding.get('mitre_attack_ids', []), 500)}", styles["mono"]))
            block.append(_plain_p(f"CVEs: {_compact_json(finding.get('cve_ids', []), 500)}", styles["mono"]))
            block.append(_plain_p(f"Attack path: {_compact_json(finding.get('attack_path', []), 900)}", styles["mono"]))
            block.append(_plain_p(f"Affected objects: {_compact_json(finding.get('affected_objects', []), 900)}", styles["mono"]))
            block.append(_plain_p(f"Remediation steps: {_compact_json(finding.get('remediation_steps', []), 900)}", styles["mono"]))
            evidence_rows = [
                [
                    item.get("origin"),
                    item.get("source_type"),
                    item.get("collection_method"),
                    _fmt_number(item.get("confidence"), 2),
                    item.get("relevance") or "-",
                ]
                for item in finding.get("evidence", [])[:20]
            ]
            if evidence_rows:
                block.append(_plain_p("Linked evidence", styles["h2"]))
                block.append(_table(["Origin", "Source", "Method", "Confidence", "Relevance"], evidence_rows, styles, col_widths=[0.68 * inch, 0.72 * inch, 1.45 * inch, 0.7 * inch, 2.1 * inch]))
            if len(block) >= 4:
                story.append(KeepTogether(block[:4]))
                story.extend(block[4:])
            else:
                story.extend(block)
            story.append(Spacer(1, 8))

    if "attack_paths" in sections:
        _numbered_section("Attack Paths")
        attack = payload.get("attack_paths", {})
        story.append(_plain_p(f"Persisted attack-path records: {_fmt_number(attack.get('total_paths', 0))}. Risk levels are computed from persisted path scores.", styles["body"]))
        rows = [
            [
                path.get("risk_level"),
                _fmt_number(path.get("path_score"), 1),
                path.get("hop_count"),
                path.get("target_tier"),
                path.get("path_type"),
                path.get("explanation"),
            ]
            for path in attack.get("top_paths", [])
        ]
        story.append(_table(["Risk", "Score", "Hops", "Tier", "Path Type", "Explanation"], rows, styles, col_widths=[0.62 * inch, 0.52 * inch, 0.42 * inch, 0.42 * inch, 1.0 * inch, 3.15 * inch]))

    if "graph_posture" in sections:
        _numbered_section("Graph Posture")
        graph = payload.get("graph_posture", {})
        story.append(
            _metric_cards(
                [
                    ("Nodes", _fmt_number(graph.get("node_count", 0)), "Entities"),
                    ("Edges", _fmt_number(graph.get("edge_count", 0)), "Relationships"),
                    ("High Risk", _fmt_number(graph.get("high_risk_edge_count", 0)), "Weighted >= 0.8"),
                    ("Avg Weight", _fmt_number(graph.get("average_edge_risk_weight", 0), 2), "Edge risk"),
                ],
                styles,
                total_width,
            )
        )
        story.append(Spacer(1, 8))
        edge_rows_raw = [[edge_type, count] for edge_type, count in (graph.get("edge_type_counts") or {}).items()]
        edge_compact = compact_rows_for_pdf("graph_edge_types", edge_rows_raw, sort_key=lambda row: (-int(row[1] or 0), str(row[0] or "").lower()))
        notice = _pdf_compaction_notice(edge_compact, styles)
        if notice:
            story.append(notice)
        edge_rows = edge_compact["rows"]
        story.append(_table(["Edge Type", "Count"], edge_rows, styles, col_widths=[2.5 * inch, 1.0 * inch]))

    if "identity_inventory" in sections:
        _numbered_section("Identity Inventory")
        identity = payload.get("identity_inventory", {})
        story.append(
            _metric_cards(
                [
                    ("Entities", _fmt_number(identity.get("total_entities", 0)), "Total"),
                    ("Tier-0", _fmt_number(identity.get("tier0_entities", 0)), "Privileged"),
                    ("Crown Jewels", _fmt_number(identity.get("crown_jewels", 0)), "Sensitive"),
                    ("Admin Count", _fmt_number(identity.get("admin_count_entities", 0)), "Protected objects"),
                ],
                styles,
                total_width,
            )
        )
        story.append(Spacer(1, 8))
        count_rows = [[entity_type, count] for entity_type, count in (identity.get("entity_counts") or {}).items()]
        story.append(_table(["Entity Type", "Count"], count_rows, styles, col_widths=[2.5 * inch, 1.0 * inch]))
        tier_rows = [[item.get("entity_type"), item.get("label"), _fmt_bool(item.get("crown_jewel"))] for item in identity.get("tier0_examples", [])]
        if tier_rows:
            story.append(Spacer(1, 8))
            story.append(_plain_p("Tier-0 examples", styles["h2"]))
            story.append(_table(["Type", "Label", "Crown Jewel"], tier_rows, styles, col_widths=[1.1 * inch, 3.4 * inch, 1.0 * inch]))

    if "pki_posture" in sections:
        _numbered_section("PKI Posture")
        pki = payload.get("pki_posture", {})
        story.append(_plain_p(f"Templates: {_fmt_number(pki.get('total_templates', 0))}; vulnerable templates: {_fmt_number(pki.get('vulnerable_templates', 0))}.", styles["body"]))
        pki_counts = [
            ["ESC1", pki.get("esc1_count", 0)],
            ["ESC2", pki.get("esc2_count", 0)],
            ["ESC3", pki.get("esc3_count", 0)],
            ["ESC4", pki.get("esc4_count", 0)],
        ]
        story.append(_table(["ESC Signal", "Templates"], pki_counts, styles, col_widths=[1.4 * inch, 1.0 * inch]))
        story.append(Spacer(1, 8))
        rows_raw = [[item.get("name"), item.get("ca_name"), ", ".join(item.get("esc_flags", [])) or "-", _fmt_bool(item.get("vulnerable"))] for item in pki.get("templates", [])]
        pki_compact = compact_rows_for_pdf("pki_posture", rows_raw, sort_key=_pki_sort_key)
        notice = _pdf_compaction_notice(pki_compact, styles)
        if notice:
            story.append(notice)
        rows = pki_compact["rows"]
        story.append(_table(["Template", "CA", "ESC Flags", "Vulnerable"], rows, styles, col_widths=[2.2 * inch, 1.6 * inch, 1.15 * inch, 0.85 * inch]))

    if "trust_posture" in sections:
        _numbered_section("Trust Posture")
        trust = payload.get("trust_posture", {})
        story.append(_plain_p(f"Trust objects: {_fmt_number(trust.get('total_trusts', 0))}; SID filtering disabled: {_fmt_number(trust.get('sid_filtering_off', 0))}.", styles["body"]))
        trust_counts = [
            ["SID filtering disabled", trust.get("sid_filtering_off", 0)],
            ["Selective authentication disabled", trust.get("selective_auth_off", 0)],
            ["Forest trusts", trust.get("forest_trusts", 0)],
            ["Critical risk", trust.get("critical_risk", 0)],
            ["High risk", trust.get("high_risk", 0)],
        ]
        story.append(_table(["Trust Signal", "Count"], trust_counts, styles, col_widths=[2.7 * inch, 1.0 * inch]))
        story.append(Spacer(1, 8))
        rows_raw = [[item.get("source"), item.get("target"), item.get("trust_type"), item.get("risk"), _fmt_bool(item.get("sid_filtering")), _fmt_bool(item.get("selective_auth"))] for item in trust.get("trusts", [])]
        trust_compact = compact_rows_for_pdf("trust_posture", rows_raw, sort_key=_trust_sort_key)
        notice = _pdf_compaction_notice(trust_compact, styles)
        if notice:
            story.append(notice)
        rows = trust_compact["rows"]
        story.append(_table(["Source", "Target", "Type", "Risk", "SID Filtering", "Selective Auth"], rows, styles, col_widths=[1.15 * inch, 1.35 * inch, 0.92 * inch, 0.6 * inch, 0.82 * inch, 0.82 * inch]))

    if "service_accounts" in sections:
        _numbered_section("Service Account Posture")
        service = payload.get("service_account_posture", {})
        story.append(_plain_p(f"Tracked service accounts: {_fmt_number(service.get('total', 0))}; Kerberoastable: {_fmt_number(service.get('kerberoastable', 0))}; AS-REP roastable: {_fmt_number(service.get('asrep_roastable', 0))}.", styles["body"]))
        risk_rows = [[risk, count] for risk, count in (service.get("by_risk") or {}).items()]
        signal_rows = [
            ["Privileged/admin service accounts", service.get("privileged", 0)],
            ["Kerberoastable", service.get("kerberoastable", 0)],
            ["AS-REP roastable", service.get("asrep_roastable", 0)],
            ["Unconstrained delegation", service.get("unconstrained_delegation", 0)],
            ["Stale password", service.get("stale_password", 0)],
        ]
        story.append(_table(["Service Account Signal", "Count"], signal_rows, styles, col_widths=[2.9 * inch, 1.0 * inch]))
        story.append(Spacer(1, 8))
        story.append(_table(["Risk", "Accounts"], risk_rows, styles, col_widths=[1.4 * inch, 1.0 * inch]))
        story.append(Spacer(1, 8))
        rows_raw = [[item.get("risk"), item.get("sam_account_name"), item.get("entity_type"), _fmt_bool(item.get("kerberoastable")), _fmt_bool(item.get("asrep_roastable")), _fmt_bool(item.get("unconstrained_delegation")), item.get("password_age_days")] for item in service.get("accounts", [])]
        service_compact = compact_rows_for_pdf("service_accounts", rows_raw, sort_key=_service_account_sort_key)
        notice = _pdf_compaction_notice(service_compact, styles)
        if notice:
            story.append(notice)
        rows = service_compact["rows"]
        story.append(_table(["Risk", "Account", "Type", "Kerberoast", "AS-REP", "Unconstrained", "Pwd Age"], rows, styles, col_widths=[0.62 * inch, 1.42 * inch, 0.85 * inch, 0.72 * inch, 0.68 * inch, 0.88 * inch, 0.62 * inch]))

    if "validation" in sections:
        _numbered_section("Validation History")
        validation = payload.get("validation_posture", {})
        story.append(_plain_p(f"Validation runs: {_fmt_number(validation.get('total_runs', 0))}. Simulated runs remain explicitly labeled.", styles["body"]))
        rows_raw = [[item.get("module_id"), item.get("status"), item.get("final_verdict"), item.get("execution_mode"), _fmt_bool(item.get("simulated")), item.get("origin"), item.get("created_at")] for item in validation.get("runs", [])]
        validation_compact = compact_rows_for_pdf("validation", rows_raw)
        notice = _pdf_compaction_notice(validation_compact, styles)
        if notice:
            story.append(notice)
        rows = validation_compact["rows"]
        story.append(_table(["Module", "Status", "Verdict", "Mode", "Simulated", "Origin", "Created"], rows, styles, col_widths=[0.9 * inch, 0.72 * inch, 0.92 * inch, 1.02 * inch, 0.68 * inch, 0.78 * inch, 1.0 * inch]))

    if "remediation_plan" in sections:
        _numbered_section("Remediation Workplan")
        remediation = payload.get("remediation_plan", {})
        story.append(_plain_p(f"Actionable findings prioritized: {_fmt_number(remediation.get('actionable_findings', 0))}.", styles["body"]))
        rows = [[item.get("priority"), item.get("severity"), item.get("status"), _fmt_number(item.get("score"), 1), item.get("title"), item.get("estimated_effort")] for item in remediation.get("items", [])]
        story.append(_table(["#", "Severity", "Status", "Score", "Finding", "Effort"], rows, styles, col_widths=[0.35 * inch, 0.65 * inch, 0.75 * inch, 0.5 * inch, 3.15 * inch, 0.8 * inch]))

    if "evidence_appendix" in sections:
        _numbered_section("Evidence Appendix")
        appendix = payload.get("evidence_appendix", {})
        story.append(_plain_p(appendix.get("redaction_policy") or "Evidence previews are redacted.", styles["body"]))
        rows_raw = [[item.get("origin"), item.get("source_type"), item.get("collection_method"), _fmt_number(item.get("confidence"), 2), _fmt_bool(item.get("is_corroborated")), _compact_json(item.get("raw_data_redacted"), 260)] for item in appendix.get("records", [])]
        evidence_compact = compact_rows_for_pdf("evidence_appendix", rows_raw, sort_key=_evidence_sort_key)
        notice = _pdf_compaction_notice(evidence_compact, styles)
        if notice:
            story.append(notice)
        rows = evidence_compact["rows"]
        story.append(_table(["Origin", "Source", "Method", "Confidence", "Corroborated", "Redacted Preview"], rows, styles, col_widths=[0.65 * inch, 0.72 * inch, 1.12 * inch, 0.7 * inch, 0.8 * inch, 2.32 * inch]))

    if "execution_summary" in sections:
        _numbered_section("Execution Summary")
        execution = payload.get("execution_summary", {})
        story.append(_plain_p(execution.get("redaction_notice") or "Operational values omitted.", styles["body"]))
        status_rows = [[status, count] for status, count in (execution.get("status_counts") or {}).items()]
        loot_rows = [[loot_type, count] for loot_type, count in (execution.get("loot_item_counts_by_type") or {}).items()]
        story.append(_plain_p("Chain status", styles["h2"]))
        story.append(_table(["Status", "Chains"], status_rows, styles, col_widths=[2.0 * inch, 1.0 * inch]))
        story.append(Spacer(1, 8))
        story.append(_plain_p("Loot counts by type", styles["h2"]))
        story.append(_table(["Loot Type", "Items"], loot_rows, styles, col_widths=[2.5 * inch, 1.0 * inch]))

    if "raw_context" in sections:
        _numbered_section("Raw Context")
        story.append(_plain_p(_compact_json(payload.get("raw_context", {}), 6000), styles["mono"]))

    story.append(Spacer(1, 18))
    story.append(HRFlowable(width="100%", thickness=0.5, color=_LINE, spaceBefore=4, spaceAfter=8))
    story.append(_plain_p(f"Report engine: {meta.get('generator', 'AdByG0d Reporting Engine')} {meta.get('generator_version', '')}. {meta.get('redaction_policy', '')}", styles["small"]))

    doc.multiBuild(story, onFirstPage=lambda canvas, document: _draw_first_page(canvas, document, payload), onLaterPages=lambda canvas, document: _draw_later_pages(canvas, document, payload))
    return buffer.getvalue()
