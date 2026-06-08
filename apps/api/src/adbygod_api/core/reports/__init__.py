"""Assessment reporting engine.

This package owns the backend report payload, HTML rendering, and PDF rendering
used by the Reports API.  It is intentionally server-side so the web UI and
external API clients receive the same provenance-safe report semantics.
"""

from .report_builder import (
    DEFAULT_REPORT_SECTIONS,
    REPORT_SECTION_CATALOG,
    build_report_payload,
    build_report_preview,
    normalize_report_sections,
)
from .renderers import render_csv_report, render_html_report, render_pdf_report

__all__ = [
    "DEFAULT_REPORT_SECTIONS",
    "REPORT_SECTION_CATALOG",
    "build_report_payload",
    "build_report_preview",
    "normalize_report_sections",
    "render_csv_report",
    "render_html_report",
    "render_pdf_report",
]
