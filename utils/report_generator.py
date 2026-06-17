"""
utils/report_generator.py
Project : ProWin — Windows Service & Process Monitoring Agent
"""

import os
import json
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from utils.helpers import load_config

_CFG         = load_config()
_REPORTS_DIR = os.path.join(
    os.path.dirname(__file__), "..", _CFG.get("reports_path", "reports/")
)
os.makedirs(_REPORTS_DIR, exist_ok=True)

# Colour map for severity columns in the PDF report
_PDF_LEVEL_COLORS = {
    "CRITICAL": colors.HexColor("#dc3545"),
    "HIGH":     colors.HexColor("#fd7e14"),
    "MEDIUM":   colors.HexColor("#ffc107"),
    "LOW":      colors.HexColor("#17a2b8"),
    "INFO":     colors.HexColor("#6c757d"),
}


# ── Filename helper ───────────────────────────────────────────────────────────

def _stamped_filename(prefix: str, extension: str) -> str:
    """Return an absolute path with a timestamp embedded in the filename."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(_REPORTS_DIR, f"{prefix}_{stamp}.{extension}")


# ── PDF builder helpers ───────────────────────────────────────────────────────

def _add_title_block(story: list, scan_time: str, styles) -> None:
    """Append the report header (title, subtitle, divider) to *story*."""
    title_style = ParagraphStyle(
        "ProWinTitle",
        parent=styles["Heading1"],
        fontSize=20,
        textColor=colors.HexColor("#1e1e2e"),
        alignment=TA_CENTER,
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "ProWinSubtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        textColor=colors.grey,
        fontSize=9,
    )

    story.append(Paragraph("🔍 ProWin — Endpoint Security Report", title_style))
    story.append(Paragraph(f"Scan completed: {scan_time}", subtitle_style))
    story.append(Paragraph("Author: Rohan Nair", subtitle_style))
    story.append(Spacer(1, 0.4 * cm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#2d6cdf")))
    story.append(Spacer(1, 0.3 * cm))


def _add_summary_table(story: list, data: dict, styles) -> None:
    """Append the executive-summary metrics table to *story*."""
    h2 = ParagraphStyle(
        "ProWinH2",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#2d6cdf"),
        spaceBefore=12,
        spaceAfter=4,
    )
    counts = data.get("alert_counts", {})
    rows = [
        ["Metric", "Value"],
        ["Total Processes Enumerated",  str(len(data.get("processes", [])))],
        ["Total Services Audited",      str(len(data.get("services", [])))],
        ["Persistence Entries Found",   str(len(data.get("startup_entries", [])))],
        ["Total Security Findings",     str(sum(counts.values()))],
        ["Critical Findings",           str(counts.get("CRITICAL", 0))],
        ["High Findings",               str(counts.get("HIGH", 0))],
        ["Medium Findings",             str(counts.get("MEDIUM", 0))],
        ["Low Findings",                str(counts.get("LOW", 0))],
    ]
    tbl = Table(rows, colWidths=[9 * cm, 6 * cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#2d6cdf")),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.HexColor("#f8f9fa"), colors.white]),
        ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("PADDING",       (0, 0), (-1, -1), 5),
    ]))
    story.append(Paragraph("Executive Summary", h2))
    story.append(tbl)
    story.append(Spacer(1, 0.5 * cm))


def _add_findings_table(story: list, findings: list, styles) -> None:
    """Append a colour-coded findings table (capped at 50 rows) to *story*."""
    if not findings:
        return

    h2 = ParagraphStyle(
        "ProWinH2b",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#2d6cdf"),
        spaceBefore=12,
        spaceAfter=4,
    )
    normal = styles["Normal"]
    normal.fontSize = 9

    header = [["Time", "Process", "PID", "Parent", "Severity", "Reason"]]
    body   = [
        [
            f.get("timestamp", "")[:16],
            f.get("process", ""),
            str(f.get("pid", "")),
            f.get("parent", ""),
            f.get("severity", "INFO"),
            Paragraph(f.get("reason", "")[:80], normal),
        ]
        for f in findings[:50]
    ]

    tbl = Table(header + body, colWidths=[2.8*cm, 2.5*cm, 1.2*cm, 2.5*cm, 1.8*cm, 6.2*cm])
    tbl_style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#343a40")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID",       (0, 0), (-1, -1), 0.3, colors.HexColor("#dee2e6")),
        ("FONTSIZE",   (0, 0), (-1, -1), 8),
        ("PADDING",    (0, 0), (-1, -1), 4),
        ("VALIGN",     (0, 0), (-1, -1), "TOP"),
    ]
    for row_idx, f in enumerate(findings[:50], start=1):
        sev   = f.get("severity", "INFO")
        clr   = _PDF_LEVEL_COLORS.get(sev, colors.grey)
        tbl_style.append(("TEXTCOLOR", (4, row_idx), (4, row_idx), clr))
        tbl_style.append(("FONTNAME",  (4, row_idx), (4, row_idx), "Helvetica-Bold"))
        if row_idx % 2 == 0:
            tbl_style.append(("BACKGROUND", (0, row_idx), (-1, row_idx),
                               colors.HexColor("#f8f9fa")))

    tbl.setStyle(TableStyle(tbl_style))
    story.append(Paragraph("Security Findings", h2))
    story.append(tbl)
    story.append(Spacer(1, 0.5 * cm))


def _add_service_table(story: list, services: list, styles) -> None:
    """Append a table of flagged services (up to 30 rows) to *story*."""
    flagged = [s for s in services if s.get("is_suspicious")]
    if not flagged:
        return

    h2 = ParagraphStyle(
        "ProWinH2c",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#2d6cdf"),
        spaceBefore=12,
        spaceAfter=4,
    )
    normal = styles["Normal"]
    normal.fontSize = 9

    rows = [["Service Name", "State", "Path", "Reason"]] + [
        [
            s.get("service_name", ""),
            s.get("state", ""),
            Paragraph((s.get("path") or "")[:60], normal),
            Paragraph((s.get("reason") or "")[:60], normal),
        ]
        for s in flagged[:30]
    ]
    tbl = Table(rows, colWidths=[4*cm, 2*cm, 5.5*cm, 5.5*cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#343a40")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID",       (0, 0), (-1, -1), 0.3, colors.HexColor("#dee2e6")),
        ("FONTSIZE",   (0, 0), (-1, -1), 8),
        ("PADDING",    (0, 0), (-1, -1), 4),
        ("VALIGN",     (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(Paragraph("Suspicious Services", h2))
    story.append(tbl)
    story.append(Spacer(1, 0.5 * cm))


# ── Public report builders ────────────────────────────────────────────────────

def build_pdf_report(data: dict) -> str:
    """
    Assemble a formatted A4 PDF report from the scan data dict.

    Parameters
    ----------
    data : dict
        Keys: processes, services, alerts, startup_entries, alert_counts,
        scan_time.

    Returns
    -------
    str
        Absolute path to the saved PDF file.
    """
    filepath = _stamped_filename("ProWin_Report", "pdf")
    doc = SimpleDocTemplate(
        filepath, pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )
    styles = getSampleStyleSheet()
    story  = []

    scan_time = data.get("scan_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    _add_title_block(story, scan_time, styles)
    _add_summary_table(story, data, styles)
    _add_findings_table(story, data.get("alerts", []), styles)
    _add_service_table(story, data.get("services", []), styles)

    normal = styles["Normal"]
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
    story.append(Paragraph(
        "ProWin — Endpoint Security Monitoring Agent | Author: Rohan Nair | Confidential",
        ParagraphStyle("footer", parent=normal,
                       alignment=TA_CENTER, textColor=colors.grey, fontSize=7),
    ))

    doc.build(story)
    print(f"[REPORT] PDF saved: {filepath}")
    return filepath


def build_txt_report(data: dict) -> str:
    """
    Write a plain-text summary report.

    Returns
    -------
    str
        Absolute path to the saved TXT file.
    """
    filepath  = _stamped_filename("ProWin_Report", "txt")
    scan_time = data.get("scan_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    counts    = data.get("alert_counts", {})

    lines = [
        "=" * 72,
        "  PROWIN — ENDPOINT SECURITY MONITORING AGENT — SCAN REPORT",
        f"  Author    : Rohan Nair",
        f"  Scan time : {scan_time}",
        "=" * 72,
        "",
        "EXECUTIVE SUMMARY",
        "-" * 42,
        f"  Processes enumerated      : {len(data.get('processes', []))}",
        f"  Services audited          : {len(data.get('services', []))}",
        f"  Persistence entries found : {len(data.get('startup_entries', []))}",
        f"  Total security findings   : {sum(counts.values())}",
        f"    Critical : {counts.get('CRITICAL', 0)}",
        f"    High     : {counts.get('HIGH', 0)}",
        f"    Medium   : {counts.get('MEDIUM', 0)}",
        f"    Low      : {counts.get('LOW', 0)}",
        "",
        "SECURITY FINDINGS",
        "-" * 42,
    ]

    for f in data.get("alerts", []):
        lines.append(
            f"  [{f.get('severity', '?'):8s}] {f.get('timestamp', '')[:16]} | "
            f"{f.get('process', '')} (PID:{f.get('pid', '')}) | "
            f"Parent: {f.get('parent', '')} | {f.get('reason', '')}"
        )

    lines += ["", "SUSPICIOUS SERVICES", "-" * 42]
    for s in data.get("services", []):
        if s.get("is_suspicious"):
            lines.append(
                f"  {s.get('service_name', '')} | "
                f"{s.get('state', '')} | "
                f"{s.get('reason', '')}"
            )

    lines += ["", "=" * 72, "END OF PROWIN REPORT", "=" * 72]

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    print(f"[REPORT] TXT saved: {filepath}")
    return filepath


def build_json_report(data: dict) -> str:
    """
    Serialise the full scan data dict to a JSON file for SIEM ingestion.

    Returns
    -------
    str
        Absolute path to the saved JSON file.
    """
    filepath = _stamped_filename("ProWin_Report", "json")
    data["generated_by"] = "ProWin — Rohan Nair"
    data["generated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
    print(f"[REPORT] JSON saved: {filepath}")
    return filepath


def export_all(data: dict) -> dict:
    """
    Generate all three report formats in a single call.

    Parameters
    ----------
    data : dict
        Scan results dict (same as individual builders).

    Returns
    -------
    dict
        {'pdf': path, 'txt': path, 'json': path}
    """
    return {
        "pdf":  build_pdf_report(data),
        "txt":  build_txt_report(data),
        "json": build_json_report(data),
    }
