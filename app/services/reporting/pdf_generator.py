"""
app/services/reporting/pdf_generator.py
────────────────────────────────────────
Generates professional PDF security audit reports using ReportLab.
"""

import traceback
import io
import os
from datetime import datetime
from typing import Optional

from app.core.logging import get_logger

logger = get_logger(__name__)


class PDFGenerator:
    """
    Generates a downloadable PDF security audit report from report_data dict.
    Uses ReportLab for PDF generation without external dependencies.
    """

    def generate(self, report_data: dict) -> Optional[bytes]:
        """
        Generate a PDF from the report data dictionary.

        Args:
            report_data: The full report_data JSON from the Report model.

        Returns:
            PDF file as bytes, or None on error.
        """
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.platypus import (
                SimpleDocTemplate,
                Paragraph,
                Spacer,
                Table,
                TableStyle,
                HRFlowable,
                PageBreak,
            )
            from reportlab.lib.enums import TA_CENTER, TA_LEFT

            buffer = io.BytesIO()
            doc = SimpleDocTemplate(
                buffer,
                pagesize=A4,
                rightMargin=2 * cm,
                leftMargin=2 * cm,
                topMargin=2 * cm,
                bottomMargin=2 * cm,
            )

            styles = getSampleStyleSheet()
            story = []

            # Colour palette matching SmartFuzz green theme
            EMERALD = colors.HexColor("#10B981")
            DARK = colors.HexColor("#0F172A")
            ROSE = colors.HexColor("#F43F5E")
            AMBER = colors.HexColor("#F59E0B")
            SLATE = colors.HexColor("#64748B")

            # ── Title Block ───────────────────────────────────────────────────
            title_style = ParagraphStyle(
                "Title",
                parent=styles["Title"],
                fontSize=28,
                textColor=DARK,
                spaceAfter=6,
            )
            subtitle_style = ParagraphStyle(
                "Subtitle",
                parent=styles["Normal"],
                fontSize=12,
                textColor=SLATE,
                spaceAfter=4,
            )

            story.append(Paragraph("SmartFuzz Security Audit Report", title_style))
            story.append(
                Paragraph(
                    f"Target: <b>{report_data.get('target_url', 'N/A')}</b>",
                    subtitle_style,
                )
            )
            story.append(
                Paragraph(
                    f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}",
                    subtitle_style,
                )
            )
            story.append(Spacer(1, 0.5 * cm))
            story.append(HRFlowable(width="100%", thickness=2, color=EMERALD))
            story.append(Spacer(1, 0.5 * cm))

            # ── Executive Summary ─────────────────────────────────────────────
            heading_style = ParagraphStyle(
                "Heading",
                parent=styles["Heading2"],
                textColor=DARK,
                fontSize=14,
                spaceBefore=12,
                spaceAfter=6,
            )
            body_style = ParagraphStyle(
                "Body",
                parent=styles["Normal"],
                fontSize=10,
                leading=14,
                textColor=DARK,
            )

            story.append(Paragraph("Executive Summary", heading_style))
            summary = report_data.get("executive_summary") or "No summary available."
            story.append(Spacer(1, 0.5 * cm))

            # ── Summary Statistics Table ──────────────────────────────────────
            story.append(Paragraph("Scan Statistics", heading_style))
            s = report_data.get("summary", {})
            stats_data = [
                ["Metric", "Value"],
                ["Total Vulnerabilities", str(s.get("total_vulnerabilities", 0))],
                ["High Severity", str(s.get("high_count", 0))],
                ["Medium Severity", str(s.get("medium_count", 0))],
                ["Low Severity", str(s.get("low_count", 0))],
                ["Total Requests Sent", str(s.get("total_requests", 0))],
                ["Endpoints Discovered", str(s.get("total_endpoints", 0))],
                ["Scan Duration", f"{(s.get('scan_duration_seconds') or 0):.1f}s"],
            ]
            stats_table = Table(stats_data, colWidths=[9 * cm, 6 * cm])
            stats_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), EMERALD),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 11),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.white, colors.HexColor("#F8FAFC")],
                        ),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                        ("FONTSIZE", (0, 1), (-1, -1), 10),
                        ("PADDING", (0, 0), (-1, -1), 8),
                    ]
                )
            )
            story.append(stats_table)
            story.append(Spacer(1, 1 * cm))

            # ── Vulnerabilities Section ───────────────────────────────────────
            vulns = report_data.get("vulnerabilities", [])
            if vulns:
                story.append(PageBreak())
                story.append(Paragraph("Vulnerability Details", heading_style))

                for i, vuln in enumerate(vulns, 1):
                    severity = vuln.get("severity", "Low")
                    sev_color = (
                        ROSE
                        if severity == "High"
                        else (AMBER if severity == "Medium" else EMERALD)
                    )

                    # Vuln header
                    vuln_title = ParagraphStyle(
                        f"VT{i}",
                        parent=styles["Heading3"],
                        textColor=sev_color,
                        fontSize=12,
                        spaceBefore=16,
                    )
                    story.append(
                        Paragraph(
                            f"{i}. {vuln.get('type', 'Unknown')} [{severity}]",
                            vuln_title,
                        )
                    )

                    # Details table
                    detail_data = [
                        ["Field", "Value"],
                        ["URL", str(vuln.get("url") or "")],
                        ["Parameter", str(vuln.get("parameter") or "")],
                        ["Payload", str(vuln.get("payload") or "")],
                    ]
                    detail_table = Table(detail_data, colWidths=[4 * cm, 13 * cm])
                    detail_table.setStyle(
                        TableStyle(
                            [
                                ("BACKGROUND", (0, 0), (-1, 0), SLATE),
                                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                                ("FONTSIZE", (0, 0), (-1, -1), 9),
                                (
                                    "GRID",
                                    (0, 0),
                                    (-1, -1),
                                    0.3,
                                    colors.HexColor("#E2E8F0"),
                                ),
                                (
                                    "ROWBACKGROUNDS",
                                    (0, 1),
                                    (-1, -1),
                                    [colors.white, colors.HexColor("#F8FAFC")],
                                ),
                                # ("WORDWRAP", (1, 1), (1, -1), True),
                                ("PADDING", (0, 0), (-1, -1), 6),
                            ]
                        )
                    )
                    story.append(detail_table)

                    # Remediation
                    fix = vuln.get("fixRecommendation", "")
                    if fix:
                        story.append(Spacer(1, 0.2 * cm))
                        fix_style = ParagraphStyle(
                            f"Fix{i}",
                            parent=styles["Normal"],
                            fontSize=9,
                            leading=13,
                            textColor=colors.HexColor("#065F46"),
                            backColor=colors.HexColor("#ECFDF5"),
                            borderPadding=8,
                        )
                        story.append(Paragraph(f"<b>Remediation:</b> {fix}", fix_style))

            story.append(Spacer(1, 1 * cm))
            story.append(HRFlowable(width="100%", thickness=1, color=SLATE))
            story.append(
                Paragraph(
                    "Generated by SmartFuzz — AI-Driven Intelligent Web Fuzzer",
                    ParagraphStyle(
                        "Footer",
                        parent=styles["Normal"],
                        fontSize=8,
                        textColor=SLATE,
                        alignment=TA_CENTER,
                    ),
                )
            )

            doc.build(story)
            return buffer.getvalue()

        except ImportError:
            logger.error("pdf_generator.reportlab_not_installed")
            return None

        except Exception as exc:
            traceback.print_exc()
            logger.error("pdf_generator.error", error=str(exc))
            return None
