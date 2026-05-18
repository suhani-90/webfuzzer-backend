"""
app/services/reporting/report_builder.py
──────────────────────────────────────────
Generates structured JSON + PDF reports from completed scans.
Stores report data in the reports table and optionally generates a PDF file.
"""

import json
import os
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.core.logging import get_logger
from app.db.session import AsyncSessionLocal
from app.models.report import Report
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.services.ai.payload_engine import payload_engine
from app.services.reporting.pdf_generator import PDFGenerator

logger = get_logger(__name__)


class ReportBuilder:
    """
    Builds and persists security audit reports.
    Creates a Report record containing summary stats,
    all vulnerabilities, and an AI-generated executive summary.
    """

    async def build_and_save(self, scan_id: str) -> Optional[Report]:
        """
        Build a complete report for the given scan and save it to the DB.

        Args:
            scan_id: UUID of the completed Scan.

        Returns:
            The persisted Report ORM model, or None on error.
        """
        async with AsyncSessionLocal() as db:
            # Load scan with all related vulnerabilities
            result = await db.execute(
                select(Scan)
                .where(Scan.id == scan_id)
                .options(selectinload(Scan.vulnerabilities))
            )
            scan = result.scalar_one_or_none()
            if not scan:
                logger.error("report_builder.scan_not_found", scan_id=scan_id)
                return None

            vulns = scan.vulnerabilities

            # Count by severity
            high_count = sum(1 for v in vulns if v.severity == "High")
            medium_count = sum(1 for v in vulns if v.severity == "Medium")
            low_count = sum(1 for v in vulns if v.severity == "Low")
            total = len(vulns)

            # AI executive summary
            executive_summary = await payload_engine.generate_executive_summary(
                target_url=scan.target_url,
                vuln_count=total,
                severity_breakdown={
                    "High": high_count,
                    "Medium": medium_count,
                    "Low": low_count,
                },
            )

            # Build full report JSON structure
            duration: Optional[float] = None
            if scan.started_at and scan.completed_at:
                duration = (scan.completed_at - scan.started_at).total_seconds()

            report_data = {
                "scan_id": scan_id,
                "target_url": scan.target_url,
                "scan_type": scan.scan_type,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "summary": {
                    "total_vulnerabilities": total,
                    "high_count": high_count,
                    "medium_count": medium_count,
                    "low_count": low_count,
                    "total_requests": scan.total_requests,
                    "total_endpoints": scan.total_endpoints,
                    "scan_duration_seconds": duration,
                },
                "executive_summary": executive_summary,
                "vulnerabilities": [
                    {
                        "id": v.id,
                        "type": v.type,
                        "severity": v.severity,
                        "url": v.url,
                        "parameter": v.parameter,
                        "payload": v.payload,
                        "responseSnippet": v.response_snippet or "",
                        "fixRecommendation": v.fix_recommendation or "",
                        "detected_at": v.detected_at.isoformat(),
                    }
                    for v in vulns
                ],
            }

            # Check if report already exists (idempotent)
            existing = await db.execute(select(Report).where(Report.scan_id == scan_id))
            report = existing.scalar_one_or_none()

            if report:
                report.report_data = report_data
                report.executive_summary = executive_summary
                report.total_vulnerabilities = total
                report.high_count = high_count
                report.medium_count = medium_count
                report.low_count = low_count
                report.generated_at = datetime.now(timezone.utc)
            else:
                report = Report(
                    scan_id=scan_id,
                    total_vulnerabilities=total,
                    high_count=high_count,
                    medium_count=medium_count,
                    low_count=low_count,
                    executive_summary=executive_summary,
                    report_data=report_data,
                )
                db.add(report)

            await db.commit()
            await db.refresh(report)

            logger.info(
                "report_builder.saved",
                scan_id=scan_id,
                total=total,
                report_id=report.id,
            )
            return report

    async def get_report_dict(self, scan_id: str) -> Optional[dict]:
        """Fetch the full report_data JSON for a scan."""
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Report).where(Report.scan_id == scan_id))
            report = result.scalar_one_or_none()
            return report.report_data if report else None
