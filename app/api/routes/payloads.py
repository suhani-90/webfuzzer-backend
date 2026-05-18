"""
app/api/routes/payloads.py
───────────────────────────
AI payload generation endpoint:
  POST /payloads/generate   — generate context-aware payloads via Gemini
"""

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.dependencies import get_current_user
from app.models.user import User
from app.schemas.vulnerability import PayloadGenerateRequest, PayloadGenerateResponse
from app.services.ai.payload_engine import payload_engine

router = APIRouter(prefix="/payloads", tags=["AI Payloads"])


@router.post(
    "/generate",
    response_model=PayloadGenerateResponse,
    summary="Generate AI-powered security payloads via Gemini",
)
async def generate_payloads(
    payload: PayloadGenerateRequest,
    current_user: User = Depends(get_current_user),
) -> PayloadGenerateResponse:
    """
    Use Gemini AI + static libraries to generate a categorised
    set of security fuzzing payloads for the given target.

    Returns payloads grouped by category (sqli, xss, rce, etc.)
    """
    categories = await payload_engine.generate(
        target_url=payload.target_url,
        scan_type=payload.scan_type,
        include_sql=payload.include_sql,
        include_xss=payload.include_xss,
        include_rce=payload.include_rce,
        include_auth=payload.include_auth_bypass,
        custom_context=payload.context or "",
        ai_count=payload.count,
    )

    all_payloads = [p for pl in categories.values() for p in pl]
    return PayloadGenerateResponse(
        payloads=all_payloads,
        categories=categories,
        ai_generated=True,
        total_count=len(all_payloads),
    )


"""
app/api/routes/reports.py
──────────────────────────
Report endpoints:
  GET /reports/{scan_id}       — full JSON report
  GET /reports/{scan_id}/pdf   — downloadable PDF report
"""

from fastapi import (
    APIRouter as _APIRouter,
    Depends as _Depends,
    HTTPException as _HTTPException,
    status as _status,
)
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select as _select

from app.core.dependencies import (
    get_current_user as _get_current_user,
    get_db as _get_db,
)
from app.models.report import Report
from app.models.scan import Scan
from app.models.user import User as _User
from app.services.reporting.pdf_generator import PDFGenerator
from app.services.reporting.report_builder import ReportBuilder

reports_router = _APIRouter(prefix="/reports", tags=["Reports"])


@reports_router.get(
    "/{scan_id}",
    summary="Get JSON security audit report for a scan",
)
async def get_report(
    scan_id: str,
    db: AsyncSession = _Depends(_get_db),
    current_user: _User = _Depends(_get_current_user),
) -> dict:
    """
    Return the full security audit report as JSON.
    Automatically generates the report if it doesn't exist yet.
    """
    # Verify ownership
    scan_result = await db.execute(
        _select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise _HTTPException(
            status_code=_status.HTTP_404_NOT_FOUND, detail="Scan not found."
        )

    # Try to get existing report
    report_result = await db.execute(_select(Report).where(Report.scan_id == scan_id))
    report = report_result.scalar_one_or_none()

    if not report:
        # Build report on-demand if not yet generated
        builder = ReportBuilder()
        await builder.build_and_save(scan_id)
        report_data = await builder.get_report_dict(scan_id)
        if not report_data:
            raise _HTTPException(
                status_code=_status.HTTP_404_NOT_FOUND,
                detail="Report not available yet. Scan may still be in progress.",
            )
        return report_data

    return report.report_data


@reports_router.get(
    "/{scan_id}/pdf",
    summary="Download PDF security audit report",
    responses={200: {"content": {"application/pdf": {}}}},
)
async def download_pdf_report(
    scan_id: str,
    db: AsyncSession = _Depends(_get_db),
    current_user: _User = _Depends(_get_current_user),
) -> Response:
    """
    Generate and download a professional PDF security audit report.
    """
    # Verify ownership
    scan_result = await db.execute(
        _select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    if not scan_result.scalar_one_or_none():
        raise _HTTPException(
            status_code=_status.HTTP_404_NOT_FOUND, detail="Scan not found."
        )

    # Get report data
    report_result = await db.execute(_select(Report).where(Report.scan_id == scan_id))
    report = report_result.scalar_one_or_none()

    if not report:
        raise _HTTPException(
            status_code=_status.HTTP_404_NOT_FOUND,
            detail="Report not generated yet.",
        )

    generator = PDFGenerator()
    pdf_bytes = generator.generate(report.report_data)

    if not pdf_bytes:
        raise _HTTPException(
            status_code=_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="PDF generation failed.",
        )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="smartfuzz_report_{scan_id[:8]}.pdf"'
        },
    )
