"""
app/api/routes/fuzz.py
───────────────────────
Vulnerability results endpoint:
  GET /fuzz/results/{scan_id}   — paginated vulnerability list for a scan
"""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from backend.app.core.dependencies import get_current_user, get_db
from backend.app.models.scan import Scan
from backend.app.models.user import User
from backend.app.models.vulnerability import Vulnerability
from backend.app.schemas.vulnerability import VulnerabilityResponse

router = APIRouter(prefix="/fuzz", tags=["Fuzzing Results"])


@router.get(
    "/results/{scan_id}",
    response_model=List[VulnerabilityResponse],
    summary="Get all vulnerabilities found in a scan",
)
async def get_fuzz_results(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    severity: str = Query(None, description="Filter by severity: High | Medium | Low"),
    vuln_type: str = Query(None, description="Filter by vulnerability type"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> List[VulnerabilityResponse]:
    """
    Return all vulnerabilities discovered during a scan.
    Supports filtering by severity and type.
    Results are sorted by severity (High first) then detection time.
    """
    # Verify scan belongs to current user
    scan_result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    if not scan_result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found."
        )

    query = select(Vulnerability).where(Vulnerability.scan_id == scan_id)

    if severity:
        query = query.where(Vulnerability.severity == severity)
    if vuln_type:
        query = query.where(Vulnerability.type.ilike(f"%{vuln_type}%"))

    # Order: High severity first, then by detection time desc
    from sqlalchemy import case

    severity_order = case(
        {"High": 1, "Medium": 2, "Low": 3},
        value=Vulnerability.severity,
        else_=4,
    )
    query = query.order_by(severity_order, Vulnerability.detected_at.desc())
    query = query.limit(limit).offset(offset)

    result = await db.execute(query)
    vulns = result.scalars().all()

    # Manually map to response with aliases
    return [
        VulnerabilityResponse(
            id=v.id,
            scan_id=v.scan_id,
            url=v.url,
            parameter=v.parameter,
            payload=v.payload,
            type=v.type,
            severity=v.severity,
            responseSnippet=v.response_snippet,
            fixRecommendation=v.fix_recommendation,
            http_method=v.http_method,
            status_code=v.status_code,
            response_time_ms=v.response_time_ms,
            detected_at=v.detected_at,
        )
        for v in vulns
    ]
