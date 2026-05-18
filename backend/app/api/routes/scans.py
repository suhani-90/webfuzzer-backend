"""
app/api/routes/scans.py
────────────────────────
Scan orchestration endpoints:
  POST  /scans/start            — start a new scan (dispatches Celery task)
  GET   /scans                  — list all scans for current user
  GET   /scans/{scan_id}/status — get live scan status + progress
  GET   /scans/{scan_id}/logs   — get scan logs (paginated)
  POST  /scans/{scan_id}/stop   — cancel an active scan
"""

import uuid
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from backend.app.core.dependencies import get_current_user, get_db
from backend.app.core.logging import get_logger
from backend.app.models.scan import Scan, ScanStatus, ScanType
from backend.app.models.target import Target
from backend.app.models.user import User
from backend.app.schemas.scan import (
    ScanCreateResponse,
    ScanListItem,
    ScanStartRequest,
    ScanStatusResponse,
)
from backend.app.utils.url_validator import url_validator

logger = get_logger(__name__)
router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post(
    "/start",
    response_model=ScanCreateResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start a new security scan",
)
async def start_scan(
    payload: ScanStartRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanCreateResponse:
    """
    Initiate a new fuzzing scan.

    1. Validates the target URL (SSRF prevention)
    2. Creates a Target record if one doesn't exist for this URL
    3. Creates a Scan record with PENDING status
    4. Dispatches a Celery background task to run the scan
    5. Returns the scan_id immediately for WebSocket subscription

    The frontend should then connect to:
      ws://host/ws/scans/{scan_id}
    to receive real-time log events.
    """
    # Validate URL
    is_valid, reason = url_validator.validate(payload.targetUrl)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid target URL: {reason}",
        )
    safe_url = url_validator.sanitise(payload.targetUrl)

    # Find or create target for this URL
    result = await db.execute(
        select(Target).where(
            Target.user_id == current_user.id,
            Target.url == safe_url,
        )
    )
    target = result.scalar_one_or_none()
    if not target:
        target = Target(
            user_id=current_user.id,
            url=safe_url,
            name=safe_url,
            scan_depth=payload.depth,
        )
        db.add(target)
        await db.flush()  # Get target.id without committing

    # Create scan record
    scan_id = str(uuid.uuid4())
    scan = Scan(
        id=scan_id,
        user_id=current_user.id,
        target_id=target.id,
        target_url=safe_url,
        scan_type=payload.scanType,
        depth=payload.depth,
        payload_config=payload.payloads.model_dump(),
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    await db.commit()

    # Dispatch Celery background task
    try:
        from backend.app.services.fuzzer.tasks import run_scan

        task = run_scan.delay(scan_id, payload.model_dump(mode="json"))
        # Save Celery task ID for monitoring
        scan.celery_task_id = task.id
        await db.commit()
        logger.info("scan.dispatched", scan_id=scan_id, task_id=task.id)
    except Exception as exc:
        # If Celery is not running, mark scan as failed
        logger.error("scan.dispatch_failed", scan_id=scan_id, error=str(exc))
        scan.status = ScanStatus.FAILED
        scan.error_message = f"Failed to dispatch scan task: {str(exc)}"
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan worker is unavailable. Ensure Celery and Redis are running.",
        )

    return ScanCreateResponse(
        scan_id=scan_id,
        status=ScanStatus.PENDING,
        message="Scan queued successfully. Connect to WebSocket for live updates.",
    )


@router.get(
    "",
    response_model=List[ScanListItem],
    summary="List all scans for current user",
)
async def list_scans(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> List[ScanListItem]:
    """Return paginated list of scans for the authenticated user."""
    result = await db.execute(
        select(Scan)
        .where(Scan.user_id == current_user.id)
        .order_by(Scan.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return result.scalars().all()


@router.get(
    "/{scan_id}/status",
    response_model=ScanStatusResponse,
    summary="Get real-time scan status",
)
async def get_scan_status(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanStatusResponse:
    """
    Return the current status and metrics of a scan.
    Poll this endpoint or subscribe to the WebSocket for live updates.
    """
    result = await db.execute(
        select(Scan).where(
            Scan.id == scan_id,
            Scan.user_id == current_user.id,
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found."
        )
    return scan


@router.post(
    "/{scan_id}/stop",
    status_code=status.HTTP_200_OK,
    summary="Cancel an active scan",
)
async def stop_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Cancel a running scan by revoking its Celery task."""
    result = await db.execute(
        select(Scan).where(
            Scan.id == scan_id,
            Scan.user_id == current_user.id,
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found."
        )

    if scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan is already in terminal state: {scan.status}.",
        )

    # Revoke Celery task
    if scan.celery_task_id:
        try:
            from backend.app.core.celery_app import celery_app

            celery_app.control.revoke(scan.celery_task_id, terminate=True)
        except Exception as exc:
            logger.warning("scan.revoke_failed", scan_id=scan_id, error=str(exc))

    scan.status = ScanStatus.CANCELLED
    scan.completed_at = datetime.now(timezone.utc)
    await db.commit()

    return {"scan_id": scan_id, "status": "cancelled", "message": "Scan cancelled."}
