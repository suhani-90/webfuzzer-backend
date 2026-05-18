"""
app/api/routes/targets.py
──────────────────────────
Target management endpoints:
  POST   /targets          — register a new scan target
  GET    /targets          — list all targets for current user
  GET    /targets/{id}     — get a specific target
  DELETE /targets/{id}     — delete a target
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from backend.app.core.dependencies import get_current_user, get_db
from backend.app.models.target import Target
from backend.app.models.user import User
from backend.app.schemas.target import TargetCreateRequest, TargetResponse
from backend.app.utils.url_validator import url_validator

router = APIRouter(prefix="/targets", tags=["Targets"])


@router.post(
    "",
    response_model=TargetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new scan target URL",
)
async def create_target(
    payload: TargetCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TargetResponse:
    """
    Register a web application target for fuzzing.
    Validates the URL for safety (SSRF prevention) before saving.
    """
    is_valid, reason = url_validator.validate(payload.url)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid target URL: {reason}",
        )

    safe_url = url_validator.sanitise(payload.url)

    target = Target(
        user_id=current_user.id,
        url=safe_url,
        name=payload.name or safe_url,
        description=payload.description,
        scan_depth=payload.scan_depth,
        rate_limit_rps=payload.rate_limit_rps,
        allowed_methods=payload.allowed_methods,
        custom_headers=payload.custom_headers,
        cookies=payload.cookies,
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)
    return target


@router.get(
    "",
    response_model=list[TargetResponse],
    summary="List all targets for current user",
)
async def list_targets(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[TargetResponse]:
    """Return all targets belonging to the authenticated user."""
    result = await db.execute(
        select(Target)
        .where(Target.user_id == current_user.id)
        .order_by(Target.created_at.desc())
    )
    return result.scalars().all()


@router.get(
    "/{target_id}",
    response_model=TargetResponse,
    summary="Get a specific target by ID",
)
async def get_target(
    target_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TargetResponse:
    """Retrieve a target by its UUID. Must belong to the current user."""
    result = await db.execute(
        select(Target).where(
            Target.id == target_id,
            Target.user_id == current_user.id,
        )
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Target not found."
        )
    return target


@router.delete(
    "/{target_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a target and all its scans",
)
async def delete_target(
    target_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    """Delete a target by ID. Cascades to all associated scans and results."""
    result = await db.execute(
        select(Target).where(
            Target.id == target_id,
            Target.user_id == current_user.id,
        )
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Target not found."
        )
    await db.delete(target)
    await db.commit()
