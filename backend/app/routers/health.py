from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import get_current_user, get_db
from ..models import HealthReport, User
from ..schemas import HealthReportIn, HealthReportOut

router = APIRouter(prefix="/health", tags=["health"])


def _compute_score(weak_count: int, reused_count: int, breached_count: int, total_entries: int) -> int:
    if total_entries == 0:
        return 100
    return max(
        0,
        min(100, 100 - (20 * breached_count) - (15 * weak_count) - (10 * reused_count)),
    )


def _to_out(r: HealthReport) -> HealthReportOut:
    return HealthReportOut(
        id=r.id,
        user_id=r.user_id,
        total_entries=r.total_entries,
        weak_count=r.weak_count,
        reused_count=r.reused_count,
        old_count=r.old_count,
        breached_count=r.breached_count,
        score=_compute_score(r.weak_count, r.reused_count, r.breached_count, r.total_entries),
        created_at=r.created_at.isoformat(),
        updated_at=r.updated_at.isoformat(),
    )


@router.post("/report", response_model=HealthReportOut)
async def upsert_report(
    body: HealthReportIn,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    existing = await db.scalar(
        select(HealthReport).where(HealthReport.user_id == user.id)
    )
    now = datetime.now(timezone.utc)
    if existing:
        existing.total_entries = body.total_entries
        existing.weak_count = body.weak_count
        existing.reused_count = body.reused_count
        existing.old_count = body.old_count
        existing.breached_count = body.breached_count
        existing.updated_at = now
        await db.commit()
        await db.refresh(existing)
        return _to_out(existing)
    report = HealthReport(
        user_id=user.id,
        total_entries=body.total_entries,
        weak_count=body.weak_count,
        reused_count=body.reused_count,
        old_count=body.old_count,
        breached_count=body.breached_count,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)
    return _to_out(report)


@router.get("/latest", response_model=HealthReportOut)
async def get_latest(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    report = await db.scalar(
        select(HealthReport).where(HealthReport.user_id == user.id)
    )
    if not report:
        raise HTTPException(404, "no health report yet")
    return _to_out(report)
