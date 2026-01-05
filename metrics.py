from datetime import datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from db import get_db
from auth import get_current_user
from models import TrafficLog, Project, User

router = APIRouter(prefix="/projects", tags=["metrics"])


# =========================
# Helpers
# =========================

def get_project_or_404(
    project_id: UUID,
    user: User,
    db: Session,
) -> Project:
    project = (
        db.query(Project)
        .filter(Project.id == project_id, Project.owner_id == user.id)
        .first()
    )
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    return project


def parse_time_range(hours: int | None):
    if hours:
        return datetime.utcnow() - timedelta(hours=hours)
    return None


# =========================
# Routes
# =========================

@router.get("/{project_id}/metrics/summary")
def metrics_summary(
    project_id: UUID,
    hours: int | None = Query(default=24, ge=1, le=720),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = get_project_or_404(project_id, current_user, db)
    since = parse_time_range(hours)

    base_query = db.query(TrafficLog).filter(
        TrafficLog.project_id == project.id
    )

    if since:
        base_query = base_query.filter(TrafficLog.created_at >= since)

    total_requests = base_query.count()
    blocked_requests = base_query.filter(TrafficLog.blocked.is_(True)).count()

    avg_risk_query = db.query(func.avg(TrafficLog.risk_score)).filter(
        TrafficLog.project_id == project.id,
        TrafficLog.risk_score.isnot(None),
    )

    if since:
        avg_risk_query = avg_risk_query.filter(TrafficLog.created_at >= since)

    avg_risk = avg_risk_query.scalar()

    return {
        "project_id": project.id,
        "time_window_hours": hours,
        "total_requests": total_requests,
        "blocked_requests": blocked_requests,
        "block_rate": (
            blocked_requests / total_requests
            if total_requests > 0
            else 0
        ),
        "average_risk_score": round(avg_risk, 2) if avg_risk else None,
    }


@router.get("/{project_id}/metrics/traffic")
def traffic_timeseries(
    project_id: UUID,
    hours: int | None = Query(default=24, ge=1, le=720),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = get_project_or_404(project_id, current_user, db)
    since = parse_time_range(hours)

    query = (
        db.query(
            func.date_trunc("hour", TrafficLog.created_at).label("bucket"),
            func.count().label("requests"),
            func.sum(func.cast(TrafficLog.blocked, int)).label("blocked"),
        )
        .filter(TrafficLog.project_id == project.id)
        .group_by("bucket")
        .order_by("bucket")
    )

    if since:
        query = query.filter(TrafficLog.created_at >= since)

    results = query.all()

    return [
        {
            "timestamp": row.bucket,
            "requests": row.requests,
            "blocked": row.blocked or 0,
        }
        for row in results
    ]
