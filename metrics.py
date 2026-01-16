"""
Metrics & Analytics endpoints for SecureX Control API.

SCHEMA ALIGNMENT:
- All queries use TrafficLog.endpoint (DB column) for grouping/filtering
- 'endpoint' is the canonical, normalized path
- NEVER use 'normalized_path' in SQL queries (it's a read-only property alias)
"""
from datetime import datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, Integer
from sqlalchemy.orm import Session

from db import get_db
from auth import get_current_user
from models import TrafficLog, Project, User
from schemas import EndpointAnalysisResponse, EndpointAnalysis, EndpointMetrics

router = APIRouter(prefix="/projects", tags=["metrics"])


def get_project_or_404(project_id: UUID, user: User, db: Session) -> Project:
    project = (
        db.query(Project)
        .filter(Project.id == project_id, Project.owner_id == user.id)
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@router.get("/{project_id}/endpoint-analysis", response_model=EndpointAnalysisResponse)
def endpoint_analysis(
    project_id: UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    try:
        project = get_project_or_404(project_id, user, db)
        now = datetime.utcnow()

        last_5m = now - timedelta(minutes=5)
        last_7d = now - timedelta(days=7)
        current_hour = now.hour

        # ───── CURRENT TRAFFIC ─────
        current = (
            db.query(
                TrafficLog.endpoint,
                func.count().label("requests"),
                func.avg(TrafficLog.risk_score).label("avg_risk"),
                func.sum(func.cast(TrafficLog.decision == "THROTTLE", Integer)).label("throttled"),
                func.sum(func.cast(TrafficLog.decision == "BLOCK", Integer)).label("blocked"),
            )
            .filter(
                TrafficLog.project_id == project.id,
                TrafficLog.created_at >= last_5m,
            )
            .group_by(TrafficLog.endpoint)
            .all()
        )

        # ───── HISTORICAL BASELINE ─────
        hist = (
            db.query(
                TrafficLog.endpoint,
                func.count().label("total"),
            )
            .filter(
                TrafficLog.project_id == project.id,
                TrafficLog.created_at >= last_7d,
            )
            .group_by(TrafficLog.endpoint)
            .all()
        )

        hist_rpm = {r.endpoint: r.total / (7 * 24 * 60) for r in hist if r.endpoint}

        # ───── TIME-OF-DAY BASELINE ─────
        tod = (
            db.query(
                TrafficLog.endpoint,
                func.count().label("total"),
            )
            .filter(
                TrafficLog.project_id == project.id,
                TrafficLog.created_at >= last_7d,
                func.extract("hour", TrafficLog.created_at) == current_hour,
            )
            .group_by(TrafficLog.endpoint)
            .all()
        )

        tod_rpm = {r.endpoint: r.total / (7 * 60) for r in tod if r.endpoint}

        results = []

        for r in current:
            endpoint = r.endpoint
            if not endpoint:
                continue

            requests = r.requests or 0
            curr_rpm = requests / 5.0

            base = tod_rpm.get(endpoint, hist_rpm.get(endpoint, 0))
            base = max(base, 0.1)

            multiplier = curr_rpm / base

            throttle_rate = (r.throttled or 0) / requests if requests else 0
            block_rate = (r.blocked or 0) / requests if requests else 0
            avg_risk = r.avg_risk or 0

            severity = "NORMAL"
            color = "green"
            notes = []

            if throttle_rate > 0.1:
                severity, color = "HIGH", "red"
                notes.append(f"High throttling ({int(throttle_rate * 100)}%).")
            elif multiplier >= 4 and curr_rpm > 10:
                severity, color = "HIGH", "red"
                notes.append(f"Traffic spike ({multiplier:.1f}x baseline).")
            elif avg_risk >= 0.7:
                severity, color = "WATCH", "yellow"
                notes.append("Elevated risk scores.")
            elif multiplier >= 2 and curr_rpm > 5:
                severity, color = "WATCH", "yellow"
                notes.append(f"Traffic elevated ({multiplier:.1f}x).")
            else:
                notes.append("Traffic within normal range.")

            results.append(
                EndpointAnalysis(
                    endpoint=endpoint,
                    severity=severity,
                    color=color,
                    summary=" ".join(notes),
                    metrics=EndpointMetrics(
                        current_rpm=round(curr_rpm, 2),
                        baseline_rpm=round(base, 2),
                        traffic_multiplier=round(multiplier, 2),
                        throttle_rate=round(throttle_rate, 2),
                        block_rate=round(block_rate, 2),
                        avg_risk_score=round(avg_risk, 2),
                    ),
                    securex_action="Monitoring" if severity == "NORMAL" else "Active mitigation",
                    suggested_action=None if severity == "NORMAL" else "Inspect traffic sources.",
                )
            )

        return EndpointAnalysisResponse(generated_at=now, endpoints=results)

    except Exception:
        # HARD FAIL-SAFE — NEVER break dashboard
        return EndpointAnalysisResponse(
            generated_at=datetime.utcnow(),
            endpoints=[],
        )
