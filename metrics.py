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
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()
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

        # Time windows
        last_5m = now - timedelta(minutes=5)
        last_7d = now - timedelta(days=7)
        current_hour = now.hour

        # ─────────────────────────────────────────────
        # 1. Current Traffic (last 5 minutes)
        # ─────────────────────────────────────────────
        # Defensive: ensure we target the REAL column 'endpoint'
        current_stats = db.query(
            TrafficLog.endpoint,
            func.count().label("requests"),
            func.avg(TrafficLog.risk_score).label("avg_risk"),
            func.sum(func.cast(TrafficLog.decision == "THROTTLE", Integer)).label("throttled"),
            func.sum(func.cast(TrafficLog.decision == "BLOCK", Integer)).label("blocked"),
        ).filter(
            TrafficLog.project_id == project.id,
            TrafficLog.created_at >= last_5m,
        ).group_by(
            TrafficLog.endpoint
        ).all()

        # ─────────────────────────────────────────────
        # 2. Historical Baseline (last 7 days)
        # ─────────────────────────────────────────────
        historical_stats = db.query(
            TrafficLog.endpoint,
            func.count().label("total_reqs"),
        ).filter(
            TrafficLog.project_id == project.id,
            TrafficLog.created_at >= last_7d,
        ).group_by(
            TrafficLog.endpoint
        ).all()

        historical_rpm = {
            r.endpoint: r.total_reqs / (7 * 24 * 60)
            for r in historical_stats if r.endpoint
        }

        # ─────────────────────────────────────────────
        # 3. Time-of-Day Baseline (same hour, last 7 days)
        # ─────────────────────────────────────────────
        tod_stats = db.query(
            TrafficLog.endpoint,
            func.count().label("total_reqs"),
        ).filter(
            TrafficLog.project_id == project.id,
            TrafficLog.created_at >= last_7d,
            func.extract("hour", TrafficLog.created_at) == current_hour,
        ).group_by(
            TrafficLog.endpoint
        ).all()

        tod_rpm = {
            r.endpoint: r.total_reqs / (7 * 60)
            for r in tod_stats if r.endpoint
        }

        # ─────────────────────────────────────────────
        # 4. Analysis & Response
        # ─────────────────────────────────────────────
        results = []

        for r in current_stats:
            if not r.endpoint:
                continue

            curr_rpm = (r.requests or 0) / 5.0

            base_hist = historical_rpm.get(r.endpoint, 0)
            base_tod = tod_rpm.get(r.endpoint, 0)

            baseline_used = base_tod if base_tod > 1 else base_hist
            baseline_used = max(baseline_used, 0.1)

            multiplier = curr_rpm / baseline_used

            total_reqs = r.requests or 0
            throttle_rate = (r.throttled or 0) / total_reqs if total_reqs else 0.0
            block_rate = (r.blocked or 0) / total_reqs if total_reqs else 0.0
            avg_risk = r.avg_risk or 0.0

            severity = "NORMAL"
            color = "green"
            summary_parts = []

            is_high_risk = avg_risk >= 0.7
            is_high_traffic = multiplier >= 4.0 and curr_rpm > 10
            is_elevated_traffic = multiplier >= 2.0 and curr_rpm > 5
            is_throttling = throttle_rate > 0.1

            if is_throttling:
                severity = "HIGH"
                color = "red"
                summary_parts.append(f"High throttling detected ({int(throttle_rate * 100)}%).")
            elif is_high_traffic:
                severity = "HIGH"
                color = "red"
                summary_parts.append(f"Traffic surge detected ({multiplier:.1f}x baseline).")
            elif is_high_risk:
                severity = "WATCH"
                color = "yellow"
                summary_parts.append("Elevated risk scores detected.")
            elif is_elevated_traffic:
                severity = "WATCH"
                color = "yellow"
                summary_parts.append(f"Traffic is elevated ({multiplier:.1f}x typical).")
            else:
                summary_parts.append("Traffic is within normal limits.")

            if curr_rpm > 0 and base_tod == 0:
                summary_parts.append("No historical data for this time of day.")

            securex_action = "Monitoring"
            suggested_action = None

            if severity == "HIGH":
                securex_action = "Active throttling / Rate limiting"
                suggested_action = "Check for DOS/DDOS or provision more capacity."
            elif severity == "WATCH":
                securex_action = "Enhanced Logging"
                suggested_action = "Review traffic sources."

            results.append(
                EndpointAnalysis(
                    endpoint=r.endpoint,
                    severity=severity,
                    color=color,
                    summary=" ".join(summary_parts),
                    metrics=EndpointMetrics(
                        current_rpm=round(curr_rpm, 2),
                        baseline_rpm=round(baseline_used, 2),
                        traffic_multiplier=round(multiplier, 2),
                        throttle_rate=round(throttle_rate, 2),
                        block_rate=round(block_rate, 2),
                        avg_risk_score=round(avg_risk, 2),
                    ),
                    securex_action=securex_action,
                    suggested_action=suggested_action,
                )
            )

        return EndpointAnalysisResponse(
            generated_at=now,
            endpoints=results,
        )

    except Exception:
        # Fallback to empty list so dashboard never 500s
        return EndpointAnalysisResponse(
            generated_at=datetime.utcnow(),
            endpoints=[],
        )
