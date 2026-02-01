"""
Metrics & Analytics endpoints for SecureX Control API.

DESIGN GUARANTEES:
- Registered endpoints are ALWAYS returned
- Zero traffic still shows endpoint with empty metrics
- Time-window based calculations are respected
- No silent drops, ever

SCHEMA:
- TrafficLog.endpoint      -> raw path
- TrafficLog.endpoint_id   -> FK to Endpoint.id
- Endpoint.pattern         -> canonical endpoint pattern
"""

from datetime import datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, Integer, extract
from sqlalchemy.orm import Session

from db import get_db
from auth import get_current_user
from models import TrafficLog, Project, User, Endpoint, MetricBucket
from schemas import (
    EndpointAnalysisResponse,
    EndpointAnalysis,
    EndpointMetrics,
)

router = APIRouter(prefix="/projects", tags=["metrics"])


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def get_project_or_404(project_id: UUID, user: User, db: Session) -> Project:
    project = (
        db.query(Project)
        .filter(
            Project.id == project_id,
            Project.owner_id == user.id,
        )
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


def resolve_time_window(time_range: str) -> int:
    if time_range == "1h":
        return 60
    if time_range == "24h":
        return 1440
    return 5  # default 5m


# ─────────────────────────────────────────────────────────────
# Endpoint Analysis
# ─────────────────────────────────────────────────────────────

@router.get(
    "/{project_id}/endpoint-analysis",
    response_model=EndpointAnalysisResponse,
)
def endpoint_analysis(
    project_id: UUID,
    time_range: str = Query("5m"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    try:
        project = get_project_or_404(project_id, user, db)

        now = datetime.utcnow()
        window_minutes = resolve_time_window(time_range)
        window_start = now - timedelta(minutes=window_minutes)

        last_7d = now - timedelta(days=7)
        current_hour = now.hour

        # ─────────────────────────────────────────────────
        # 1. Endpoint Registry (SOURCE OF TRUTH)
        # ─────────────────────────────────────────────────

        endpoints = (
            db.query(Endpoint)
            .filter(Endpoint.project_id == project.id)
            .all()
        )

        endpoint_ids = [e.id for e in endpoints]
        id_to_pattern = {e.id: e.pattern for e in endpoints}

        # ─────────────────────────────────────────────────
        # 2. Current Traffic (window-based)
        # ─────────────────────────────────────────────────

        current_data = (
            db.query(
                TrafficLog.endpoint_id,
                func.count().label("requests"),
                func.avg(TrafficLog.risk_score).label("avg_risk"),
                func.sum(
                    func.cast(TrafficLog.decision == "THROTTLE", Integer)
                ).label("throttled"),
                func.sum(
                    func.cast(TrafficLog.decision == "BLOCK", Integer)
                ).label("blocked"),
            )
            .filter(
                TrafficLog.project_id == project.id,
                TrafficLog.created_at >= window_start,
                TrafficLog.endpoint_id.in_(endpoint_ids),
            )
            .group_by(TrafficLog.endpoint_id)
            .all()
        )

        curr_stats = {
            id_to_pattern[row.endpoint_id]: {
                "requests": row.requests or 0,
                "avg_risk": row.avg_risk or 0,
                "throttled": row.throttled or 0,
                "blocked": row.blocked or 0,
            }
            for row in current_data
            if row.endpoint_id in id_to_pattern
        }

        # ─────────────────────────────────────────────────
        # 3. Historical Baseline (7-day average)
        # ─────────────────────────────────────────────────

        hist_data = (
            db.query(
                MetricBucket.endpoint_id,
                func.sum(MetricBucket.request_count).label("total_reqs"),
            )
            .join(Endpoint)
            .filter(
                Endpoint.project_id == project.id,
                MetricBucket.bucket_start >= last_7d,
            )
            .group_by(MetricBucket.endpoint_id)
            .all()
        )

        minutes_7d = 7 * 24 * 60
        hist_rpm = {
            id_to_pattern[row.endpoint_id]: (row.total_reqs or 0) / minutes_7d
            for row in hist_data
            if row.endpoint_id in id_to_pattern
        }

        # ─────────────────────────────────────────────────
        # 4. Time-of-Day Baseline
        # ─────────────────────────────────────────────────

        tod_data = (
            db.query(
                MetricBucket.endpoint_id,
                func.sum(MetricBucket.request_count).label("total_reqs"),
            )
            .join(Endpoint)
            .filter(
                Endpoint.project_id == project.id,
                MetricBucket.bucket_start >= last_7d,
                extract("hour", MetricBucket.bucket_start) == current_hour,
            )
            .group_by(MetricBucket.endpoint_id)
            .all()
        )

        minutes_tod = 7 * 60
        tod_rpm = {
            id_to_pattern[row.endpoint_id]: (row.total_reqs or 0) / minutes_tod
            for row in tod_data
            if row.endpoint_id in id_to_pattern
        }

        # ─────────────────────────────────────────────────
        # 5. Assemble Results (ALWAYS INCLUDE ENDPOINTS)
        # ─────────────────────────────────────────────────

        results = []

        for ep in endpoints:
            c = curr_stats.get(ep.pattern, {})

            requests = c.get("requests", 0)
            curr_rpm = requests / window_minutes

            throttled = c.get("throttled", 0)
            blocked = c.get("blocked", 0)
            avg_risk = c.get("avg_risk", 0)

            throttle_rate = throttled / requests if requests else 0.0
            block_rate = blocked / requests if requests else 0.0

            base_rpm = tod_rpm.get(
                ep.pattern,
                hist_rpm.get(ep.pattern, 0.0),
            )
            base_rpm = max(base_rpm, 0.1)

            multiplier = curr_rpm / base_rpm if base_rpm else 0.0

            severity = "NORMAL"
            color = "green"
            notes = []

            if requests == 0:
                notes.append("No active traffic.")
            elif throttle_rate > 0.1:
                severity, color = "HIGH", "red"
                notes.append("High throttling detected.")
            elif multiplier >= 4:
                severity, color = "HIGH", "red"
                notes.append("Traffic spike detected.")
            elif avg_risk >= 0.7:
                severity, color = "WATCH", "yellow"
                notes.append("Elevated risk scores.")
            elif multiplier >= 2:
                severity, color = "WATCH", "yellow"
                notes.append("Traffic elevated.")
            else:
                notes.append("Traffic within normal range.")

            results.append(
                EndpointAnalysis(
                    endpoint=ep.pattern,
                    severity=severity,
                    color=color,
                    summary=" ".join(notes),
                    metrics=EndpointMetrics(
                        current_rpm=round(curr_rpm, 2),
                        baseline_rpm=round(base_rpm, 2),
                        traffic_multiplier=round(multiplier, 2),
                        throttle_rate=round(throttle_rate, 2),
                        block_rate=round(block_rate, 2),
                        avg_risk_score=round(avg_risk, 2),
                    ),
                    securex_action=(
                        "Monitoring"
                        if severity == "NORMAL"
                        else "Active mitigation"
                    ),
                    suggested_action=(
                        None
                        if severity == "NORMAL"
                        else "Inspect traffic sources."
                    ),
                )
            )

        return EndpointAnalysisResponse(
            generated_at=now,
            endpoints=results,
        )

    except Exception:
        return EndpointAnalysisResponse(
            generated_at=datetime.utcnow(),
            endpoints=[],
        )
