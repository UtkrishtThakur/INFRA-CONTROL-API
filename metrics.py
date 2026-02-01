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


# ─────────────────────────────────────────────────────────────
# Endpoint Analysis
# ─────────────────────────────────────────────────────────────

@router.get(
    "/{project_id}/endpoint-analysis",
    response_model=EndpointAnalysisResponse,
)
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

        # ───── STRATEGY ─────
        # 1. Get ALL registered endpoints (ensures visibility even with 0 traffic)
        # 2. Get CURRENT traffic from TrafficLogs (last 5 minutes)
        # 3. Get HISTORICAL traffic from MetricBuckets (aggregated)

        # ─────────────────────────────────────────────
        # 1. Endpoint Registry
        # ─────────────────────────────────────────────

        endpoints = (
            db.query(Endpoint)
            .filter(Endpoint.project_id == project.id)
            .all()
        )

        # pattern -> Endpoint
        endpoint_map = {e.pattern: e for e in endpoints}

        # endpoint_id -> pattern
        id_to_pattern = {e.id: e.pattern for e in endpoints}

        # ─────────────────────────────────────────────
        # 2. Current Traffic (Last 5 minutes)
        # ─────────────────────────────────────────────

        current_data = (
            db.query(
                TrafficLog.endpoint,
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
                TrafficLog.created_at >= last_5m,
            )
            .group_by(TrafficLog.endpoint)
            .all()
        )

        # endpoint pattern -> stats
        curr_stats = {}

        for row in current_data:
            curr_stats[row.endpoint] = {
                "requests": row.requests or 0,
                "avg_risk": row.avg_risk or 0,
                "throttled": row.throttled or 0,
                "blocked": row.blocked or 0,
            }

        # ─────────────────────────────────────────────
        # 3. Historical Baseline (7-day global average)
        # ─────────────────────────────────────────────

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

        minutes_in_7d = 7 * 24 * 60
        hist_rpm_map = {}

        for row in hist_data:
            pattern = id_to_pattern.get(row.endpoint_id)
            if pattern:
                hist_rpm_map[pattern] = (row.total_reqs or 0) / minutes_in_7d

        # ─────────────────────────────────────────────
        # 4. Time-of-Day Baseline (same hour, last 7 days)
        # ─────────────────────────────────────────────

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

        minutes_in_tod = 7 * 60
        tod_rpm_map = {}

        for row in tod_data:
            pattern = id_to_pattern.get(row.endpoint_id)
            if pattern:
                tod_rpm_map[pattern] = (row.total_reqs or 0) / minutes_in_tod

        # ─────────────────────────────────────────────
        # 5. Assemble Results
        # ─────────────────────────────────────────────

        results = []

        for pattern, ep_obj in endpoint_map.items():
            c = curr_stats.get(pattern, {})

            requests = c.get("requests", 0)
            curr_rpm = requests / 5.0

            throttled = c.get("throttled", 0)
            blocked = c.get("blocked", 0)
            avg_risk = c.get("avg_risk", 0)

            throttle_rate = throttled / requests if requests else 0.0
            block_rate = blocked / requests if requests else 0.0

            base_rpm = tod_rpm_map.get(
                pattern,
                hist_rpm_map.get(pattern, 0),
            )
            base_rpm = max(base_rpm, 0.1)

            multiplier = curr_rpm / base_rpm

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

            if not notes:
                if requests == 0:
                    notes.append("No active traffic.")
                else:
                    notes.append("Traffic within normal range.")

            results.append(
                EndpointAnalysis(
                    endpoint=pattern,
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
        # HARD FAIL-SAFE — never break dashboard
        return EndpointAnalysisResponse(
            generated_at=datetime.utcnow(),
            endpoints=[],
        )
