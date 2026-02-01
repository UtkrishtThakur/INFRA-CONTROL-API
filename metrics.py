"""
Metrics & Analytics endpoints for SecureX Control API.

SCHEMA ALIGNMENT:
- TrafficLog.endpoint      -> raw path (e.g. /user/123)
- TrafficLog.endpoint_id   -> FK to Endpoint.id (may be NULL for legacy logs)
- Endpoint.pattern         -> canonical pattern (e.g. /user/{id})

RULES:
- Prefer aggregation by endpoint_id
- Fallback to pattern matching on raw endpoint if endpoint_id is missing
- NEVER let metrics disappear silently
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


def normalize_fallback_path(path: str) -> str:
    """
    Best-effort fallback normalizer for raw paths.
    Converts:
      /user/123        -> /user/{id}
      /order/9f8a...   -> /order/{id}
    """
    parts = path.strip("/").split("/")
    normalized = []

    for p in parts:
        if p.isdigit() or len(p) >= 8:
            normalized.append("{id}")
        else:
            normalized.append(p)

    return "/" + "/".join(normalized)


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

        # ─────────────────────────────────────────────────
        # 1. Endpoint Registry
        # ─────────────────────────────────────────────────

        endpoints = (
            db.query(Endpoint)
            .filter(Endpoint.project_id == project.id)
            .all()
        )

        endpoint_map = {e.pattern: e for e in endpoints}
        id_to_pattern = {e.id: e.pattern for e in endpoints}

        # Always allow fallback bucket
        endpoint_map.setdefault("UNREGISTERED", None)

        # ─────────────────────────────────────────────────
        # 2. Current Traffic (last 5 minutes)
        # ─────────────────────────────────────────────────

        current_data = (
            db.query(
                TrafficLog.endpoint_id,
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
            .group_by(TrafficLog.endpoint_id, TrafficLog.endpoint)
            .all()
        )

        curr_stats = {}

        for row in current_data:
            # Prefer registered endpoint
            if row.endpoint_id and row.endpoint_id in id_to_pattern:
                pattern = id_to_pattern[row.endpoint_id]
            else:
                # Fallback normalization
                pattern = normalize_fallback_path(row.endpoint or "/unknown")
                endpoint_map.setdefault(pattern, None)

            stats = curr_stats.setdefault(
                pattern,
                {
                    "requests": 0,
                    "avg_risk_sum": 0.0,
                    "risk_count": 0,
                    "throttled": 0,
                    "blocked": 0,
                },
            )

            stats["requests"] += row.requests or 0
            if row.avg_risk is not None:
                stats["avg_risk_sum"] += row.avg_risk * (row.requests or 1)
                stats["risk_count"] += row.requests or 1
            stats["throttled"] += row.throttled or 0
            stats["blocked"] += row.blocked or 0

        # Finalize avg risk
        for stats in curr_stats.values():
            if stats["risk_count"]:
                stats["avg_risk"] = stats["avg_risk_sum"] / stats["risk_count"]
            else:
                stats["avg_risk"] = 0.0

        # ─────────────────────────────────────────────────
        # 3. Historical Baseline (registered endpoints only)
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

        minutes_in_7d = 7 * 24 * 60
        hist_rpm_map = {
            id_to_pattern[row.endpoint_id]: (row.total_reqs or 0) / minutes_in_7d
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

        minutes_in_tod = 7 * 60
        tod_rpm_map = {
            id_to_pattern[row.endpoint_id]: (row.total_reqs or 0) / minutes_in_tod
            for row in tod_data
            if row.endpoint_id in id_to_pattern
        }

        # ─────────────────────────────────────────────────
        # 5. Assemble Results
        # ─────────────────────────────────────────────────

        results = []

        for pattern in endpoint_map.keys():
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
                notes.append("High throttling detected.")
            elif multiplier >= 4 and curr_rpm > 10:
                severity, color = "HIGH", "red"
                notes.append("Traffic spike detected.")
            elif avg_risk >= 0.7:
                severity, color = "WATCH", "yellow"
                notes.append("Elevated risk scores.")
            elif multiplier >= 2 and curr_rpm > 5:
                severity, color = "WATCH", "yellow"
                notes.append("Traffic elevated.")

            if not notes:
                notes.append(
                    "No active traffic."
                    if requests == 0
                    else "Traffic within normal range."
                )

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
        return EndpointAnalysisResponse(
            generated_at=datetime.utcnow(),
            endpoints=[],
        )
