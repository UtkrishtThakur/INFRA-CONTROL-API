"""
Metrics & Analytics endpoints for SecureX Control API.

RULES:
- TrafficLog.endpoint may contain raw paths
- utils.normalize_path() is the ONLY normalization source
- Dashboard must NEVER show dynamic raw endpoints
- All aggregation happens on normalized endpoint
"""

from datetime import datetime, timedelta
from uuid import UUID
from collections import defaultdict

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
from utils import normalize_path

router = APIRouter(prefix="/projects", tags=["metrics"])


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def get_project_or_404(
    project_id: UUID,
    user: User,
    db: Session,
) -> Project:
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


# ─────────────────────────────────────────────
# Endpoint Analysis
# ─────────────────────────────────────────────

@router.get(
    "/{project_id}/endpoint-analysis",
    response_model=EndpointAnalysisResponse,
)
def endpoint_analysis(
    project_id: UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    project = get_project_or_404(project_id, user, db)

    now = datetime.utcnow()
    last_5m = now - timedelta(minutes=5)
    last_7d = now - timedelta(days=7)
    current_hour = now.hour

    # ─────────────────────────────────────────────
    # 1. Fetch Raw Traffic (last 5 minutes)
    # ─────────────────────────────────────────────

    raw_rows = (
        db.query(TrafficLog)
        .filter(
            TrafficLog.project_id == project.id,
            TrafficLog.created_at >= last_5m,
        )
        .all()
    )

    # ─────────────────────────────────────────────
    # 2. Normalize + Aggregate In Memory
    # ─────────────────────────────────────────────

    current_stats = defaultdict(lambda: {
        "requests": 0,
        "avg_risk_total": 0.0,
        "throttled": 0,
        "blocked": 0,
    })

    for row in raw_rows:
        normalized = normalize_path(row.endpoint)

        stats = current_stats[normalized]
        stats["requests"] += 1
        stats["avg_risk_total"] += float(row.risk_score or 0)

        if row.decision == "THROTTLE":
            stats["throttled"] += 1
        if row.decision == "BLOCK":
            stats["blocked"] += 1

    # finalize averages
    for endpoint, stats in current_stats.items():
        if stats["requests"] > 0:
            stats["avg_risk"] = stats["avg_risk_total"] / stats["requests"]
        else:
            stats["avg_risk"] = 0.0

    # ─────────────────────────────────────────────
    # 3. Historical Baseline (7-day RPM)
    # ─────────────────────────────────────────────

    hist_rows = (
        db.query(
            MetricBucket.endpoint_id,
            func.sum(MetricBucket.request_count).label("total"),
        )
        .join(Endpoint)
        .filter(
            Endpoint.project_id == project.id,
            MetricBucket.bucket_start >= last_7d,
        )
        .group_by(MetricBucket.endpoint_id)
        .all()
    )

    endpoint_ids = {
        e.id: e.pattern
        for e in db.query(Endpoint)
        .filter(Endpoint.project_id == project.id)
        .all()
    }

    minutes_7d = 7 * 24 * 60

    hist_rpm = {
        endpoint_ids[row.endpoint_id]: (row.total or 0) / minutes_7d
        for row in hist_rows
        if row.endpoint_id in endpoint_ids
    }

    # ─────────────────────────────────────────────
    # 4. Time-of-Day Baseline
    # ─────────────────────────────────────────────

    tod_rows = (
        db.query(
            MetricBucket.endpoint_id,
            func.sum(MetricBucket.request_count).label("total"),
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
        endpoint_ids[row.endpoint_id]: (row.total or 0) / minutes_tod
        for row in tod_rows
        if row.endpoint_id in endpoint_ids
    }

    # ─────────────────────────────────────────────
    # 5. Combine All Normalized Endpoints
    # ─────────────────────────────────────────────

    all_patterns = set(current_stats.keys()) | set(hist_rpm.keys())

    results = []

    for pattern in all_patterns:
        curr = current_stats.get(pattern, {})

        requests = curr.get("requests", 0)
        throttled = curr.get("throttled", 0)
        blocked = curr.get("blocked", 0)
        avg_risk = curr.get("avg_risk", 0)

        curr_rpm = requests / 5.0
        throttle_rate = throttled / requests if requests else 0.0
        block_rate = blocked / requests if requests else 0.0

        baseline = tod_rpm.get(pattern, hist_rpm.get(pattern, 0.0))
        baseline = max(baseline, 0.1)

        multiplier = curr_rpm / baseline

        severity = "NORMAL"
        color = "green"
        notes = []

        if throttle_rate > 0.1:
            severity, color = "HIGH", "red"
            notes.append(f"High throttling ({int(throttle_rate * 100)}%).")
        elif multiplier >= 4 and curr_rpm > 10:
            severity, color = "HIGH", "red"
            notes.append(f"Traffic spike ({multiplier:.1f}× baseline).")
        elif avg_risk >= 0.7:
            severity, color = "WATCH", "yellow"
            notes.append("Elevated risk scores.")
        elif multiplier >= 2 and curr_rpm > 5:
            severity, color = "WATCH", "yellow"
            notes.append(f"Traffic elevated ({multiplier:.1f}× baseline).")

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
                    baseline_rpm=round(baseline, 2),
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
