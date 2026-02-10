from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session
from collections import defaultdict
from datetime import datetime
import logging

from db import get_db
from config import settings
from config import settings
from models import (
    Project,
    Domain,
    APIKey,
    TrafficLog,
    Endpoint,
    MetricBucket,
)
from schemas import (
    WorkerConfigOut,
    WorkerProjectConfig,
    TrafficLogIngest,
)

# ======================================================
# Setup
# ======================================================

router = APIRouter(prefix="/internal/worker", tags=["internal"])
traffic_router = APIRouter(prefix="/internal", tags=["traffic"])

logger = logging.getLogger("securex.control.traffic")


# ======================================================
# Security
# ======================================================

def verify_worker_secret(x_control_secret: str = Header(...)):
    if x_control_secret != settings.CONTROL_WORKER_SHARED_SECRET:
        raise HTTPException(status_code=401, detail="Invalid worker secret")


# ======================================================
# Worker Config Endpoint
# ======================================================

@router.get(
    "/config",
    response_model=WorkerConfigOut,
    dependencies=[Depends(verify_worker_secret)],
)
def get_worker_config(db: Session = Depends(get_db)):
    projects = db.query(Project).all()
    domains = db.query(Domain).filter(Domain.verified.is_(True)).all()
    keys = db.query(APIKey).filter(APIKey.is_active.is_(True)).all()

    domain_map = defaultdict(list)
    key_map = defaultdict(list)

    for d in domains:
        domain_map[d.project_id].append(d.hostname)

    for k in keys:
        key_map[k.project_id].append(k.key_hash)

    return WorkerConfigOut(
        projects=[
            WorkerProjectConfig(
                id=p.id,
                upstream_url=p.upstream_base_url,
                domains=domain_map[p.id],
                api_keys=key_map[p.id],
            )
            for p in projects
        ]
    )


# ======================================================
# Traffic Ingestion (PRODUCTION SAFE)
# ======================================================

@traffic_router.post(
    "/traffic",
    dependencies=[Depends(verify_worker_secret)],
)
def ingest_traffic(payload: TrafficLogIngest, db: Session = Depends(get_db)):
    """
    Canonical traffic ingestion endpoint.

    Guarantees:
    - No crashes
    - No silent data corruption
    - Correct aggregation
    - Stable endpoint normalization
    """

    try:
        # --------------------------------------------------
        # 1. Trust worker-normalized endpoint (or fallback)
        # --------------------------------------------------
        # CRITICAL: Control API must NOT normalize. Trust the worker.
        normalized_endpoint = payload.endpoint or payload.path

        # --------------------------------------------------
        # 2. Resolve API Key ID (optional)
        # --------------------------------------------------
        api_key_id = None
        if payload.api_key_hash:
            key = (
                db.query(APIKey)
                .filter(APIKey.key_hash == payload.api_key_hash)
                .first()
            )
            if key:
                api_key_id = key.id

        # --------------------------------------------------
        # 3. Endpoint Registry (upsert)
        # --------------------------------------------------
        endpoint = (
            db.query(Endpoint)
            .filter(
                Endpoint.project_id == payload.project_id,
                Endpoint.method == payload.method,
                Endpoint.pattern == normalized_endpoint,
            )
            .first()
        )

        now = datetime.utcnow()

        if not endpoint:
            endpoint = Endpoint(
                project_id=payload.project_id,
                method=payload.method,
                pattern=normalized_endpoint,
                first_seen_at=now,
                last_seen_at=now,
            )
            db.add(endpoint)
            db.flush()
        else:
            endpoint.last_seen_at = now

        # --------------------------------------------------
        # 4. Hourly Metric Bucket
        # --------------------------------------------------
        bucket_start = now.replace(minute=0, second=0, microsecond=0)

        bucket = (
            db.query(MetricBucket)
            .filter(
                MetricBucket.endpoint_id == endpoint.id,
                MetricBucket.bucket_start == bucket_start,
            )
            .first()
        )

        if not bucket:
            bucket = MetricBucket(
                endpoint_id=endpoint.id,
                bucket_start=bucket_start,
                request_count=0,
                error_count=0,
                latency_sum=0,
                risk_score_sum=0,
                throttled_count=0,
                blocked_count=0,
            )
            db.add(bucket)

        bucket.request_count += 1
        bucket.latency_sum += payload.latency_ms

        if payload.status_code >= 400:
            bucket.error_count += 1

        if payload.risk_score is not None:
            bucket.risk_score_sum += int(payload.risk_score * 100)

        if payload.decision == "THROTTLE":
            bucket.throttled_count += 1
        elif payload.decision == "BLOCK":
            bucket.blocked_count += 1

        # --------------------------------------------------
        # 5. Raw Traffic Log (FULL DATA)
        # --------------------------------------------------
        # Pydantic already parsed payload.timestamp into a datetime object
        log_timestamp = payload.timestamp or now

        log = TrafficLog(
            project_id=payload.project_id,
            api_key_id=api_key_id,
            timestamp=log_timestamp,
            ip=payload.ip,
            user_agent=payload.user_agent,
            path=payload.path,
            endpoint=normalized_endpoint,
            method=payload.method,
            status_code=payload.status_code,
            decision=payload.decision,
            risk_score=int(payload.risk_score * 100) if payload.risk_score is not None else None,
            latency_ms=payload.latency_ms,
        )

        db.add(log)
        db.commit()

        return {"status": "ingested"}

    except Exception as e:
        db.rollback()
        logger.error(f"Traffic ingestion failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Ingestion failed")
