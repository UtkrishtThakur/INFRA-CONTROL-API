from fastapi import APIRouter, Depends, Header, HTTPException, Body
from sqlalchemy.orm import Session
from collections import defaultdict

from db import get_db
from config import settings
from models import Project, Domain, APIKey, TrafficLog
from schemas import WorkerConfigOut, WorkerProjectConfig

router = APIRouter(prefix="/internal/worker", tags=["internal"])


def verify_worker_secret(x_control_secret: str = Header(...)):
    if x_control_secret != settings.CONTROL_WORKER_SHARED_SECRET:
        raise HTTPException(status_code=401, detail="Invalid worker secret")


@router.get("/config", response_model=WorkerConfigOut, dependencies=[Depends(verify_worker_secret)])
def get_worker_config(db: Session = Depends(get_db)):
    projects = db.query(Project).all()
    domains = db.query(Domain).filter(Domain.verified.is_(True)).all()
    keys = db.query(APIKey).filter(APIKey.is_active.is_(True)).all()

    domain_map, key_map = defaultdict(list), defaultdict(list)

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


# ═══════════════════════════════════════════════════════════════
# TRAFFIC INGESTION ENDPOINT
# ═══════════════════════════════════════════════════════════════
# Separate router for strict path "/internal/traffic"
traffic_router = APIRouter(prefix="/internal", tags=["traffic"])

from schemas import TrafficLogIngest
import logging

logger = logging.getLogger(__name__)

from datetime import datetime, timedelta
import logging

from schemas import TrafficLogIngest
from models import Project, Endpoint, MetricBucket
from utils import normalize_path

logger = logging.getLogger(__name__)

@traffic_router.post("/traffic", dependencies=[Depends(verify_worker_secret)])
def ingest_traffic_v2(payload: TrafficLogIngest, db: Session = Depends(get_db)):
    """
    Production-safe traffic ingestion v2.
    
    Includes:
    - Path Normalization
    - Endpoint Registry Upsert
    - Time-Bucket Aggregation
    - Raw Logging
    """
    try:
        # ───── 1. Normalize Path ─────
        # If worker sent 'endpoint', trust it (maybe). But here we enforce our own normalization 
        # to ensure consistency.
        normalized_pattern = normalize_path(payload.path)
        
        # ───── 2. Resolve API Key ID (if hash provided) ─────
        api_key_id = None
        if payload.api_key_hash:
            try:
                key_obj = db.query(APIKey).filter(
                    APIKey.key_hash == payload.api_key_hash
                ).first()
                if key_obj:
                    api_key_id = key_obj.id
            except Exception as lookup_err:
                logger.warning(f"API key lookup failed: {lookup_err}")

        # ───── 3. Endpoint Registry Ingestion ─────
        # Check if endpoint exists
        endpoint_obj = db.query(Endpoint).filter(
            Endpoint.project_id == payload.project_id,
            Endpoint.method == payload.method,
            Endpoint.pattern == normalized_pattern
        ).first()

        if not endpoint_obj:
            # Create new endpoint
            endpoint_obj = Endpoint(
                project_id=payload.project_id,
                method=payload.method,
                pattern=normalized_pattern,
                first_seen_at=datetime.utcnow(),
                last_seen_at=datetime.utcnow()
            )
            db.add(endpoint_obj)
            db.flush()  # to get ID
        else:
            # Update last_seen
            endpoint_obj.last_seen_at = datetime.utcnow()

        # ───── 4. Update Metric Bucket (Aggregation) ─────
        # Bucket by hour
        now = datetime.utcnow()
        bucket_start = now.replace(minute=0, second=0, microsecond=0)
        
        bucket = db.query(MetricBucket).filter(
            MetricBucket.endpoint_id == endpoint_obj.id,
            MetricBucket.bucket_start == bucket_start
        ).first()

        if not bucket:
            bucket = MetricBucket(
                endpoint_id=endpoint_obj.id,
                bucket_start=bucket_start,
                request_count=0,
                error_count=0,
                latency_sum=0,
                risk_score_sum=0,
                throttled_count=0,
                blocked_count=0
            )
            db.add(bucket)

        # Update stats
        bucket.request_count += 1
        if payload.status_code >= 400:
            bucket.error_count += 1
        bucket.latency_sum += payload.latency_ms
        if payload.risk_score:
            bucket.risk_score_sum += int(payload.risk_score * 100) # Store as int if needed, or float
        
        if payload.decision == "THROTTLE":
            bucket.throttled_count += 1
        elif payload.decision == "BLOCK":
            bucket.blocked_count += 1

        # ───── 5. Raw Traffic Log ─────
        log_entry = TrafficLog(
            project_id=payload.project_id,
            api_key_id=api_key_id,
            ip=payload.ip,
            path=payload.path,               # Raw path
            endpoint=normalized_pattern,     # Canonical path
            method=payload.method,
            status_code=payload.status_code,
            decision=payload.decision,
            risk_score=payload.risk_score,
            latency_ms=payload.latency_ms,
        )

        db.add(log_entry)
        db.commit()
        
        return {"status": "ingested", "normalized": normalized_pattern}

    except Exception as e:
        # ───── PRODUCTION SAFETY ─────
        try:
            db.rollback()
        except:
            pass
        
        logger.error(f"Traffic ingestion failed: {e}", exc_info=True)
        return {"status": "error_ignored", "error": str(e)}
