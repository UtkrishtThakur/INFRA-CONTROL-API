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

@traffic_router.post("/traffic", dependencies=[Depends(verify_worker_secret)])
def ingest_traffic_v2(payload: TrafficLogIngest, db: Session = Depends(get_db)):
    """
    Production-safe traffic ingestion.
    
    GUARANTEES:
    - Never returns 500
    - Logs errors but swallows exceptions
    - Always returns 200 with status indicator
    
    SCHEMA ALIGNMENT:
    - Uses 'endpoint' field (canonical path) matching DB column
    - Falls back to 'path' if endpoint not provided
    """
    try:
        # ───── 1. Determine canonical endpoint ─────
        # 'endpoint' is normalized/canonical path stored in DB
        # 'path' is raw request path
        # If worker didn't provide endpoint, use raw path as fallback
        final_endpoint = payload.endpoint or payload.path

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
                # If lookup fails, continue without linking key
                logger.warning(f"API key lookup failed: {lookup_err}")

        # ───── 3. Create Traffic Log Record ─────
        log_entry = TrafficLog(
            project_id=payload.project_id,
            api_key_id=api_key_id,  # NULL if not found/provided
            ip=payload.ip,
            path=payload.path,               # Raw path
            endpoint=final_endpoint,         # Canonical path (DB column)
            method=payload.method,
            status_code=payload.status_code,
            decision=payload.decision,
            risk_score=payload.risk_score,
            latency_ms=payload.latency_ms,
            # created_at defaults to now() in DB
        )

        db.add(log_entry)
        db.commit()
        
        return {"status": "ingested"}

    except Exception as e:
        # ───── PRODUCTION SAFETY: NEVER CRASH ─────
        # Rollback transaction to prevent partial writes
        try:
            db.rollback()
        except:
            pass
        
        # Log error for debugging (use structured logging in production)
        logger.error(f"Traffic ingestion failed: {e}", exc_info=True)
        
        # Return success status to prevent worker retries
        return {"status": "error_ignored", "error": str(e)}
