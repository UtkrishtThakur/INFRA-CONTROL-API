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


    db.add(TrafficLog(
        project_id=payload["project_id"],
        api_key_id=payload.get("api_key_id"),
        ip=payload["ip"],
        path=payload["path"],
        endpoint=payload["normalized_path"],
        method=payload["method"],
        status_code=payload["status_code"],
        decision=payload["decision"],
        risk_score=payload.get("risk_score"),
        latency_ms=payload.get("latency_ms"),
    ))
    db.commit()
    return {"status": "ok"}


# Separate router for strict path "/internal/traffic"
traffic_router = APIRouter(prefix="/internal", tags=["traffic"])

from schemas import TrafficLogIngest
import logging

@traffic_router.post("/traffic", dependencies=[Depends(verify_worker_secret)])
def ingest_traffic_v2(payload: TrafficLogIngest, db: Session = Depends(get_db)):
    """
    Production-safe traffic ingestion.
    Never returns 500. Logs errors and returns 200.
    """
    try:
        # 1. Map endpoint (canonical) vs path (raw)
        # If worker didn't normalize, fallback to raw path
        final_endpoint = payload.normalized_path or payload.path

        # 2. Create Record
        log_entry = TrafficLog(
            project_id=payload.project_id,
            # Note: api_key_hash is passed, but DB needs api_key_id. 
            # We skip looking up ID for speed/safety if schema doesn't match?
            # Wait, TrafficLog has api_key_id (FK). 
            # The payload has api_key_hash.
            # If we don't look it up, we need to allow null or change logic.
            # Old code: api_key_id=payload.get("api_key_id"). 
            # But payload description says "api_key_hash".
            # The worker must be sending api_key_id or the hash?
            # User request: "api_key_hash (string)".
            # DB has "api_key_id".
            # If I try to insert hash into UUID column => CRASH.
            # So I MUST lookup the key or ignore it?
            # The User Request didn't specify looking it up, but "api_key_hash" implies I need to find the ID.
            # HOWEVER, for "Do NOT crash", if I can't find it, I should null it.
            # Let's try to lookup ONLY if provided.
            
            # actually, let's verify what the old code did.
            # Old code: api_key_id=payload.get("api_key_id")
            # So old worker sent ID. New worker sends HASH?
            # I'll stick to robust behavior:
            # If I can't easily map it, I'll leave it NULL to avoid crashing.
            
            # WAIT, if I am "Hardening", correctly linking API keys is important.
            # But "metrics endpoints never 500". This is ingestion.
            # "Produce-stable".
            # I will attempt to look up API Key by hash if provided.
            
            ip=payload.ip,
            path=payload.path,
            endpoint=final_endpoint,
            method=payload.method,
            status_code=payload.status_code,
            decision=payload.decision,
            risk_score=payload.risk_score,
            latency_ms=payload.latency_ms,
            # timestamp defaults to now() in DB
        )
        
        # Resolve API Key ID if hash provided
        if payload.api_key_hash:
             # Fast lookup
             # We need to import APIKey model? It is imported.
             key_obj = db.query(APIKey).filter(APIKey.key_hash == payload.api_key_hash).first()
             if key_obj:
                 log_entry.api_key_id = key_obj.id

        db.add(log_entry)
        db.commit()
        return {"status": "ingested"}

    except Exception as e:
        # PRODUCTION SAFETY: Log error, swallow exception, return 200
        # In a real app, use logger.exception(e) or sentry
        print(f"CRITICAL: Traffic ingestion failed: {e}")
        return {"status": "ignored_error"}
