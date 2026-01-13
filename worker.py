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


@router.post("/traffic/ingest", dependencies=[Depends(verify_worker_secret)])
def ingest_traffic(payload: dict = Body(...), db: Session = Depends(get_db)):
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
