from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session
from collections import defaultdict

from db import get_db
from config import settings
from models import Project, Domain, APIKey
from schemas import WorkerConfigOut, WorkerProjectConfig

router = APIRouter(
    prefix="/internal/worker",
    tags=["internal"],
)

# =========================
# Internal auth (worker)
# =========================

def verify_worker_secret(
    x_control_secret: str = Header(...)
):
    if x_control_secret != settings.CONTROL_WORKER_SHARED_SECRET:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid worker secret",
        )


# =========================
# Worker config endpoint
# =========================

@router.get(
    "/config",
    response_model=WorkerConfigOut,
    dependencies=[Depends(verify_worker_secret)],
)
def get_worker_config(
    db: Session = Depends(get_db),
):
    projects = db.query(Project).all()

    domains = (
        db.query(Domain)
        .filter(Domain.verified.is_(True))
        .all()
    )

    keys = (
        db.query(APIKey)
        .filter(APIKey.is_active.is_(True))
        .all()
    )

    project_domains = defaultdict(list)
    for d in domains:
        project_domains[d.project_id].append(d.hostname)

    project_keys = defaultdict(list)
    for k in keys:
        project_keys[k.project_id].append(k.key_hash)

    result = []
    for p in projects:
        result.append(
            WorkerProjectConfig(
                id=p.id,
                upstream_url=p.upstream_base_url,
                domains=project_domains[p.id],
                api_keys=project_keys[p.id],
            )
        )

    return WorkerConfigOut(projects=result)
