import secrets
import dns.resolver
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from db import get_db
from auth import get_current_user
from models import Domain, Project, User
from schemas import (
    DomainCreate,
    DomainOut,
    DomainVerificationInfo,
    DomainVerifyResponse,
)

router = APIRouter(prefix="/projects/{project_id}/domains", tags=["domains"])


# =========================
# Helpers
# =========================

def generate_verification_token() -> str:
    return secrets.token_urlsafe(32)


def verify_domain_dns(hostname: str, token: str) -> bool:
    """
    Verifies:
    TXT _gateway.<hostname>
    value = gateway-verification=<token>
    """
    record = f"_gateway.{hostname}"
    expected = f"gateway-verification={token}"

    try:
        answers = dns.resolver.resolve(record, "TXT")
    except Exception:
        return False

    for rdata in answers:
        # rdata.strings is a list of byte-strings because TXT records can be chunked
        # we join them to get the full string
        value = "".join(part.decode() for part in rdata.strings)
        if value == expected:
            return True

    return False


def get_project_owner_check(db: Session, project_id: UUID, user_id: UUID) -> Project:
    project = (
        db.query(Project)
        .filter(Project.id == project_id, Project.owner_id == user_id)
        .first()
    )
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    return project

def get_domain_or_404(db: Session, domain_id: UUID, project_id: UUID) -> Domain:
    domain = (
        db.query(Domain)
        .filter(Domain.id == domain_id, Domain.project_id == project_id)
        .first()
    )
    if not domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )
    return domain


# =========================
# Routes
# =========================

@router.post("", response_model=DomainOut, status_code=status.HTTP_201_CREATED)
def add_domain(
    project_id: UUID,
    payload: DomainCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = get_project_owner_check(db, project_id, current_user.id)

    # Check globally unique hostname
    existing = db.query(Domain).filter(Domain.hostname == payload.hostname).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Domain already in use by another project",
        )

    token = generate_verification_token()
    domain = Domain(
        project_id=project.id,
        hostname=payload.hostname,
        verification_token=token,
    )
    db.add(domain)
    db.commit()
    db.refresh(domain)

    return DomainOut(
        id=domain.id,
        hostname=domain.hostname,
        verified=domain.verified,
        created_at=domain.created_at,
        verification=DomainVerificationInfo(
            type="TXT",
            host=f"_gateway.{domain.hostname}",
            value=f"gateway-verification={token}",
        )
    )


@router.get("", response_model=list[DomainOut])
def list_domains(
    project_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = get_project_owner_check(db, project_id, current_user.id)
    domains = (
        db.query(Domain)
        .filter(Domain.project_id == project.id)
        .order_by(Domain.created_at.desc())
        .all()
    )
    
    # Map to schema manually or let pydantic handle it
    # We need to construct the verification info dynamically if not verified
    results = []
    for d in domains:
        info = None
        if not d.verified:
            info = DomainVerificationInfo(
                type="TXT",
                host=f"_gateway.{d.hostname}",
                value=f"gateway-verification={d.verification_token}",
            )
        
        results.append(DomainOut(
            id=d.id,
            hostname=d.hostname,
            verified=d.verified,
            created_at=d.created_at,
            verified_at=d.verified_at,
            verification=info
        ))
    return results


@router.get("/{domain_id}", response_model=DomainOut)
def get_domain(
    project_id: UUID,
    domain_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    get_project_owner_check(db, project_id, current_user.id)
    d = get_domain_or_404(db, domain_id, project_id)

    info = None
    if not d.verified:
        info = DomainVerificationInfo(
            type="TXT",
            host=f"_gateway.{d.hostname}",
            value=f"gateway-verification={d.verification_token}",
        )

    return DomainOut(
        id=d.id,
        hostname=d.hostname,
        verified=d.verified,
        created_at=d.created_at,
        verified_at=d.verified_at,
        verification=info
    )


@router.post("/{domain_id}/verify", response_model=DomainVerifyResponse)
def verify_domain(
    project_id: UUID,
    domain_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    get_project_owner_check(db, project_id, current_user.id)
    domain = get_domain_or_404(db, domain_id, project_id)

    if domain.verified:
        return DomainVerifyResponse(verified=True)

    if not verify_domain_dns(domain.hostname, domain.verification_token):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="DNS verification failed",
        )

    domain.verified = True
    domain.verified_at = datetime.utcnow()
    db.commit()

    return DomainVerifyResponse(verified=True)


@router.delete("/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_domain(
    project_id: UUID,
    domain_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    get_project_owner_check(db, project_id, current_user.id)
    domain = get_domain_or_404(db, domain_id, project_id)
    
    db.delete(domain)
    db.commit()
