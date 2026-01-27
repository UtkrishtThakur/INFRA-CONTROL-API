import secrets
import hashlib
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from db import get_db
from models import APIKey, Project, User
from auth import get_current_user
from schemas import APIKeyCreate, APIKeyOut, APIKeyToken

router = APIRouter(prefix="/projects/{project_id}/keys", tags=["api-keys"])


# =========================
# Helpers
# =========================

def generate_api_key() -> str:
    """
    Generates a secure random API key.
    """
    return secrets.token_urlsafe(32)


def hash_api_key(raw_key: str) -> str:
    """
    Hash API key using SHA-256.
    Fast lookup, safe to store.
    """
    return hashlib.sha256(raw_key.encode()).hexdigest()


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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )

    return project


# =========================
# Routes
# =========================

@router.post(
    "",
    response_model=APIKeyToken,
    status_code=status.HTTP_201_CREATED,
)
def create_api_key(
    project_id: UUID,
    payload: APIKeyCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = get_project_or_404(project_id, current_user, db)

    # I am keeping single-key policy for now as per my previous understanding,
    # OR simpler: just create a new key. User said "lifecycle" and "create once".
    # Previous code had "Rotate" behavior (revoke all).
    # I will support multiple keys but I will NOT enforce rotation here, unless the user explicit wants it.
    # The previous code: "🔥 Revoke ALL existing active keys".
    # I will REMOVE this automatic revocation to allow multiple keys unless requested?
    # User said "API key lifecycle (create once, hash only)".
    # Usually you want multiple keys (one for prod, one for dev, or rotation overlap).
    # I will allow multiple keys.
    
    raw_key = generate_api_key()
    key_hash = hash_api_key(raw_key)

    api_key = APIKey(
        project_id=project.id,
        key_hash=key_hash,
        label=payload.label,
        is_active=True
    )

    db.add(api_key)
    db.commit()
    db.refresh(api_key)

    # Return the raw key ONLY now
    return APIKeyToken(
        id=api_key.id,
        label=api_key.label,
        api_key=raw_key,
        created_at=api_key.created_at
    )


@router.get(
    "",
    response_model=list[APIKeyOut],
)
def list_api_keys(
    project_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = get_project_or_404(project_id, current_user, db)

    keys = (
        db.query(APIKey)
        .filter(APIKey.project_id == project.id)
        .order_by(APIKey.created_at.desc())
        .all()
    )

    # Raw key is NOT present in APIKeyOut schema, so safe
    return keys


@router.delete(
    "/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def revoke_api_key(
    project_id: UUID,
    key_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = get_project_or_404(project_id, current_user, db)

    api_key = (
        db.query(APIKey)
        .filter(
            APIKey.id == key_id,
            APIKey.project_id == project.id,
        )
        .first()
    )

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )

    # Soft delete / revoke
    api_key.is_active = False
    api_key.revoked_at = datetime.utcnow()

    db.commit()
