from datetime import datetime
from typing import Optional, List, Dict
from uuid import UUID

from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: UUID
    email: EmailStr
    created_at: datetime

    class Config:
        from_attributes = True


class ProjectCreate(BaseModel):
    name: str
    upstream_base_url: str


class ProjectOut(BaseModel):
    id: UUID
    name: str
    upstream_base_url: str
    created_at: datetime

    class Config:
        from_attributes = True


class APIKeyCreate(BaseModel):
    label: Optional[str] = None


class APIKeyToken(BaseModel):
    """Returned ONLY once upon creation"""
    id: UUID
    label: Optional[str]
    api_key: str
    created_at: datetime

class APIKeyOut(BaseModel):
    """Safe representation of an API Key (no raw secret)"""
    id: UUID
    label: Optional[str]
    is_active: bool
    created_at: datetime
    # NO RAW KEY HERE

    class Config:
        from_attributes = True


class DomainCreate(BaseModel):
    hostname: str


class DomainVerificationInfo(BaseModel):
    type: str
    host: str
    value: str


class DomainOut(BaseModel):
    id: UUID
    hostname: str
    verified: bool
    created_at: datetime
    verified_at: Optional[datetime] = None
    verification: Optional[DomainVerificationInfo] = None

    class Config:
        from_attributes = True


class DomainVerifyResponse(BaseModel):
    verified: bool


# =========================
# Worker Schemas
# =========================

class WorkerProjectConfig(BaseModel):
    id: UUID
    upstream_url: str
    domains: List[str]
    api_keys: List[str]  # List of HASHES

class WorkerConfigOut(BaseModel):
    projects: List[WorkerProjectConfig]
