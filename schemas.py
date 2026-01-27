from datetime import datetime
from typing import Optional, List
from uuid import UUID

from pydantic import BaseModel, EmailStr

# =========================
# Auth Schemas
# =========================

class UserCreate(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: UUID
    email: EmailStr
    is_verified: bool
    created_at: datetime

    class Config:
        from_attributes = True


class RegisterResponse(BaseModel):
    message: str


class EmailVerificationResponse(BaseModel):
    message: str


# =========================
# Project Schemas
# =========================

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


# =========================
# API Key Schemas
# =========================

class APIKeyCreate(BaseModel):
    label: Optional[str] = None


class APIKeyToken(BaseModel):
    """
    Returned ONLY once upon creation
    """
    id: UUID
    label: Optional[str]
    api_key: str
    created_at: datetime


class APIKeyOut(BaseModel):
    """
    Safe representation of an API Key (no raw secret)
    """
    id: UUID
    label: Optional[str]
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# =========================
# Domain Schemas
# =========================

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
    api_keys: List[str]  # HASHES only


class WorkerConfigOut(BaseModel):
    projects: List[WorkerProjectConfig]


# =========================
# Intelligence / Metrics
# =========================

class EndpointMetrics(BaseModel):
    current_rpm: float
    baseline_rpm: float
    traffic_multiplier: float
    throttle_rate: float
    block_rate: float
    avg_risk_score: Optional[float]


class EndpointAnalysis(BaseModel):
    endpoint: str
    severity: str        # NORMAL | WATCH | HIGH
    color: str           # green | yellow | red
    summary: str
    metrics: EndpointMetrics
    securex_action: str
    suggested_action: Optional[str]


class EndpointAnalysisResponse(BaseModel):
    generated_at: datetime
    endpoints: List[EndpointAnalysis]


# =========================
# Traffic Logs
# =========================

class TrafficLogIngest(BaseModel):
    """
    Traffic log ingestion schema.

    'endpoint' is the canonical normalized path stored in DB.
    'path' is the raw request path.
    """
    project_id: UUID
    api_key_hash: Optional[str] = None
    method: str
    path: str
    endpoint: Optional[str] = None
    ip: str
    user_agent: Optional[str] = None
    risk_score: Optional[float] = None
    decision: str              # ALLOW | THROTTLE | BLOCK
    status_code: int
    latency_ms: int
    timestamp: Optional[datetime] = None
