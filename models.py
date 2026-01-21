import uuid
from sqlalchemy import Column, String, Boolean, DateTime, Integer, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from db import Base


# ───────────────── USERS ─────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# ───────────────── PROJECTS ─────────────────

class Project(Base):
    __tablename__ = "projects"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False)

    owner_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )

    upstream_base_url = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    api_keys = relationship("APIKey", cascade="all, delete-orphan")
    domains = relationship("Domain", cascade="all, delete-orphan")
    traffic_logs = relationship("TrafficLog", cascade="all, delete-orphan")


# ───────────────── API KEYS ─────────────────

class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    project_id = Column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    key_hash = Column(String, nullable=False, index=True)
    label = Column(String)

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    revoked_at = Column(DateTime(timezone=True))


# ───────────────── DOMAINS ─────────────────

class Domain(Base):
    __tablename__ = "domains"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    project_id = Column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    hostname = Column(String, unique=True, nullable=False, index=True)
    verification_token = Column(String, nullable=False)

    verified = Column(Boolean, default=False)
    verified_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())



# ───────────────── ENDPOINTS (METADATA) ─────────────────

class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    project_id = Column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    method = Column(String, nullable=False)
    pattern = Column(String, nullable=False)  # e.g. "/api/users/:id"
    
    first_seen_at = Column(DateTime(timezone=True), server_default=func.now())
    last_seen_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    buckets = relationship("MetricBucket", cascade="all, delete-orphan")


# ───────────────── METRIC BUCKETS (HISTORY) ─────────────────

class MetricBucket(Base):
    __tablename__ = "metric_buckets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    endpoint_id = Column(
        UUID(as_uuid=True),
        ForeignKey("endpoints.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Time bucket (e.g. hourly start time)
    bucket_start = Column(DateTime(timezone=True), nullable=False, index=True)

    request_count = Column(Integer, default=0)
    error_count = Column(Integer, default=0)
    latency_sum = Column(Integer, default=0)
    risk_score_sum = Column(Integer, default=0)
    
    throttled_count = Column(Integer, default=0)
    blocked_count = Column(Integer, default=0)


# ───────────────── TRAFFIC LOGS (CRITICAL) ─────────────────

class TrafficLog(Base):
    """
    Immutable request facts emitted by SecureX worker.

    IMPORTANT:
    - DB schema is authoritative
    - This model MUST match the database exactly
    """

    __tablename__ = "traffic_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    project_id = Column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    api_key_id = Column(
        UUID(as_uuid=True),
        ForeignKey("api_keys.id", ondelete="SET NULL"),
        index=True,
    )

    # ───── ROUTING ─────
    endpoint = Column(String, nullable=False, index=True)   # canonical path
    path = Column(String, nullable=False)                   # raw path
    method = Column(String, nullable=False)

    # ───── REQUEST CONTEXT ─────
    ip = Column(String, nullable=False, index=True)
    status_code = Column(Integer, nullable=False)

    # ───── SECURITY SIGNALS ─────
    decision = Column(String, nullable=False)  # ALLOW | THROTTLE | BLOCK
    risk_score = Column(Integer)
    latency_ms = Column(Integer)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        index=True,
    )

    # ───── BACKWARD COMPAT (NO SQL USE) ─────
    @property
    def normalized_path(self) -> str:
        """
        **DEPRECATED**: Backward-compatibility alias only.
        
        WARNING: NEVER use this property in SQL queries, filters, or GROUP BY.
        The actual DB column is 'endpoint' (line 116).
        
        This property exists ONLY for legacy code compatibility.
        Always use TrafficLog.endpoint in queries.
        """
        return self.endpoint
