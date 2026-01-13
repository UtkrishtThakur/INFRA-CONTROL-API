import uuid
from sqlalchemy import Column, String, Boolean, DateTime, Integer, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from db import Base


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Project(Base):
    __tablename__ = "projects"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False)

    owner_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=False,
    )

    upstream_base_url = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    api_keys = relationship("APIKey", cascade="all, delete-orphan")
    domains = relationship("Domain", cascade="all, delete-orphan")
    traffic_logs = relationship("TrafficLog", cascade="all, delete-orphan")


class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), index=True)

    key_hash = Column(String, nullable=False, index=True)
    label = Column(String, nullable=True)

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    revoked_at = Column(DateTime(timezone=True), nullable=True)


class Domain(Base):
    __tablename__ = "domains"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), index=True)

    hostname = Column(String, unique=True, nullable=False, index=True)
    verification_token = Column(String, nullable=False)

    verified = Column(Boolean, default=False)
    verified_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class TrafficLog(Base):
    """
    Immutable request facts emitted by the worker.
    """

    __tablename__ = "traffic_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), index=True)

    api_key_id = Column(UUID(as_uuid=True), ForeignKey("api_keys.id", ondelete="SET NULL"), index=True)

    ip = Column(String, nullable=False, index=True)
    path = Column(String, nullable=False)
    endpoint = Column(String, nullable=False, index=True)
    method = Column(String, nullable=False)

    status_code = Column(Integer, nullable=False)
    decision = Column(String, nullable=False)  # ALLOW | THROTTLE | BLOCK

    risk_score = Column(Integer)
    latency_ms = Column(Integer)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
