import uuid
from sqlalchemy import (
    Column,
    String,
    Boolean,
    DateTime,
    Integer,
    ForeignKey,
)
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
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    upstream_base_url = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # relationships (CRITICAL)
    api_keys = relationship(
        "APIKey",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    domains = relationship(
        "Domain",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    traffic_logs = relationship(
        "TrafficLog",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    project_id = Column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    key_hash = Column(String, nullable=False)
    label = Column(String, nullable=True)

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    revoked_at = Column(DateTime(timezone=True), nullable=True)


class Domain(Base):
    __tablename__ = "domains"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    project_id = Column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    hostname = Column(String, nullable=False, unique=True, index=True)
    verification_token = Column(String, nullable=False)

    verified = Column(Boolean, default=False)
    verified_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class TrafficLog(Base):
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
        nullable=True,
    )

    ip = Column(String, nullable=False)
    path = Column(String, nullable=False)
    method = Column(String, nullable=False)

    status = Column(Integer, nullable=False)
    risk_score = Column(Integer, nullable=True)
    blocked = Column(Boolean, default=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
