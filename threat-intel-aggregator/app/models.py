"""
SQLAlchemy ORM models — mirror the DDL in db/schema.sql.
"""
import enum
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


# ─────────────────────────────── Enums ───────────────────────────────────────

class IoCType(str, enum.Enum):
    ip = "ip"
    domain = "domain"
    hash_md5 = "hash_md5"
    hash_sha1 = "hash_sha1"
    hash_sha256 = "hash_sha256"
    url = "url"
    email = "email"


class ThreatLevel(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"
    unknown = "unknown"


class AlertStatus(str, enum.Enum):
    open = "open"
    investigating = "investigating"
    resolved = "resolved"
    false_positive = "false_positive"


class FeedStatus(str, enum.Enum):
    active = "active"
    paused = "paused"
    error = "error"
    disabled = "disabled"


# ──────────────────────────── ORM Models ─────────────────────────────────────

class ThreatSource(Base):
    __tablename__ = "threat_sources"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    feed_url: Mapped[Optional[str]] = mapped_column(Text)
    api_key_env_var: Mapped[Optional[str]] = mapped_column(String(100))
    status: Mapped[FeedStatus] = mapped_column(
        Enum(FeedStatus, name="feed_status"), nullable=False, default=FeedStatus.active
    )
    fetch_interval: Mapped[int] = mapped_column(Integer, nullable=False, default=3600)
    last_fetched_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_ioc_count: Mapped[Optional[int]] = mapped_column(Integer)
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    metadata_: Mapped[Dict[str, Any]] = mapped_column("metadata", JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # relationships
    source_mappings: Mapped[List["IoCSourceMapping"]] = relationship(
        back_populates="source", cascade="all, delete-orphan"
    )
    fetch_logs: Mapped[List["FeedFetchLog"]] = relationship(
        back_populates="source", cascade="all, delete-orphan"
    )


class IoC(Base):
    __tablename__ = "iocs"
    __table_args__ = (
        UniqueConstraint("value", "type", name="uq_ioc_value_type"),
        CheckConstraint("confidence_score BETWEEN 0 AND 100", name="ck_confidence_range"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    type: Mapped[IoCType] = mapped_column(Enum(IoCType, name="ioc_type"), nullable=False)
    threat_level: Mapped[ThreatLevel] = mapped_column(
        Enum(ThreatLevel, name="threat_level"), nullable=False, default=ThreatLevel.unknown
    )
    confidence_score: Mapped[float] = mapped_column(Numeric(5, 2), nullable=False, default=0)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expiry_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    tags: Mapped[List[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    country_code: Mapped[Optional[str]] = mapped_column(String(2))
    asn: Mapped[Optional[int]] = mapped_column(Integer)
    asn_org: Mapped[Optional[str]] = mapped_column(String(255))
    malware_families: Mapped[List[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    raw_data: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # relationships
    source_mappings: Mapped[List["IoCSourceMapping"]] = relationship(
        back_populates="ioc", cascade="all, delete-orphan"
    )
    alert_mappings: Mapped[List["AlertIoCMapping"]] = relationship(
        back_populates="ioc", cascade="all, delete-orphan"
    )


class IoCSourceMapping(Base):
    __tablename__ = "ioc_source_mappings"
    __table_args__ = (
        UniqueConstraint("ioc_id", "source_id", name="uq_ioc_source"),
        CheckConstraint("source_confidence BETWEEN 0 AND 100", name="ck_src_confidence_range"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    ioc_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("iocs.id", ondelete="CASCADE"))
    source_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("threat_sources.id", ondelete="CASCADE"))
    external_id: Mapped[Optional[str]] = mapped_column(Text)
    reported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    source_severity: Mapped[Optional[ThreatLevel]] = mapped_column(
        Enum(ThreatLevel, name="threat_level")
    )
    source_confidence: Mapped[Optional[float]] = mapped_column(Numeric(5, 2))
    raw_entry: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    ioc: Mapped["IoC"] = relationship(back_populates="source_mappings")
    source: Mapped["ThreatSource"] = relationship(back_populates="source_mappings")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus, name="alert_status"), nullable=False, default=AlertStatus.open
    )
    severity: Mapped[ThreatLevel] = mapped_column(
        Enum(ThreatLevel, name="threat_level"), nullable=False, default=ThreatLevel.unknown
    )
    source_system: Mapped[Optional[str]] = mapped_column(String(100))
    external_ref: Mapped[Optional[str]] = mapped_column(String(255))
    affected_asset: Mapped[Optional[str]] = mapped_column(String(500))
    raw_alert: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    ioc_mappings: Mapped[List["AlertIoCMapping"]] = relationship(
        back_populates="alert", cascade="all, delete-orphan"
    )


class AlertIoCMapping(Base):
    __tablename__ = "alert_ioc_mappings"
    __table_args__ = (UniqueConstraint("alert_id", "ioc_id", name="uq_alert_ioc"),)

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    alert_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"))
    ioc_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("iocs.id", ondelete="CASCADE"))
    matched_on: Mapped[str] = mapped_column(Text, nullable=False)
    enriched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    notes: Mapped[Optional[str]] = mapped_column(Text)

    alert: Mapped["Alert"] = relationship(back_populates="ioc_mappings")
    ioc: Mapped["IoC"] = relationship(back_populates="alert_mappings")


class EnrichmentCache(Base):
    __tablename__ = "enrichment_cache"
    __table_args__ = (UniqueConstraint("ioc_value", "ioc_type", "provider", name="uq_cache_entry"),)

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    ioc_value: Mapped[str] = mapped_column(Text, nullable=False)
    ioc_type: Mapped[IoCType] = mapped_column(Enum(IoCType, name="ioc_type"), nullable=False)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    response: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class FeedFetchLog(Base):
    __tablename__ = "feed_fetch_logs"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    source_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("threat_sources.id", ondelete="CASCADE"))
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    iocs_fetched: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    iocs_inserted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    iocs_updated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    errors: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="running")
    error_details: Mapped[Optional[str]] = mapped_column(Text)

    source: Mapped["ThreatSource"] = relationship(back_populates="fetch_logs")
