"""
Pydantic schemas — request/response validation and serialisation.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models import AlertStatus, FeedStatus, IoCType, ThreatLevel


# ──────────────────────────── Shared helpers ──────────────────────────────────

class _OrmBase(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


# ──────────────────────────── ThreatSource ────────────────────────────────────

class ThreatSourceOut(_OrmBase):
    id: UUID
    name: str
    provider: str
    feed_url: Optional[str]
    status: FeedStatus
    fetch_interval: int
    last_fetched_at: Optional[datetime]
    last_ioc_count: Optional[int]
    error_message: Optional[str]
    created_at: datetime


# ──────────────────────────── IoC ─────────────────────────────────────────────

class IoCCreate(BaseModel):
    value: str = Field(..., min_length=1, max_length=2048)
    type: IoCType
    threat_level: ThreatLevel = ThreatLevel.unknown
    confidence_score: float = Field(0, ge=0, le=100)
    tags: List[str] = []
    country_code: Optional[str] = Field(None, max_length=2)
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    malware_families: List[str] = []
    expiry_date: Optional[datetime] = None
    raw_data: Dict[str, Any] = {}

    @field_validator("value")
    @classmethod
    def strip_value(cls, v: str) -> str:
        return v.strip().lower()


class IoCUpdate(BaseModel):
    threat_level: Optional[ThreatLevel] = None
    confidence_score: Optional[float] = Field(None, ge=0, le=100)
    tags: Optional[List[str]] = None
    malware_families: Optional[List[str]] = None
    is_active: Optional[bool] = None
    expiry_date: Optional[datetime] = None


class IoCOut(_OrmBase):
    id: UUID
    value: str
    type: IoCType
    threat_level: ThreatLevel
    confidence_score: float
    first_seen: datetime
    last_seen: datetime
    expiry_date: Optional[datetime]
    is_active: bool
    tags: List[str]
    country_code: Optional[str]
    asn: Optional[int]
    asn_org: Optional[str]
    malware_families: List[str]
    created_at: datetime
    updated_at: datetime


class IoCSearchParams(BaseModel):
    value: Optional[str] = None
    type: Optional[IoCType] = None
    threat_level: Optional[ThreatLevel] = None
    tag: Optional[str] = None
    malware_family: Optional[str] = None
    country_code: Optional[str] = None
    is_active: Optional[bool] = True
    first_seen_from: Optional[datetime] = None
    first_seen_to: Optional[datetime] = None
    last_seen_from: Optional[datetime] = None
    last_seen_to: Optional[datetime] = None
    min_confidence: Optional[float] = Field(None, ge=0, le=100)
    page: int = Field(1, ge=1)
    page_size: int = Field(50, ge=1, le=500)


class PaginatedIoCResponse(BaseModel):
    total: int
    page: int
    page_size: int
    results: List[IoCOut]


# ──────────────────────────── Enrichment ──────────────────────────────────────

class EnrichmentRequest(BaseModel):
    value: str = Field(..., min_length=1, max_length=2048, description="IP, domain, or hash to enrich")
    type: Optional[IoCType] = Field(None, description="IoC type — auto-detected if omitted")
    include_live_lookup: bool = Field(True, description="Query live threat APIs in addition to local DB")

    @field_validator("value")
    @classmethod
    def strip_value(cls, v: str) -> str:
        return v.strip().lower()


class ProviderResult(BaseModel):
    provider: str
    found: bool
    threat_level: Optional[ThreatLevel] = None
    confidence: Optional[float] = None
    details: Dict[str, Any] = {}
    cached: bool = False
    error: Optional[str] = None


class EnrichmentResponse(BaseModel):
    value: str
    type: IoCType
    in_local_db: bool
    local_record: Optional[IoCOut] = None
    composite_threat_level: ThreatLevel
    composite_confidence: float
    provider_results: List[ProviderResult] = []
    tags: List[str] = []
    malware_families: List[str] = []
    enriched_at: datetime


# ──────────────────────────── Alerts ──────────────────────────────────────────

class AlertCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    severity: ThreatLevel = ThreatLevel.unknown
    source_system: Optional[str] = None
    external_ref: Optional[str] = None
    affected_asset: Optional[str] = None
    raw_alert: Dict[str, Any] = {}
    # IoC values to associate / enrich immediately
    ioc_values: List[str] = []


class AlertUpdate(BaseModel):
    status: Optional[AlertStatus] = None
    severity: Optional[ThreatLevel] = None
    description: Optional[str] = None


class AlertOut(_OrmBase):
    id: UUID
    title: str
    description: Optional[str]
    status: AlertStatus
    severity: ThreatLevel
    source_system: Optional[str]
    external_ref: Optional[str]
    affected_asset: Optional[str]
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime]


class AlertDetailOut(AlertOut):
    matched_iocs: List[IoCOut] = []


# ──────────────────────────── Feed management ────────────────────────────────

class FeedFetchLogOut(_OrmBase):
    id: UUID
    source_id: UUID
    started_at: datetime
    finished_at: Optional[datetime]
    iocs_fetched: int
    iocs_inserted: int
    iocs_updated: int
    errors: int
    status: str
    error_details: Optional[str]


class IngestTriggerResponse(BaseModel):
    triggered_sources: List[str]
    message: str


# ──────────────────────────── Generic responses ───────────────────────────────

class MessageResponse(BaseModel):
    message: str

class ErrorResponse(BaseModel):
    detail: str
    code: Optional[str] = None
