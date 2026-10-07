"""
IoC CRUD & search routes — /api/v1/iocs
"""
import logging
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import IoC, IoCType, ThreatLevel
from app.schemas import (
    IoCCreate,
    IoCOut,
    IoCSearchParams,
    IoCUpdate,
    MessageResponse,
    PaginatedIoCResponse,
)

router = APIRouter(prefix="/iocs", tags=["IoCs"])
logger = logging.getLogger(__name__)


@router.get("", response_model=PaginatedIoCResponse, summary="Search and filter IoCs")
async def search_iocs(
    value: Optional[str] = Query(None, description="Substring match on IoC value"),
    type: Optional[IoCType] = Query(None, description="Filter by IoC type"),
    threat_level: Optional[ThreatLevel] = Query(None, description="Filter by threat level"),
    tag: Optional[str] = Query(None, description="Filter by tag (exact match)"),
    malware_family: Optional[str] = Query(None, description="Filter by malware family"),
    country_code: Optional[str] = Query(None, max_length=2),
    is_active: Optional[bool] = Query(True),
    min_confidence: Optional[float] = Query(None, ge=0, le=100),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    filters = []

    if value:
        filters.append(IoC.value.ilike(f"%{value.strip().lower()}%"))
    if type:
        filters.append(IoC.type == type)
    if threat_level:
        filters.append(IoC.threat_level == threat_level)
    if tag:
        filters.append(IoC.tags.contains([tag]))
    if malware_family:
        filters.append(IoC.malware_families.contains([malware_family.lower()]))
    if country_code:
        filters.append(IoC.country_code == country_code.upper())
    if is_active is not None:
        filters.append(IoC.is_active == is_active)
    if min_confidence is not None:
        filters.append(IoC.confidence_score >= min_confidence)

    base_q = select(IoC).where(and_(*filters)) if filters else select(IoC)
    count_q = select(func.count()).select_from(base_q.subquery())

    total_result = await db.execute(count_q)
    total = total_result.scalar_one()

    offset = (page - 1) * page_size
    stmt = base_q.order_by(IoC.last_seen.desc()).offset(offset).limit(page_size)
    result = await db.execute(stmt)
    iocs = result.scalars().all()

    return PaginatedIoCResponse(
        total=total,
        page=page,
        page_size=page_size,
        results=[IoCOut.model_validate(i) for i in iocs],
    )


@router.get("/{ioc_id}", response_model=IoCOut, summary="Get a single IoC by ID")
async def get_ioc(ioc_id: UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(IoC).where(IoC.id == ioc_id))
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IoC not found")
    return IoCOut.model_validate(ioc)


@router.post("", response_model=IoCOut, status_code=status.HTTP_201_CREATED, summary="Manually add an IoC")
async def create_ioc(payload: IoCCreate, db: AsyncSession = Depends(get_db)):
    # Check for duplicate
    stmt = select(IoC).where(and_(IoC.value == payload.value, IoC.type == payload.type))
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"IoC '{payload.value}' of type '{payload.type}' already exists.",
        )

    ioc = IoC(**payload.model_dump())
    db.add(ioc)
    await db.flush()
    return IoCOut.model_validate(ioc)


@router.patch("/{ioc_id}", response_model=IoCOut, summary="Update IoC fields")
async def update_ioc(ioc_id: UUID, payload: IoCUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(IoC).where(IoC.id == ioc_id))
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IoC not found")

    for field, val in payload.model_dump(exclude_unset=True).items():
        setattr(ioc, field, val)
    await db.flush()
    return IoCOut.model_validate(ioc)


@router.delete("/{ioc_id}", response_model=MessageResponse, summary="Delete an IoC")
async def delete_ioc(ioc_id: UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(IoC).where(IoC.id == ioc_id))
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IoC not found")

    await db.delete(ioc)
    return MessageResponse(message=f"IoC {ioc_id} deleted.")


@router.get("/lookup/{value}", response_model=IoCOut, summary="Exact-match lookup by value")
async def lookup_ioc(
    value: str,
    type: Optional[IoCType] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    filters = [IoC.value == value.strip().lower()]
    if type:
        filters.append(IoC.type == type)

    stmt = select(IoC).where(and_(*filters)).order_by(IoC.confidence_score.desc()).limit(1)
    result = await db.execute(stmt)
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IoC not found in local database")
    return IoCOut.model_validate(ioc)
