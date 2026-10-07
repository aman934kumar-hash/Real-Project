"""
Alerts routes — /api/v1/alerts
"""
import logging
from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models import Alert, AlertIoCMapping, AlertStatus, IoC, IoCType, ThreatLevel
from app.schemas import (
    AlertCreate,
    AlertDetailOut,
    AlertOut,
    AlertUpdate,
    IoCOut,
    MessageResponse,
)
from app.services.enrichment import enrich_ioc
from app.utils.ioc_detector import detect_ioc_type

router = APIRouter(prefix="/alerts", tags=["Alerts"])
logger = logging.getLogger(__name__)


@router.get("", response_model=List[AlertOut], summary="List alerts")
async def list_alerts(
    status: Optional[AlertStatus] = Query(None),
    severity: Optional[ThreatLevel] = Query(None),
    source_system: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    filters = []
    if status:
        filters.append(Alert.status == status)
    if severity:
        filters.append(Alert.severity == severity)
    if source_system:
        filters.append(Alert.source_system == source_system)

    base_q = select(Alert).where(and_(*filters)) if filters else select(Alert)
    stmt = base_q.order_by(Alert.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(stmt)
    alerts = result.scalars().all()
    return [AlertOut.model_validate(a) for a in alerts]


@router.post(
    "",
    response_model=AlertDetailOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create alert and auto-enrich IoCs",
)
async def create_alert(payload: AlertCreate, db: AsyncSession = Depends(get_db)):
    alert = Alert(
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        source_system=payload.source_system,
        external_ref=payload.external_ref,
        affected_asset=payload.affected_asset,
        raw_alert=payload.raw_alert,
    )
    db.add(alert)
    await db.flush()

    matched_iocs: List[IoC] = []

    # Auto-enrich any IoC values provided
    for raw_value in payload.ioc_values:
        ioc_type = detect_ioc_type(raw_value)
        if not ioc_type:
            logger.warning("Skipping unrecognised IoC value: %s", raw_value)
            continue
        try:
            enrichment = await enrich_ioc(
                value=raw_value,
                ioc_type=ioc_type,
                include_live_lookup=True,
                db=db,
            )
        except Exception as exc:
            logger.error("Enrichment failed for %s: %s", raw_value, exc)
            continue

        # Link IoC to alert
        if enrichment.local_record:
            ioc_id = enrichment.local_record.id
            existing = await db.execute(
                select(AlertIoCMapping).where(
                    and_(AlertIoCMapping.alert_id == alert.id, AlertIoCMapping.ioc_id == ioc_id)
                )
            )
            if not existing.scalar_one_or_none():
                db.add(AlertIoCMapping(alert_id=alert.id, ioc_id=ioc_id, matched_on=raw_value))
                await db.flush()
                ioc_result = await db.execute(select(IoC).where(IoC.id == ioc_id))
                ioc_obj = ioc_result.scalar_one_or_none()
                if ioc_obj:
                    matched_iocs.append(ioc_obj)

            # Escalate alert severity if IoC threat level is higher
            from app.services.enrichment import _LEVEL_ORDER
            if _LEVEL_ORDER.get(enrichment.composite_threat_level, 0) > _LEVEL_ORDER.get(alert.severity, 0):
                alert.severity = enrichment.composite_threat_level
                await db.flush()

    detail = AlertDetailOut.model_validate(alert)
    detail.matched_iocs = [IoCOut.model_validate(i) for i in matched_iocs]
    return detail


@router.get("/{alert_id}", response_model=AlertDetailOut, summary="Get alert with matched IoCs")
async def get_alert(alert_id: UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Alert).where(Alert.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    # Load matched IoCs
    mapping_result = await db.execute(
        select(AlertIoCMapping).where(AlertIoCMapping.alert_id == alert_id)
    )
    mappings = mapping_result.scalars().all()
    ioc_ids = [m.ioc_id for m in mappings]

    iocs = []
    if ioc_ids:
        ioc_result = await db.execute(select(IoC).where(IoC.id.in_(ioc_ids)))
        iocs = ioc_result.scalars().all()

    detail = AlertDetailOut.model_validate(alert)
    detail.matched_iocs = [IoCOut.model_validate(i) for i in iocs]
    return detail


@router.patch("/{alert_id}", response_model=AlertOut, summary="Update alert status or severity")
async def update_alert(alert_id: UUID, payload: AlertUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    for field, val in payload.model_dump(exclude_unset=True).items():
        setattr(alert, field, val)

    if payload.status == AlertStatus.resolved and not alert.resolved_at:
        alert.resolved_at = datetime.now(timezone.utc)

    await db.flush()
    return AlertOut.model_validate(alert)


@router.delete("/{alert_id}", response_model=MessageResponse, summary="Delete an alert")
async def delete_alert(alert_id: UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    await db.delete(alert)
    return MessageResponse(message=f"Alert {alert_id} deleted.")
