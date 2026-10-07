"""
Feed management / ingest trigger routes — /api/v1/feeds
"""
import logging
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import FeedFetchLog, ThreatSource
from app.schemas import (
    FeedFetchLogOut,
    IngestTriggerResponse,
    MessageResponse,
    ThreatSourceOut,
)
from app.services.ingest import run_ingest

router = APIRouter(prefix="/feeds", tags=["Feeds & Ingest"])
logger = logging.getLogger(__name__)


@router.get("", response_model=List[ThreatSourceOut], summary="List registered threat sources")
async def list_sources(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ThreatSource).order_by(ThreatSource.name))
    return [ThreatSourceOut.model_validate(s) for s in result.scalars().all()]


@router.post(
    "/ingest",
    response_model=IngestTriggerResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger an IoC ingest run",
    description=(
        "Queues an ingest job in the background. "
        "Optionally pass `source_names` to restrict the run to specific feeds. "
        "Results are stored asynchronously — poll `/feeds/logs` to see progress."
    ),
)
async def trigger_ingest(
    background_tasks: BackgroundTasks,
    source_names: Optional[List[str]] = Query(None, description="Specific source names to ingest"),
):
    triggered = source_names or ["all registered sources"]
    background_tasks.add_task(run_ingest, source_names)
    return IngestTriggerResponse(
        triggered_sources=triggered,
        message="Ingest job queued. Check /api/v1/feeds/logs for status.",
    )


@router.get("/logs", response_model=List[FeedFetchLogOut], summary="Recent fetch logs")
async def fetch_logs(
    source_id: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(FeedFetchLog)
    if source_id:
        stmt = stmt.where(FeedFetchLog.source_id == source_id)
    stmt = stmt.order_by(FeedFetchLog.started_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(stmt)
    return [FeedFetchLogOut.model_validate(log) for log in result.scalars().all()]
