"""
Background scheduler — uses APScheduler to periodically invoke ingest runs.
"""
import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.config import get_settings
from app.services.ingest import run_ingest

logger = logging.getLogger(__name__)
settings = get_settings()

_scheduler: AsyncIOScheduler | None = None


def get_scheduler() -> AsyncIOScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = AsyncIOScheduler(timezone=settings.scheduler_timezone)
    return _scheduler


def setup_scheduler() -> AsyncIOScheduler:
    """Register all scheduled jobs and return the scheduler (not yet started)."""
    scheduler = get_scheduler()

    # Master ingest job — runs every hour by default
    scheduler.add_job(
        run_ingest,
        trigger=IntervalTrigger(hours=1),
        id="master_ingest",
        name="Master IoC Ingest",
        replace_existing=True,
        misfire_grace_time=300,  # tolerate 5-minute misfire
    )

    logger.info("Scheduler configured with %d job(s).", len(scheduler.get_jobs()))
    return scheduler
