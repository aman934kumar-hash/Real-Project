"""
Ingest service — orchestrates collector runs and persists IoCs.
"""
import logging
from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from sqlalchemy import select, and_, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.collectors.base import NormalizedIoC
from app.collectors.registry import ALL_COLLECTORS
from app.database import get_db_ctx
from app.models import FeedFetchLog, IoC, IoCSourceMapping, ThreatSource

logger = logging.getLogger(__name__)


async def _get_source_id(db: AsyncSession, source_name: str) -> Optional[UUID]:
    stmt = select(ThreatSource.id).where(ThreatSource.name == source_name)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def _upsert_ioc(
    db: AsyncSession,
    normalized: NormalizedIoC,
    source_id: UUID,
) -> tuple[bool, bool]:
    """
    Insert or update a single IoC.
    Returns (inserted, updated) booleans.
    """
    now = datetime.now(timezone.utc)

    # Check existence
    stmt = select(IoC).where(
        and_(IoC.value == normalized.value, IoC.type == normalized.type)
    )
    result = await db.execute(stmt)
    existing: Optional[IoC] = result.scalar_one_or_none()

    inserted = updated = False

    if existing is None:
        ioc = IoC(
            value=normalized.value,
            type=normalized.type,
            threat_level=normalized.threat_level,
            confidence_score=normalized.confidence_score,
            tags=sorted(set(normalized.tags)),
            malware_families=sorted(set(normalized.malware_families)),
            country_code=normalized.country_code,
            asn=normalized.asn,
            asn_org=normalized.asn_org,
            raw_data=normalized.raw_entry,
        )
        db.add(ioc)
        await db.flush()
        existing = ioc
        inserted = True
    else:
        # Merge tags and malware families, update threat level if higher
        from app.services.enrichment import _LEVEL_ORDER
        existing.last_seen = now
        existing.tags = sorted(set(existing.tags or []) | set(normalized.tags))
        existing.malware_families = sorted(
            set(existing.malware_families or []) | set(normalized.malware_families)
        )
        if _LEVEL_ORDER.get(normalized.threat_level, 0) > _LEVEL_ORDER.get(existing.threat_level, 0):
            existing.threat_level = normalized.threat_level
        if normalized.confidence_score > float(existing.confidence_score):
            existing.confidence_score = normalized.confidence_score
        await db.flush()
        updated = True

    # Upsert source mapping
    stmt2 = select(IoCSourceMapping).where(
        and_(
            IoCSourceMapping.ioc_id == existing.id,
            IoCSourceMapping.source_id == source_id,
        )
    )
    result2 = await db.execute(stmt2)
    mapping = result2.scalar_one_or_none()

    if mapping is None:
        db.add(IoCSourceMapping(
            ioc_id=existing.id,
            source_id=source_id,
            external_id=normalized.external_id,
            source_severity=normalized.threat_level,
            source_confidence=normalized.confidence_score,
            raw_entry=normalized.raw_entry,
        ))
        await db.flush()
    else:
        mapping.reported_at = now
        mapping.source_severity = normalized.threat_level
        mapping.raw_entry = normalized.raw_entry
        await db.flush()

    return inserted, updated


async def run_ingest(source_names: Optional[List[str]] = None) -> dict:
    """
    Run all (or a subset of) registered collectors and persist results.
    Returns summary statistics.
    """
    collectors = ALL_COLLECTORS
    if source_names:
        collectors = [c for c in collectors if c.source_name in source_names]

    summary = {}

    for collector in collectors:
        async with get_db_ctx() as db:
            source_id = await _get_source_id(db, collector.source_name)
            if source_id is None:
                logger.warning("Source '%s' not found in DB — skipping.", collector.source_name)
                continue

            log = FeedFetchLog(source_id=source_id, started_at=datetime.now(timezone.utc))
            db.add(log)
            await db.flush()

            try:
                iocs: List[NormalizedIoC] = await collector.collect()
                log.iocs_fetched = len(iocs)

                inserted = updated = errors = 0
                for n_ioc in iocs:
                    try:
                        ins, upd = await _upsert_ioc(db, n_ioc, source_id)
                        inserted += ins
                        updated += upd
                    except Exception as exc:
                        errors += 1
                        logger.error("[%s] Failed to persist IoC %s: %s", collector.source_name, n_ioc.value, exc)
                        await db.rollback()

                log.iocs_inserted = inserted
                log.iocs_updated = updated
                log.errors = errors
                log.status = "success"

                # Update source metadata
                stmt = select(ThreatSource).where(ThreatSource.id == source_id)
                result = await db.execute(stmt)
                src = result.scalar_one_or_none()
                if src:
                    src.last_fetched_at = datetime.now(timezone.utc)
                    src.last_ioc_count = len(iocs)
                    src.error_message = None

                summary[collector.source_name] = {
                    "fetched": len(iocs), "inserted": inserted, "updated": updated, "errors": errors
                }
                logger.info(
                    "[%s] Complete: fetched=%d inserted=%d updated=%d errors=%d",
                    collector.source_name, len(iocs), inserted, updated, errors
                )

            except Exception as exc:
                log.status = "error"
                log.error_details = str(exc)
                log.errors = 1
                logger.exception("[%s] Ingest failed: %s", collector.source_name, exc)

                stmt = select(ThreatSource).where(ThreatSource.id == source_id)
                result = await db.execute(stmt)
                src = result.scalar_one_or_none()
                if src:
                    src.status = "error"
                    src.error_message = str(exc)[:500]

                summary[collector.source_name] = {"error": str(exc)}

            finally:
                log.finished_at = datetime.now(timezone.utc)
                await db.flush()

    return summary
