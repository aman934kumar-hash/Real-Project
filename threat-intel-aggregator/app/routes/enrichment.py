"""
Enrichment route — /api/v1/enrich
"""
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.schemas import EnrichmentRequest, EnrichmentResponse
from app.services.enrichment import enrich_ioc

router = APIRouter(prefix="/enrich", tags=["Enrichment"])
logger = logging.getLogger(__name__)


@router.post(
    "",
    response_model=EnrichmentResponse,
    summary="Enrich an IP, domain, or hash",
    description=(
        "Checks the value against the local IoC database **and** (optionally) "
        "live threat APIs (VirusTotal, AbuseIPDB, AlienVault OTX). "
        "Returns a composite risk profile including threat level, confidence score, "
        "tags, malware families, and per-provider details."
    ),
)
async def enrich_endpoint(
    payload: EnrichmentRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        response = await enrich_ioc(
            value=payload.value,
            ioc_type=payload.type,
            include_live_lookup=payload.include_live_lookup,
            db=db,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    except Exception as exc:
        logger.exception("Enrichment failed for %s", payload.value)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))

    return response


@router.get(
    "/{value}",
    response_model=EnrichmentResponse,
    summary="Quick GET enrichment (auto-detect type)",
    description="Convenience GET endpoint — useful for browser testing. Wraps the POST endpoint with `include_live_lookup=true`.",
)
async def enrich_get(value: str, db: AsyncSession = Depends(get_db)):
    try:
        response = await enrich_ioc(
            value=value,
            ioc_type=None,
            include_live_lookup=True,
            db=db,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    except Exception as exc:
        logger.exception("Enrichment failed for %s", value)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))

    return response
