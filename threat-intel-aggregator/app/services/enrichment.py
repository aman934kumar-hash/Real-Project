"""
Enrichment Engine — core service layer.

Responsible for:
  1. Checking the local IoC database.
  2. Querying live providers (VirusTotal, AbuseIPDB, OTX) concurrently.
  3. Merging results into a composite threat profile.
  4. Persisting new or updated IoC records.
  5. Caching live API responses.
"""
import asyncio
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

import httpx
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models import (
    AlertIoCMapping,
    EnrichmentCache,
    IoC,
    IoCSourceMapping,
    IoCType,
    ThreatLevel,
    ThreatSource,
)
from app.schemas import EnrichmentResponse, ProviderResult
from app.utils.ioc_detector import detect_ioc_type

logger = logging.getLogger(__name__)
settings = get_settings()

# Threat-level ordering for composite scoring
_LEVEL_ORDER = {
    ThreatLevel.unknown: 0,
    ThreatLevel.informational: 1,
    ThreatLevel.low: 2,
    ThreatLevel.medium: 3,
    ThreatLevel.high: 4,
    ThreatLevel.critical: 5,
}


def _highest_level(levels: List[ThreatLevel]) -> ThreatLevel:
    return max(levels, key=lambda lvl: _LEVEL_ORDER.get(lvl, 0), default=ThreatLevel.unknown)


def _map_score_to_level(score: float) -> ThreatLevel:
    if score >= 85: return ThreatLevel.critical
    if score >= 65: return ThreatLevel.high
    if score >= 40: return ThreatLevel.medium
    if score >= 20: return ThreatLevel.low
    if score > 0:   return ThreatLevel.informational
    return ThreatLevel.unknown


# ─────────────────────── Provider query functions ────────────────────────────

async def _query_virustotal(
    client: httpx.AsyncClient,
    value: str,
    ioc_type: IoCType,
) -> ProviderResult:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return ProviderResult(provider="VirusTotal", found=False, error="API key not configured")

    headers = {"x-apikey": api_key}
    try:
        if ioc_type == IoCType.ip:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
        elif ioc_type == IoCType.domain:
            url = f"https://www.virustotal.com/api/v3/domains/{value}"
        elif ioc_type in (IoCType.hash_md5, IoCType.hash_sha1, IoCType.hash_sha256):
            url = f"https://www.virustotal.com/api/v3/files/{value}"
        elif ioc_type == IoCType.url:
            import base64
            url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        else:
            return ProviderResult(provider="VirusTotal", found=False, error=f"Unsupported type: {ioc_type}")

        resp = await client.get(url, headers=headers, timeout=settings.http_timeout_seconds)
        if resp.status_code == 404:
            return ProviderResult(provider="VirusTotal", found=False, details={})
        resp.raise_for_status()

        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) or 1
        confidence = round(malicious / total * 100, 2)

        return ProviderResult(
            provider="VirusTotal",
            found=malicious > 0,
            threat_level=_map_score_to_level(confidence),
            confidence=confidence,
            details={
                "malicious_engines": malicious,
                "total_engines": total,
                "reputation": data.get("reputation"),
                "categories": data.get("categories", {}),
                "tags": data.get("tags", []),
            },
        )
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 429:
            return ProviderResult(provider="VirusTotal", found=False, error="Rate limit exceeded")
        return ProviderResult(provider="VirusTotal", found=False, error=str(exc))
    except Exception as exc:
        logger.exception("[VirusTotal] Unexpected error for %s", value)
        return ProviderResult(provider="VirusTotal", found=False, error=str(exc))


async def _query_abuseipdb(
    client: httpx.AsyncClient,
    value: str,
    ioc_type: IoCType,
) -> ProviderResult:
    if ioc_type != IoCType.ip:
        return ProviderResult(provider="AbuseIPDB", found=False, error="Only IP lookups supported")

    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return ProviderResult(provider="AbuseIPDB", found=False, error="API key not configured")

    try:
        resp = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": value, "maxAgeInDays": 90, "verbose": True},
            timeout=settings.http_timeout_seconds,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        confidence = float(data.get("abuseConfidenceScore", 0))

        return ProviderResult(
            provider="AbuseIPDB",
            found=confidence > 0,
            threat_level=_map_score_to_level(confidence),
            confidence=confidence,
            details={
                "total_reports": data.get("totalReports"),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "usage_type": data.get("usageType"),
                "is_tor": data.get("isTor"),
                "last_reported_at": data.get("lastReportedAt"),
            },
        )
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 429:
            return ProviderResult(provider="AbuseIPDB", found=False, error="Rate limit exceeded")
        return ProviderResult(provider="AbuseIPDB", found=False, error=str(exc))
    except Exception as exc:
        logger.exception("[AbuseIPDB] Unexpected error for %s", value)
        return ProviderResult(provider="AbuseIPDB", found=False, error=str(exc))


async def _query_otx(
    client: httpx.AsyncClient,
    value: str,
    ioc_type: IoCType,
) -> ProviderResult:
    api_key = os.getenv("OTX_API_KEY", "")
    if not api_key:
        return ProviderResult(provider="AlienVault OTX", found=False, error="API key not configured")

    type_path_map = {
        IoCType.ip:          f"indicators/IPv4/{value}/general",
        IoCType.domain:      f"indicators/domain/{value}/general",
        IoCType.hash_md5:    f"indicators/file/{value}/general",
        IoCType.hash_sha1:   f"indicators/file/{value}/general",
        IoCType.hash_sha256: f"indicators/file/{value}/general",
        IoCType.url:         f"indicators/url/{value}/general",
    }
    path = type_path_map.get(ioc_type)
    if not path:
        return ProviderResult(provider="AlienVault OTX", found=False, error=f"Unsupported type: {ioc_type}")

    try:
        resp = await client.get(
            f"https://otx.alienvault.com/api/v1/{path}",
            headers={"X-OTX-API-KEY": api_key},
            timeout=settings.http_timeout_seconds,
        )
        if resp.status_code == 404:
            return ProviderResult(provider="AlienVault OTX", found=False, details={})
        resp.raise_for_status()

        data = resp.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        confidence = min(pulse_count * 10.0, 100.0)

        return ProviderResult(
            provider="AlienVault OTX",
            found=pulse_count > 0,
            threat_level=_map_score_to_level(confidence),
            confidence=confidence,
            details={
                "pulse_count": pulse_count,
                "tags": data.get("pulse_info", {}).get("tags", []),
                "malware_families": data.get("pulse_info", {}).get("malware_families", []),
                "country_name": data.get("country_name"),
                "asn": data.get("asn"),
            },
        )
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 429:
            return ProviderResult(provider="AlienVault OTX", found=False, error="Rate limit exceeded")
        return ProviderResult(provider="AlienVault OTX", found=False, error=str(exc))
    except Exception as exc:
        logger.exception("[OTX] Unexpected error for %s", value)
        return ProviderResult(provider="AlienVault OTX", found=False, error=str(exc))


# ──────────────────────── Cache helpers ───────────────────────────────────────

async def _get_cached_result(
    db: AsyncSession, value: str, ioc_type: IoCType, provider: str
) -> Optional[Dict[str, Any]]:
    now = datetime.now(timezone.utc)
    stmt = select(EnrichmentCache).where(
        and_(
            EnrichmentCache.ioc_value == value,
            EnrichmentCache.ioc_type == ioc_type,
            EnrichmentCache.provider == provider,
            EnrichmentCache.expires_at > now,
        )
    )
    result = await db.execute(stmt)
    row = result.scalar_one_or_none()
    return row.response if row else None


async def _set_cache(
    db: AsyncSession,
    value: str,
    ioc_type: IoCType,
    provider: str,
    response_data: Dict[str, Any],
) -> None:
    expires = datetime.now(timezone.utc) + timedelta(seconds=settings.enrichment_cache_ttl_seconds)
    stmt = select(EnrichmentCache).where(
        and_(
            EnrichmentCache.ioc_value == value,
            EnrichmentCache.ioc_type == ioc_type,
            EnrichmentCache.provider == provider,
        )
    )
    result = await db.execute(stmt)
    cache_row = result.scalar_one_or_none()

    if cache_row:
        cache_row.response = response_data
        cache_row.fetched_at = datetime.now(timezone.utc)
        cache_row.expires_at = expires
    else:
        db.add(EnrichmentCache(
            ioc_value=value,
            ioc_type=ioc_type,
            provider=provider,
            response=response_data,
            expires_at=expires,
        ))
    await db.flush()


# ──────────────────────── Main enrichment function ───────────────────────────

async def enrich_ioc(
    value: str,
    ioc_type: Optional[IoCType],
    include_live_lookup: bool,
    db: AsyncSession,
) -> EnrichmentResponse:
    """
    Core enrichment pipeline:
      1. Auto-detect type if not given.
      2. Query local DB.
      3. Query live providers concurrently (if requested and not cached).
      4. Build composite threat profile.
      5. Persist/update IoC in DB.
    """
    value = value.strip().lower()

    # 1 — type detection
    if ioc_type is None:
        ioc_type = detect_ioc_type(value)
        if ioc_type is None:
            raise ValueError(f"Cannot determine IoC type for: {value!r}")

    # 2 — local DB check
    stmt = select(IoC).where(
        and_(IoC.value == value, IoC.type == ioc_type)
    )
    result = await db.execute(stmt)
    local_ioc: Optional[IoC] = result.scalar_one_or_none()
    in_local_db = local_ioc is not None

    provider_results: List[ProviderResult] = []

    # 3 — live provider queries
    if include_live_lookup:
        provider_fns = [_query_virustotal, _query_abuseipdb, _query_otx]
        timeout = httpx.Timeout(settings.http_timeout_seconds)

        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            tasks = []
            cached_flags: List[bool] = []

            for fn in provider_fns:
                provider_name = fn.__name__.replace("_query_", "").replace("_", " ").title()
                # Map function name to display name
                _name_map = {
                    "_query_virustotal": "VirusTotal",
                    "_query_abuseipdb": "AbuseIPDB",
                    "_query_otx": "AlienVault OTX",
                }
                display_name = _name_map.get(fn.__name__, provider_name)
                cached_resp = await _get_cached_result(db, value, ioc_type, display_name)

                if cached_resp:
                    pr = ProviderResult(**cached_resp, cached=True)
                    provider_results.append(pr)
                    cached_flags.append(True)
                    tasks.append(None)
                else:
                    tasks.append(fn(client, value, ioc_type))
                    cached_flags.append(False)

            # Run non-cached tasks concurrently
            live_tasks = [t for t in tasks if t is not None]
            live_results = await asyncio.gather(*live_tasks, return_exceptions=True)

            live_idx = 0
            _name_map2 = {
                "_query_virustotal": "VirusTotal",
                "_query_abuseipdb": "AbuseIPDB",
                "_query_otx": "AlienVault OTX",
            }
            for i, (fn, cached) in enumerate(zip(provider_fns, cached_flags)):
                if not cached:
                    res = live_results[live_idx]
                    live_idx += 1
                    if isinstance(res, Exception):
                        display_name = _name_map2.get(fn.__name__, "Unknown")
                        res = ProviderResult(provider=display_name, found=False, error=str(res))
                    provider_results.append(res)
                    # Cache the live result
                    if not res.error:
                        await _set_cache(db, value, ioc_type, res.provider, res.model_dump())

    # 4 — composite scoring
    all_levels = [r.threat_level for r in provider_results if r.threat_level]
    if local_ioc:
        all_levels.append(local_ioc.threat_level)
    composite_level = _highest_level(all_levels) if all_levels else ThreatLevel.unknown

    confidences = [r.confidence for r in provider_results if r.confidence is not None]
    if local_ioc:
        confidences.append(float(local_ioc.confidence_score))
    composite_confidence = round(sum(confidences) / len(confidences), 2) if confidences else 0.0

    # Aggregate tags and malware families
    all_tags: List[str] = list(local_ioc.tags) if local_ioc else []
    all_families: List[str] = list(local_ioc.malware_families) if local_ioc else []
    for pr in provider_results:
        all_tags.extend(pr.details.get("tags", []))
        all_families.extend(pr.details.get("malware_families", []))
    all_tags = sorted(set(t.lower() for t in all_tags if t))
    all_families = sorted(set(f.lower() for f in all_families if f))

    # 5 — upsert into local DB if we got a positive hit
    any_positive = any(r.found for r in provider_results)
    if any_positive and not local_ioc:
        local_ioc = IoC(
            value=value,
            type=ioc_type,
            threat_level=composite_level,
            confidence_score=composite_confidence,
            tags=all_tags,
            malware_families=all_families,
            raw_data={"enriched_by": [r.provider for r in provider_results if r.found]},
        )
        db.add(local_ioc)
        await db.flush()
        in_local_db = True
    elif local_ioc:
        local_ioc.last_seen = datetime.now(timezone.utc)
        local_ioc.threat_level = composite_level
        local_ioc.confidence_score = composite_confidence
        local_ioc.tags = list(set(all_tags))
        local_ioc.malware_families = list(set(all_families))
        await db.flush()

    from app.schemas import IoCOut
    return EnrichmentResponse(
        value=value,
        type=ioc_type,
        in_local_db=in_local_db,
        local_record=IoCOut.model_validate(local_ioc) if local_ioc else None,
        composite_threat_level=composite_level,
        composite_confidence=composite_confidence,
        provider_results=provider_results,
        tags=all_tags,
        malware_families=all_families,
        enriched_at=datetime.now(timezone.utc),
    )
