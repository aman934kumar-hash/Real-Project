"""
Abstract base class for all threat-feed collectors.
Every collector must implement `fetch()` and `normalize()`.
"""
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

from app.config import get_settings
from app.models import IoCType, ThreatLevel

logger = logging.getLogger(__name__)
settings = get_settings()


@dataclass
class NormalizedIoC:
    """Canonical representation of a single IoC across all feed collectors."""
    value: str
    type: IoCType
    threat_level: ThreatLevel = ThreatLevel.unknown
    confidence_score: float = 0.0
    tags: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    country_code: Optional[str] = None
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    external_id: Optional[str] = None
    raw_entry: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        self.value = self.value.strip().lower()


class BaseCollector(ABC):
    """
    Abstract base collector.

    Subclasses must implement:
        * `source_name` property → matches `threat_sources.name` in DB
        * `fetch_raw(client)` → returns raw API / HTTP response data
        * `normalize(raw)` → converts raw data into List[NormalizedIoC]
    """

    # Retry state shared by `fetch_with_retry`
    _retry_statuses = {429, 500, 502, 503, 504}

    @property
    @abstractmethod
    def source_name(self) -> str:
        """The exact `name` value stored in the `threat_sources` table."""

    @abstractmethod
    async def fetch_raw(self, client: httpx.AsyncClient) -> Any:
        """Perform HTTP request(s) and return the raw data."""

    @abstractmethod
    def normalize(self, raw: Any) -> List[NormalizedIoC]:
        """Convert raw data into a list of NormalizedIoC objects."""

    # ------------------------------------------------------------------ helpers

    async def collect(self) -> List[NormalizedIoC]:
        """
        Public entry point used by the scheduler and ingest service.
        Returns a list of NormalizedIoC objects.
        """
        limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
        timeout = httpx.Timeout(settings.http_timeout_seconds)

        async with httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True) as client:
            raw = await self.fetch_with_retry(client)

        iocs = self.normalize(raw)
        logger.info("[%s] Collected %d IoCs", self.source_name, len(iocs))
        return iocs

    async def fetch_with_retry(self, client: httpx.AsyncClient) -> Any:
        import asyncio

        last_exc: Optional[Exception] = None
        delay = 1.0

        for attempt in range(1, settings.http_max_retries + 1):
            try:
                result = await self.fetch_raw(client)
                return result
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code in self._retry_statuses:
                    logger.warning(
                        "[%s] HTTP %s on attempt %d/%d — retrying in %.1fs",
                        self.source_name, exc.response.status_code,
                        attempt, settings.http_max_retries, delay,
                    )
                    last_exc = exc
                    # Respect Retry-After header if present
                    retry_after = exc.response.headers.get("Retry-After")
                    sleep_for = float(retry_after) if retry_after else delay
                    await asyncio.sleep(sleep_for)
                    delay *= settings.http_retry_backoff_factor
                else:
                    raise
            except (httpx.ConnectTimeout, httpx.ReadTimeout) as exc:
                logger.warning("[%s] Timeout on attempt %d/%d", self.source_name, attempt, settings.http_max_retries)
                last_exc = exc
                await asyncio.sleep(delay)
                delay *= settings.http_retry_backoff_factor

        raise RuntimeError(
            f"[{self.source_name}] All {settings.http_max_retries} attempts failed"
        ) from last_exc

    # ------------------------------------------------------------------ mapping helpers

    @staticmethod
    def _map_score_to_level(score: float) -> ThreatLevel:
        """Convert a 0-100 confidence/severity score to a ThreatLevel."""
        if score >= 85:
            return ThreatLevel.critical
        elif score >= 65:
            return ThreatLevel.high
        elif score >= 40:
            return ThreatLevel.medium
        elif score >= 20:
            return ThreatLevel.low
        elif score > 0:
            return ThreatLevel.informational
        return ThreatLevel.unknown
