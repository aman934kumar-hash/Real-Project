"""
AbuseIPDB collector.

Fetches the "blacklist" endpoint — a list of IPs reported for abusive behaviour
with a configurable minimum confidence threshold.

Docs: https://docs.abuseipdb.com/#blacklist-endpoint
"""
import logging
import os
from typing import Any, Dict, List

import httpx

from app.collectors.base import BaseCollector, NormalizedIoC
from app.models import IoCType, ThreatLevel

logger = logging.getLogger(__name__)


class AbuseIPDBCollector(BaseCollector):
    """Fetches the AbuseIPDB IP blacklist."""

    BASE_URL = "https://api.abuseipdb.com/api/v2"
    CONFIDENCE_THRESHOLD = 75   # only pull IPs with ≥75 % abuse confidence

    @property
    def source_name(self) -> str:
        return "AbuseIPDB"

    def _get_api_key(self) -> str:
        key = os.getenv("ABUSEIPDB_API_KEY", "")
        if not key:
            raise EnvironmentError("ABUSEIPDB_API_KEY environment variable is not set.")
        return key

    async def fetch_raw(self, client: httpx.AsyncClient) -> Dict[str, Any]:
        api_key = self._get_api_key()
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {
            "confidenceMinimum": self.CONFIDENCE_THRESHOLD,
            "limit": 10000,
        }
        resp = await client.get(f"{self.BASE_URL}/blacklist", headers=headers, params=params)
        resp.raise_for_status()
        return resp.json()

    def normalize(self, raw: Dict[str, Any]) -> List[NormalizedIoC]:
        iocs: List[NormalizedIoC] = []

        for entry in raw.get("data", []):
            confidence = float(entry.get("abuseConfidenceScore", 0))
            if confidence < self.CONFIDENCE_THRESHOLD:
                continue

            ip = entry.get("ipAddress", "").strip()
            if not ip:
                continue

            iocs.append(
                NormalizedIoC(
                    value=ip,
                    type=IoCType.ip,
                    threat_level=self._map_score_to_level(confidence),
                    confidence_score=confidence,
                    tags=["abusive-ip"],
                    country_code=entry.get("countryCode"),
                    raw_entry={
                        "abuse_confidence_score": confidence,
                        "total_reports": entry.get("totalReports"),
                        "last_reported_at": entry.get("lastReportedAt"),
                        "isp": entry.get("isp"),
                        "usage_type": entry.get("usageType"),
                        "domain": entry.get("domain"),
                    },
                )
            )

        logger.info("[AbuseIPDB] Normalized %d IPs", len(iocs))
        return iocs
