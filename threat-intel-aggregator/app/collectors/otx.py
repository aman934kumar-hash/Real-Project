"""
AlienVault OTX collector.

Fetches the "subscribed pulses" endpoint which contains rich IoC data including
IPs, domains, file hashes, URLs and email indicators.

Docs: https://otx.alienvault.com/api
"""
import logging
import os
from typing import Any, Dict, List, Optional

import httpx

from app.collectors.base import BaseCollector, NormalizedIoC
from app.models import IoCType, ThreatLevel

logger = logging.getLogger(__name__)

_OTX_INDICATOR_TYPE_MAP: Dict[str, Optional[IoCType]] = {
    "IPv4":       IoCType.ip,
    "IPv6":       IoCType.ip,
    "domain":     IoCType.domain,
    "hostname":   IoCType.domain,
    "URL":        IoCType.url,
    "email":      IoCType.email,
    "FileHash-MD5":    IoCType.hash_md5,
    "FileHash-SHA1":   IoCType.hash_sha1,
    "FileHash-SHA256": IoCType.hash_sha256,
}


class OTXCollector(BaseCollector):
    """Collects IoCs from AlienVault OTX subscribed pulses."""

    BASE_URL = "https://otx.alienvault.com/api/v1"
    PAGE_LIMIT = 50   # pulses per page

    @property
    def source_name(self) -> str:
        return "AlienVault OTX"

    def _get_api_key(self) -> str:
        key = os.getenv("OTX_API_KEY", "")
        if not key:
            raise EnvironmentError("OTX_API_KEY environment variable is not set.")
        return key

    async def fetch_raw(self, client: httpx.AsyncClient) -> List[Dict[str, Any]]:
        """Pages through subscribed pulses and returns all pulse dicts."""
        api_key = self._get_api_key()
        headers = {"X-OTX-API-KEY": api_key}
        pulses: List[Dict[str, Any]] = []
        url = f"{self.BASE_URL}/pulses/subscribed?limit={self.PAGE_LIMIT}&modified_since=-1d"

        while url:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            pulses.extend(data.get("results", []))
            url = data.get("next")  # OTX uses absolute next-page URLs

        logger.debug("[OTX] Fetched %d pulses", len(pulses))
        return pulses

    def normalize(self, raw: List[Dict[str, Any]]) -> List[NormalizedIoC]:
        iocs: List[NormalizedIoC] = []

        for pulse in raw:
            pulse_tags = pulse.get("tags", [])
            malware_families = [
                m.get("display_name", "")
                for m in pulse.get("malware_families", [])
                if m.get("display_name")
            ]

            for indicator in pulse.get("indicators", []):
                ioc_type = _OTX_INDICATOR_TYPE_MAP.get(indicator.get("type"))
                if ioc_type is None:
                    continue  # unsupported indicator type

                value = indicator.get("indicator", "").strip().lower()
                if not value:
                    continue

                iocs.append(
                    NormalizedIoC(
                        value=value,
                        type=ioc_type,
                        threat_level=ThreatLevel.medium,  # OTX doesn't expose a numeric severity
                        confidence_score=50.0,
                        tags=list(set(pulse_tags)),
                        malware_families=malware_families,
                        country_code=indicator.get("country_code"),
                        external_id=str(pulse.get("id", "")),
                        raw_entry={
                            "pulse_id": pulse.get("id"),
                            "pulse_name": pulse.get("name"),
                            "indicator_id": indicator.get("id"),
                            "description": indicator.get("description"),
                            "created": indicator.get("created"),
                        },
                    )
                )

        logger.info("[OTX] Normalized %d IoCs from %d pulses", len(iocs), len(raw))
        return iocs
