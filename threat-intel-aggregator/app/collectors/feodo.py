"""
Feodo Tracker collector (abuse.ch).

Downloads the JSON IP blocklist of known Emotet / TrickBot / QakBot C2 servers.
No API key required.

Docs: https://feodotracker.abuse.ch/blocklist/
"""
import logging
from typing import Any, Dict, List

import httpx

from app.collectors.base import BaseCollector, NormalizedIoC
from app.models import IoCType, ThreatLevel

logger = logging.getLogger(__name__)

_MALWARE_MAP = {
    "Emotet":   ["emotet"],
    "TrickBot": ["trickbot"],
    "QakBot":   ["qakbot"],
    "Dridex":   ["dridex"],
    "BazarLoader": ["bazarloader"],
}


class FeodoTrackerCollector(BaseCollector):
    """Collects C2 IP indicators from abuse.ch Feodo Tracker."""

    FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

    @property
    def source_name(self) -> str:
        return "Feodo Tracker"

    async def fetch_raw(self, client: httpx.AsyncClient) -> List[Dict[str, Any]]:
        resp = await client.get(self.FEED_URL)
        resp.raise_for_status()
        return resp.json()

    def normalize(self, raw: List[Dict[str, Any]]) -> List[NormalizedIoC]:
        iocs: List[NormalizedIoC] = []

        for entry in raw:
            ip = entry.get("ip_address", "").strip()
            if not ip:
                continue

            malware = entry.get("malware", "")
            families = _MALWARE_MAP.get(malware, [malware.lower()] if malware else [])

            iocs.append(
                NormalizedIoC(
                    value=ip,
                    type=IoCType.ip,
                    threat_level=ThreatLevel.high,
                    confidence_score=80.0,
                    tags=["c2-server", "botnet"],
                    malware_families=families,
                    asn=entry.get("as_number"),
                    asn_org=entry.get("as_name"),
                    country_code=entry.get("country"),
                    raw_entry={
                        "port": entry.get("port"),
                        "status": entry.get("status"),
                        "first_seen": entry.get("first_seen"),
                        "last_online": entry.get("last_online"),
                        "malware": malware,
                    },
                )
            )

        logger.info("[Feodo Tracker] Normalized %d C2 IPs", len(iocs))
        return iocs
