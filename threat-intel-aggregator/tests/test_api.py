"""
Pytest test suite for the Threat Intelligence Aggregator API.

Run with:
    pytest tests/ -v
"""
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.fixture(scope="module")
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


# ── Health check ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ── IoC type auto-detection ───────────────────────────────────────────────────

@pytest.mark.parametrize("value,expected_type", [
    ("8.8.8.8",                                                          "ip"),
    ("2001:db8::1",                                                      "ip"),
    ("malicious-domain.ru",                                              "domain"),
    ("d41d8cd98f00b204e9800998ecf8427e",                                "hash_md5"),
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709",                        "hash_sha1"),
    ("aec070645fe53ee3b3763059376134f058cc337247c978376971037851d1e25f", "hash_sha256"),
    ("http://example.com/path",                                          "url"),
    ("user@example.com",                                                 "email"),
])
def test_ioc_type_detection(value, expected_type):
    from app.utils.ioc_detector import detect_ioc_type
    from app.models import IoCType
    result = detect_ioc_type(value)
    assert result == IoCType(expected_type), f"Expected {expected_type} for {value!r}, got {result}"


def test_ioc_type_unknown():
    from app.utils.ioc_detector import detect_ioc_type
    assert detect_ioc_type("not-a-valid-ioc-!!!") is None


# ── Threat level score mapping ────────────────────────────────────────────────

@pytest.mark.parametrize("score,expected", [
    (95.0, "critical"),
    (70.0, "high"),
    (50.0, "medium"),
    (25.0, "low"),
    (5.0,  "informational"),
    (0.0,  "unknown"),
])
def test_score_to_level_mapping(score, expected):
    from app.services.enrichment import _map_score_to_level
    from app.models import ThreatLevel
    assert _map_score_to_level(score) == ThreatLevel(expected)


# ── IoC CRUD endpoints ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_ioc(client):
    payload = {
        "value": "192.0.2.99",
        "type": "ip",
        "threat_level": "high",
        "confidence_score": 77.5,
        "tags": ["test", "scanner"],
    }
    resp = await client.post("/api/v1/iocs", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["value"] == "192.0.2.99"
    assert data["type"] == "ip"
    assert data["confidence_score"] == 77.5
    return data["id"]


@pytest.mark.asyncio
async def test_create_duplicate_ioc(client):
    payload = {"value": "192.0.2.99", "type": "ip"}
    resp = await client.post("/api/v1/iocs", json=payload)
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_search_iocs_by_type(client):
    resp = await client.get("/api/v1/iocs", params={"type": "ip"})
    assert resp.status_code == 200
    data = resp.json()
    assert "results" in data
    assert all(r["type"] == "ip" for r in data["results"])


@pytest.mark.asyncio
async def test_search_iocs_pagination(client):
    resp = await client.get("/api/v1/iocs", params={"page": 1, "page_size": 5})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["results"]) <= 5


@pytest.mark.asyncio
async def test_lookup_ioc_by_value(client):
    resp = await client.get("/api/v1/iocs/lookup/192.0.2.99", params={"type": "ip"})
    assert resp.status_code == 200
    assert resp.json()["value"] == "192.0.2.99"


# ── Enrichment endpoint ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_enrich_no_live_lookup(client):
    """Enrichment with live lookup disabled — only checks local DB."""
    payload = {
        "value": "192.0.2.99",
        "type": "ip",
        "include_live_lookup": False,
    }
    resp = await client.post("/api/v1/enrich", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["value"] == "192.0.2.99"
    assert data["type"] == "ip"
    assert "composite_threat_level" in data
    assert "enriched_at" in data


@pytest.mark.asyncio
async def test_enrich_auto_detect_hash(client):
    """Hash type should be auto-detected without explicit type field."""
    payload = {
        "value": "d41d8cd98f00b204e9800998ecf8427e",
        "include_live_lookup": False,
    }
    resp = await client.post("/api/v1/enrich", json=payload)
    assert resp.status_code == 200
    assert resp.json()["type"] == "hash_md5"


@pytest.mark.asyncio
async def test_enrich_invalid_value(client):
    """Completely unrecognisable value should return 422."""
    payload = {"value": "not!!!a|||valid__ioc", "include_live_lookup": False}
    resp = await client.post("/api/v1/enrich", json=payload)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_enrich_get_endpoint(client):
    resp = await client.get("/api/v1/enrich/8.8.8.8")
    # May be 200 (with DB result) or trigger live lookup — just check structure
    assert resp.status_code in (200, 422, 500)
    if resp.status_code == 200:
        assert "composite_threat_level" in resp.json()


# ── Alerts endpoints ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_alert(client):
    payload = {
        "title": "Test Alert — suspicious outbound",
        "description": "Test alert created by pytest.",
        "severity": "medium",
        "source_system": "pytest",
        "ioc_values": [],
    }
    resp = await client.post("/api/v1/alerts", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["title"] == payload["title"]
    assert data["status"] == "open"
    return data["id"]


@pytest.mark.asyncio
async def test_list_alerts(client):
    resp = await client.get("/api/v1/alerts")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_list_feeds(client):
    resp = await client.get("/api/v1/feeds")
    assert resp.status_code == 200
    sources = resp.json()
    assert isinstance(sources, list)
    # At minimum the seeded sources should be present
    names = [s["name"] for s in sources]
    assert "AlienVault OTX" in names
