# 🛡️ Threat Intelligence Aggregator

A production-ready automated system that collects Indicators of Compromise (IoCs) from open-source threat feeds, enriches security alerts, and exposes a fast REST API backed by PostgreSQL.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         FastAPI Application                      │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  /iocs       │  │  /enrich     │  │  /alerts  /feeds     │  │
│  │  CRUD/Search │  │  Enrichment  │  │  Alert Mgmt + Ingest │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│         │                │                       │               │
│         └───────────────►│◄──────────────────────┘               │
│                    Enrichment Engine                              │
│              (DB lookup + concurrent API calls)                   │
│                          │                                        │
│          ┌───────────────┼───────────────┐                        │
│          ▼               ▼               ▼                        │
│    VirusTotal      AbuseIPDB       AlienVault OTX                 │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │          APScheduler — hourly IoC ingest jobs              │  │
│  │   OTXCollector  AbuseIPDBCollector  FeodoTrackerCollector  │  │
│  └────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                    PostgreSQL Database
          (iocs, threat_sources, alerts, enrichment_cache)
```

---

## Project Structure

```
threat-intel-aggregator/
├── app/
│   ├── main.py              # FastAPI app factory + lifespan
│   ├── config.py            # Pydantic Settings from .env
│   ├── database.py          # Async SQLAlchemy engine + session
│   ├── models.py            # ORM models (IoC, Alert, ThreatSource…)
│   ├── schemas.py           # Pydantic request/response schemas
│   ├── scheduler.py         # APScheduler background jobs
│   ├── collectors/
│   │   ├── base.py          # Abstract BaseCollector + retry logic
│   │   ├── otx.py           # AlienVault OTX feed
│   │   ├── abuseipdb.py     # AbuseIPDB blacklist
│   │   ├── feodo.py         # Feodo Tracker C2 IP feed
│   │   └── registry.py      # ALL_COLLECTORS list
│   ├── routes/
│   │   ├── iocs.py          # IoC CRUD + search endpoints
│   │   ├── enrichment.py    # /enrich endpoint
│   │   ├── alerts.py        # Alert management
│   │   └── feeds.py         # Feed management + ingest trigger
│   ├── services/
│   │   ├── enrichment.py    # Core enrichment engine
│   │   └── ingest.py        # IoC ingest orchestration
│   └── utils/
│       └── ioc_detector.py  # Auto-detect IoC type from value
├── db/
│   ├── schema.sql           # Full PostgreSQL DDL
│   └── seed_data.sql        # Sample IoCs, alerts, and mappings
├── tests/
│   └── test_api.py          # Pytest async test suite
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── .env.example
└── README.md
```

---

## Quick Start

### Option A — Docker Compose (recommended)

```bash
# 1. Clone the repository
git clone <repo-url> && cd threat-intel-aggregator

# 2. Create your .env file
cp .env.example .env
# Edit .env — add your API keys (OTX, VirusTotal, AbuseIPDB)

# 3. Start all services
docker compose up --build

# 4. Load sample data (optional)
docker exec -i threat_intel_db psql -U postgres -d threat_intel < db/seed_data.sql

# 5. Open Swagger UI
open http://localhost:8000/docs
```

### Option B — Local Python

```bash
# 1. Prerequisites: Python 3.12+, PostgreSQL 14+

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up environment
cp .env.example .env
# Edit .env — set DATABASE_URL and API keys

# 5. Create the database
createdb threat_intel
psql -d threat_intel -f db/schema.sql
psql -d threat_intel -f db/seed_data.sql   # optional sample data

# 6. Run the API
uvicorn app.main:app --reload --port 8000

# 7. Open Swagger UI
open http://localhost:8000/docs
```

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | ✅ | `postgresql+asyncpg://user:pass@host:port/db` |
| `OTX_API_KEY` | ⚠️ | AlienVault OTX API key (free at otx.alienvault.com) |
| `VIRUSTOTAL_API_KEY` | ⚠️ | VirusTotal API key (free tier: 4 req/min) |
| `ABUSEIPDB_API_KEY` | ⚠️ | AbuseIPDB API key (free tier: 1000 req/day) |
| `SECRET_KEY` | ✅ | Random 32+ char string for production |
| `DEBUG` | ❌ | `false` in production |
| `SCHEDULER_ENABLED` | ❌ | `true` to enable hourly auto-ingest |
| `ENRICHMENT_CACHE_TTL_SECONDS` | ❌ | How long to cache live API responses (default: 3600) |

---

## API Reference

### Base URL
```
http://localhost:8000/api/v1
```

Full interactive docs: `http://localhost:8000/docs`

---

### POST /enrich — Enrich an IoC

Checks an IP, domain, or file hash against the local database **and** live APIs.

**Request:**
```json
POST /api/v1/enrich
Content-Type: application/json

{
  "value": "185.220.101.45",
  "type": "ip",
  "include_live_lookup": true
}
```

**Response `200 OK`:**
```json
{
  "value": "185.220.101.45",
  "type": "ip",
  "in_local_db": true,
  "local_record": {
    "id": "a1b2c3d4-...",
    "value": "185.220.101.45",
    "type": "ip",
    "threat_level": "critical",
    "confidence_score": 95.0,
    "tags": ["tor-exit-node", "c2-server"],
    "malware_families": ["emotet"],
    "country_code": "DE",
    "first_seen": "2024-01-15T10:00:00Z",
    "last_seen": "2024-05-01T14:32:00Z"
  },
  "composite_threat_level": "critical",
  "composite_confidence": 91.5,
  "provider_results": [
    {
      "provider": "VirusTotal",
      "found": true,
      "threat_level": "critical",
      "confidence": 94.0,
      "cached": false,
      "details": {
        "malicious_engines": 47,
        "total_engines": 50,
        "reputation": -100,
        "tags": ["tor", "c2"]
      }
    },
    {
      "provider": "AbuseIPDB",
      "found": true,
      "threat_level": "critical",
      "confidence": 97.0,
      "cached": false,
      "details": {
        "total_reports": 312,
        "country_code": "DE",
        "isp": "Tor Project",
        "is_tor": true,
        "last_reported_at": "2024-05-01T12:00:00Z"
      }
    },
    {
      "provider": "AlienVault OTX",
      "found": true,
      "threat_level": "high",
      "confidence": 80.0,
      "cached": false,
      "details": {
        "pulse_count": 8,
        "tags": ["tor", "emotet"],
        "malware_families": ["Emotet"]
      }
    }
  ],
  "tags": ["c2-server", "emotet", "tor", "tor-exit-node"],
  "malware_families": ["emotet"],
  "enriched_at": "2024-05-01T14:32:45Z"
}
```

**GET shorthand (auto-detect type):**
```
GET /api/v1/enrich/d41d8cd98f00b204e9800998ecf8427e
```

---

### GET /iocs — Search IoCs

```
GET /api/v1/iocs?type=ip&threat_level=critical&tag=c2-server&page=1&page_size=10
```

**Response:**
```json
{
  "total": 3,
  "page": 1,
  "page_size": 10,
  "results": [
    {
      "id": "a1b2c3d4-...",
      "value": "185.220.101.45",
      "type": "ip",
      "threat_level": "critical",
      "confidence_score": 95.0,
      "tags": ["tor-exit-node", "c2-server"],
      "malware_families": ["emotet"],
      "country_code": "DE",
      "is_active": true,
      "first_seen": "2024-01-15T10:00:00Z",
      "last_seen": "2024-05-01T14:32:00Z"
    }
  ]
}
```

**Available filters:**

| Parameter | Type | Description |
|---|---|---|
| `value` | string | Substring match on IoC value |
| `type` | enum | `ip`, `domain`, `hash_md5`, `hash_sha1`, `hash_sha256`, `url`, `email` |
| `threat_level` | enum | `critical`, `high`, `medium`, `low`, `informational`, `unknown` |
| `tag` | string | Exact tag match |
| `malware_family` | string | Malware family name |
| `country_code` | string | Two-letter country code |
| `min_confidence` | float | Minimum confidence score (0–100) |
| `is_active` | bool | Filter active/inactive IoCs |
| `page` / `page_size` | int | Pagination |

---

### GET /iocs/lookup/{value} — Exact lookup

```
GET /api/v1/iocs/lookup/185.220.101.45?type=ip
```

Returns the exact IoC record or `404` if not found locally.

---

### POST /iocs — Manually add an IoC

```json
POST /api/v1/iocs
{
  "value": "malicious-example.ru",
  "type": "domain",
  "threat_level": "high",
  "confidence_score": 85,
  "tags": ["phishing", "manual-entry"],
  "malware_families": ["redline-stealer"]
}
```

---

### POST /alerts — Create alert with auto-enrichment

```json
POST /api/v1/alerts
{
  "title": "Outbound connection to known C2",
  "description": "Host 10.0.1.55 connected to 185.220.101.45 on port 443",
  "severity": "high",
  "source_system": "Splunk",
  "external_ref": "INC-2024-001",
  "affected_asset": "WS-042",
  "ioc_values": ["185.220.101.45", "update-flash-player.ru"]
}
```

The API automatically enriches all `ioc_values`, links them to the alert, and escalates `severity` if any IoC has a higher threat level.

---

### POST /feeds/ingest — Trigger manual ingest

```json
POST /api/v1/feeds/ingest

# Ingest all sources:
{}

# Or target specific sources:
?source_names=AlienVault+OTX&source_names=AbuseIPDB
```

**Response `202 Accepted`:**
```json
{
  "triggered_sources": ["AlienVault OTX", "AbuseIPDB"],
  "message": "Ingest job queued. Check /api/v1/feeds/logs for status."
}
```

---

### GET /feeds/logs — Ingest history

```
GET /api/v1/feeds/logs?page=1&page_size=20
```

---

## Running Tests

```bash
# Install test dependencies (included in requirements.txt)
pip install -r requirements.txt

# Run full test suite
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=app --cov-report=term-missing
```

---

## Adding a New Threat Feed

1. Create `app/collectors/my_feed.py` extending `BaseCollector`:

```python
from app.collectors.base import BaseCollector, NormalizedIoC

class MyFeedCollector(BaseCollector):
    @property
    def source_name(self) -> str:
        return "My Feed"      # must match threat_sources.name in DB

    async def fetch_raw(self, client):
        resp = await client.get("https://my-feed.example.com/iocs.json")
        resp.raise_for_status()
        return resp.json()

    def normalize(self, raw) -> list[NormalizedIoC]:
        return [
            NormalizedIoC(
                value=entry["ip"],
                type=IoCType.ip,
                threat_level=ThreatLevel.high,
                confidence_score=80.0,
            )
            for entry in raw
        ]
```

2. Add it to `app/collectors/registry.py`:
```python
from app.collectors.my_feed import MyFeedCollector
ALL_COLLECTORS = [..., MyFeedCollector()]
```

3. Insert a row into `threat_sources` in the DB (or add to `schema.sql` seed data).

---

## Rate Limiting & Error Handling

- **API rate limits** — HTTP 429 responses are caught by `fetch_with_retry` with exponential backoff. The `Retry-After` header is honoured.
- **Timeouts** — Configurable via `HTTP_TIMEOUT_SECONDS` (default 30s).
- **Duplicate IoCs** — `ON CONFLICT` upsert logic ensures no duplicate rows; tags and families are merged.
- **Enrichment caching** — Live API responses are cached in PostgreSQL for `ENRICHMENT_CACHE_TTL_SECONDS` to avoid redundant lookups.
- **Background ingest failures** — Each collector failure is logged to `feed_fetch_logs` and the source's `error_message` is updated, without crashing other collectors.
