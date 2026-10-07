-- ============================================================
-- Threat Intelligence Aggregator — PostgreSQL DDL
-- ============================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";   -- for fast text search on ioc values

-- ------------------------------------------------------------
-- ENUM TYPES
-- ------------------------------------------------------------

CREATE TYPE ioc_type AS ENUM ('ip', 'domain', 'hash_md5', 'hash_sha1', 'hash_sha256', 'url', 'email');

CREATE TYPE threat_level AS ENUM ('critical', 'high', 'medium', 'low', 'informational', 'unknown');

CREATE TYPE alert_status AS ENUM ('open', 'investigating', 'resolved', 'false_positive');

CREATE TYPE feed_status AS ENUM ('active', 'paused', 'error', 'disabled');

-- ------------------------------------------------------------
-- TABLE: threat_sources
--   Catalogue of every external threat feed / provider
-- ------------------------------------------------------------

CREATE TABLE threat_sources (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(100)  NOT NULL UNIQUE,
    provider        VARCHAR(100)  NOT NULL,
    feed_url        TEXT,
    api_key_env_var VARCHAR(100),                        -- env var that holds the API key
    status          feed_status   NOT NULL DEFAULT 'active',
    fetch_interval  INTEGER       NOT NULL DEFAULT 3600, -- seconds between polls
    last_fetched_at TIMESTAMPTZ,
    last_ioc_count  INTEGER,
    error_message   TEXT,
    metadata        JSONB         NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- ------------------------------------------------------------
-- TABLE: iocs
--   Core table — one row per unique (value, type) pair
-- ------------------------------------------------------------

CREATE TABLE iocs (
    id               UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    value            TEXT         NOT NULL,
    type             ioc_type     NOT NULL,
    threat_level     threat_level NOT NULL DEFAULT 'unknown',
    confidence_score NUMERIC(5,2) NOT NULL DEFAULT 0
                         CHECK (confidence_score BETWEEN 0 AND 100),
    first_seen       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_seen        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expiry_date      TIMESTAMPTZ,
    is_active        BOOLEAN      NOT NULL DEFAULT TRUE,
    tags             TEXT[]       NOT NULL DEFAULT '{}',
    country_code     CHAR(2),
    asn              INTEGER,
    asn_org          VARCHAR(255),
    malware_families TEXT[]       NOT NULL DEFAULT '{}',
    raw_data         JSONB        NOT NULL DEFAULT '{}',
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_ioc_value_type UNIQUE (value, type)
);

-- ------------------------------------------------------------
-- TABLE: ioc_source_mappings
--   Many-to-many: which source reported which IoC
-- ------------------------------------------------------------

CREATE TABLE ioc_source_mappings (
    id               UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    ioc_id           UUID        NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    source_id        UUID        NOT NULL REFERENCES threat_sources(id) ON DELETE CASCADE,
    external_id      TEXT,                          -- source's own identifier
    reported_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_severity  threat_level,
    source_confidence NUMERIC(5,2)
                         CHECK (source_confidence BETWEEN 0 AND 100),
    raw_entry        JSONB       NOT NULL DEFAULT '{}',

    CONSTRAINT uq_ioc_source UNIQUE (ioc_id, source_id)
);

-- ------------------------------------------------------------
-- TABLE: alerts
--   Security events / SIEM alerts that may reference IoCs
-- ------------------------------------------------------------

CREATE TABLE alerts (
    id              UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    status          alert_status NOT NULL DEFAULT 'open',
    severity        threat_level NOT NULL DEFAULT 'unknown',
    source_system   VARCHAR(100),                        -- SIEM, firewall, EDR…
    external_ref    VARCHAR(255),                        -- ticket/alert ID in source system
    affected_asset  VARCHAR(500),
    raw_alert       JSONB        NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ
);

-- ------------------------------------------------------------
-- TABLE: alert_ioc_mappings
--   IoCs discovered/linked during alert enrichment
-- ------------------------------------------------------------

CREATE TABLE alert_ioc_mappings (
    id           UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id     UUID        NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    ioc_id       UUID        NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    matched_on   TEXT        NOT NULL,   -- the literal value that triggered the match
    enriched_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    notes        TEXT,

    CONSTRAINT uq_alert_ioc UNIQUE (alert_id, ioc_id)
);

-- ------------------------------------------------------------
-- TABLE: enrichment_cache
--   Short-lived cache of live API lookups (VirusTotal, etc.)
-- ------------------------------------------------------------

CREATE TABLE enrichment_cache (
    id           UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    ioc_value    TEXT        NOT NULL,
    ioc_type     ioc_type    NOT NULL,
    provider     VARCHAR(100) NOT NULL,
    response     JSONB       NOT NULL DEFAULT '{}',
    fetched_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL,

    CONSTRAINT uq_cache_entry UNIQUE (ioc_value, ioc_type, provider)
);

-- ------------------------------------------------------------
-- TABLE: feed_fetch_logs
--   Audit trail for every scheduled / manual feed pull
-- ------------------------------------------------------------

CREATE TABLE feed_fetch_logs (
    id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_id     UUID        NOT NULL REFERENCES threat_sources(id) ON DELETE CASCADE,
    started_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at   TIMESTAMPTZ,
    iocs_fetched  INTEGER     NOT NULL DEFAULT 0,
    iocs_inserted INTEGER     NOT NULL DEFAULT 0,
    iocs_updated  INTEGER     NOT NULL DEFAULT 0,
    errors        INTEGER     NOT NULL DEFAULT 0,
    status        VARCHAR(50) NOT NULL DEFAULT 'running',
    error_details TEXT
);

-- ============================================================
-- INDEXES
-- ============================================================

-- Fast exact lookup on IoC value (most common query)
CREATE INDEX idx_iocs_value       ON iocs (value);
CREATE INDEX idx_iocs_type        ON iocs (type);
CREATE INDEX idx_iocs_threat_level ON iocs (threat_level);
CREATE INDEX idx_iocs_last_seen   ON iocs (last_seen DESC);
CREATE INDEX idx_iocs_is_active   ON iocs (is_active) WHERE is_active = TRUE;
CREATE INDEX idx_iocs_confidence  ON iocs (confidence_score DESC);

-- GIN indexes for array columns and full-text similarity
CREATE INDEX idx_iocs_tags            ON iocs USING GIN (tags);
CREATE INDEX idx_iocs_malware_families ON iocs USING GIN (malware_families);
CREATE INDEX idx_iocs_raw_data        ON iocs USING GIN (raw_data);

-- Trigram index for LIKE / ILIKE searches on value
CREATE INDEX idx_iocs_value_trgm ON iocs USING GIN (value gin_trgm_ops);

-- Alert indexes
CREATE INDEX idx_alerts_status   ON alerts (status);
CREATE INDEX idx_alerts_severity ON alerts (severity);
CREATE INDEX idx_alerts_created  ON alerts (created_at DESC);

-- Mapping indexes
CREATE INDEX idx_ioc_source_ioc_id    ON ioc_source_mappings (ioc_id);
CREATE INDEX idx_ioc_source_source_id ON ioc_source_mappings (source_id);
CREATE INDEX idx_alert_ioc_alert_id   ON alert_ioc_mappings (alert_id);
CREATE INDEX idx_alert_ioc_ioc_id     ON alert_ioc_mappings (ioc_id);

-- Cache expiry index
CREATE INDEX idx_cache_expires ON enrichment_cache (expires_at);

-- ============================================================
-- FUNCTIONS & TRIGGERS — auto-update `updated_at`
-- ============================================================

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_iocs_updated_at
    BEFORE UPDATE ON iocs
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_alerts_updated_at
    BEFORE UPDATE ON alerts
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_threat_sources_updated_at
    BEFORE UPDATE ON threat_sources
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ============================================================
-- SEED: default threat sources
-- ============================================================

INSERT INTO threat_sources (name, provider, feed_url, api_key_env_var, fetch_interval, metadata) VALUES
(
    'AlienVault OTX',
    'AlienVault',
    'https://otx.alienvault.com/api/v1',
    'OTX_API_KEY',
    3600,
    '{"description": "Open Threat Exchange — community-powered threat intelligence"}'
),
(
    'AbuseIPDB',
    'AbuseIPDB',
    'https://api.abuseipdb.com/api/v2',
    'ABUSEIPDB_API_KEY',
    7200,
    '{"description": "IP address abuse reporting and lookup service"}'
),
(
    'VirusTotal',
    'VirusTotal',
    'https://www.virustotal.com/api/v3',
    'VIRUSTOTAL_API_KEY',
    300,
    '{"description": "Aggregated AV engine scanning for files, URLs, IPs, domains"}'
),
(
    'CISA Known Exploited Vulnerabilities',
    'CISA',
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    NULL,
    86400,
    '{"description": "CISA KEV catalog — no API key required"}'
),
(
    'Feodo Tracker',
    'abuse.ch',
    'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
    NULL,
    3600,
    '{"description": "C2 server IP blocklist from abuse.ch Feodo Tracker"}'
);
