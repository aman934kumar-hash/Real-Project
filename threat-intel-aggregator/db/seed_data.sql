-- =============================================================
-- Threat Intelligence Aggregator — Sample / Mock IoC Data
-- Run AFTER schema.sql has been applied.
-- =============================================================

-- ── Sample IoCs ───────────────────────────────────────────────

INSERT INTO iocs (value, type, threat_level, confidence_score, tags, malware_families, country_code, asn, asn_org, raw_data)
VALUES
-- Malicious IPs
('185.220.101.45',  'ip', 'critical', 95.0,
 ARRAY['tor-exit-node','c2-server'],         ARRAY['emotet'],
 'DE', 200052, 'Tor Project',
 '{"note": "Known Tor exit node used for Emotet C2 traffic"}'),

('45.142.212.100',  'ip', 'high',     78.0,
 ARRAY['botnet','scanner'],                  ARRAY['trickbot'],
 'RU', 47272, 'LLC Baxet',
 '{"note": "TrickBot distribution IP — first seen in Jan 2024"}'),

('103.75.189.50',   'ip', 'high',     72.0,
 ARRAY['phishing','malware-dropper'],        ARRAY['qakbot'],
 'HK', 135377, 'NIPA Technology',
 '{"note": "QakBot dropper hosting infrastructure"}'),

('192.0.2.1',       'ip', 'low',      20.0,
 ARRAY['suspicious'],                        ARRAY[],
 'US', 15169, 'Google LLC',
 '{"note": "RFC 5737 documentation address — used for demo purposes"}'),

-- Malicious domains
('update-flash-player.ru',   'domain', 'critical', 92.0,
 ARRAY['phishing','fake-update'],            ARRAY['redline-stealer'],
 'RU', NULL, NULL,
 '{"note": "Fake Flash Player update — drops RedLine Stealer"}'),

('secure-paypal-login.com',  'domain', 'high',     85.0,
 ARRAY['phishing','credential-harvest'],     ARRAY[],
 'US', NULL, NULL,
 '{"note": "PayPal credential phishing page — active since 2024-03"}'),

('cdn-bootstrap-free.net',   'domain', 'medium',   60.0,
 ARRAY['typosquat','supply-chain'],          ARRAY[],
 'NL', NULL, NULL,
 '{"note": "Typosquat of bootstrap CDN — distributes malicious JS"}'),

-- File hashes — RedLine Stealer sample
('d41d8cd98f00b204e9800998ecf8427e',                 'hash_md5',    'critical', 98.0,
 ARRAY['ransomware','wiper'],                ARRAY['notpetya'],
 NULL, NULL, NULL,
 '{"note": "MD5 of NotPetya wiper sample (famous empty hash for demo)"}'),

('aec070645fe53ee3b3763059376134f058cc337247c978376971037851d1e25f', 'hash_sha256', 'high', 88.0,
 ARRAY['infostealer'],                       ARRAY['redline-stealer'],
 NULL, NULL, NULL,
 '{"note": "RedLine Stealer SHA256 — observed in phishing attachment"}'),

('da39a3ee5e6b4b0d3255bfef95601890afd80709',          'hash_sha1',   'medium',   55.0,
 ARRAY['downloader'],                        ARRAY['guloader'],
 NULL, NULL, NULL,
 '{"note": "GuLoader dropper SHA1 hash"}'),

-- URLs
('http://malware-delivery.xyz/payload.exe', 'url', 'critical', 96.0,
 ARRAY['malware-download','dropper'],        ARRAY['asyncrat'],
 'CN', NULL, NULL,
 '{"note": "AsyncRAT payload delivery URL"}'),

-- Email IOC
('no-reply@secure-update.top', 'email', 'high', 80.0,
 ARRAY['phishing','spoofed-sender'],         ARRAY[],
 NULL, NULL, NULL,
 '{"note": "Phishing sender address used in credential-harvest campaign"}');


-- ── Map IoCs to threat sources ────────────────────────────────

-- Link all IP IoCs to AbuseIPDB
INSERT INTO ioc_source_mappings (ioc_id, source_id, source_severity, source_confidence, raw_entry)
SELECT
    i.id,
    s.id,
    i.threat_level,
    i.confidence_score,
    jsonb_build_object('mapped_by', 'seed_data')
FROM iocs i
CROSS JOIN threat_sources s
WHERE i.type = 'ip' AND s.name = 'AbuseIPDB'
ON CONFLICT DO NOTHING;

-- Link domain/URL IoCs to AlienVault OTX
INSERT INTO ioc_source_mappings (ioc_id, source_id, source_severity, source_confidence, raw_entry)
SELECT
    i.id,
    s.id,
    i.threat_level,
    i.confidence_score,
    jsonb_build_object('mapped_by', 'seed_data')
FROM iocs i
CROSS JOIN threat_sources s
WHERE i.type IN ('domain', 'url', 'email') AND s.name = 'AlienVault OTX'
ON CONFLICT DO NOTHING;

-- Link hash IoCs to VirusTotal
INSERT INTO ioc_source_mappings (ioc_id, source_id, source_severity, source_confidence, raw_entry)
SELECT
    i.id,
    s.id,
    i.threat_level,
    i.confidence_score,
    jsonb_build_object('mapped_by', 'seed_data')
FROM iocs i
CROSS JOIN threat_sources s
WHERE i.type IN ('hash_md5', 'hash_sha1', 'hash_sha256') AND s.name = 'VirusTotal'
ON CONFLICT DO NOTHING;


-- ── Sample Alerts ─────────────────────────────────────────────

INSERT INTO alerts (title, description, severity, status, source_system, external_ref, affected_asset, raw_alert)
VALUES
(
    'Outbound connection to known C2 IP',
    'Workstation WS-042 made repeated outbound TCP connections to 185.220.101.45 on port 443.',
    'critical',
    'open',
    'Splunk SIEM',
    'INC-20240501-001',
    'WS-042 (192.168.1.42)',
    '{"rule": "Outbound C2 Detection", "hit_count": 47, "first_event": "2024-05-01T08:22:00Z"}'
),
(
    'Phishing email received — fake PayPal login',
    'User reported phishing email with link to secure-paypal-login.com.',
    'high',
    'investigating',
    'Exchange Online',
    'INC-20240501-002',
    'user@example.com',
    '{"email_subject": "Your PayPal account is limited", "sender": "no-reply@secure-update.top"}'
),
(
    'Suspicious file hash detected on endpoint',
    'EDR flagged file with SHA256 aec070645fe53ee3b3763059376134f058cc337247c978376971037851d1e25f.',
    'high',
    'open',
    'CrowdStrike Falcon',
    'INC-20240501-003',
    'LAPTOP-HR-07',
    '{"process_name": "svchost.exe", "path": "C:\\Users\\user\\AppData\\Local\\Temp\\"}'
);


-- ── Link alerts to IoCs ───────────────────────────────────────

INSERT INTO alert_ioc_mappings (alert_id, ioc_id, matched_on, notes)
SELECT a.id, i.id, i.value, 'Seeded from sample data'
FROM alerts a
CROSS JOIN iocs i
WHERE a.external_ref = 'INC-20240501-001' AND i.value = '185.220.101.45'
ON CONFLICT DO NOTHING;

INSERT INTO alert_ioc_mappings (alert_id, ioc_id, matched_on, notes)
SELECT a.id, i.id, i.value, 'Seeded from sample data'
FROM alerts a
CROSS JOIN iocs i
WHERE a.external_ref = 'INC-20240501-002' AND i.value = 'secure-paypal-login.com'
ON CONFLICT DO NOTHING;

INSERT INTO alert_ioc_mappings (alert_id, ioc_id, matched_on, notes)
SELECT a.id, i.id, i.value, 'Seeded from sample data'
FROM alerts a
CROSS JOIN iocs i
WHERE a.external_ref = 'INC-20240501-003'
  AND i.value = 'aec070645fe53ee3b3763059376134f058cc337247c978376971037851d1e25f'
ON CONFLICT DO NOTHING;
