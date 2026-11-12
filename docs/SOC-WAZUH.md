# Spark SOC + Wazuh (read-only)

## What is real
- Endpoint agents (online/offline, version, groups) come from the Wazuh Manager API (port 55000).
- Alerts (severity, time, MITRE) come from the Wazuh Indexer (OpenSearch, port 9200, `wazuh-alerts-*`). The Manager API does not serve alerts, so the Indexer is required.
- Nothing is generated. With no Wazuh configured the page says NOT CONNECTED. Self-test data is labelled TEST (demo) and removable.

## Two modes
1. **Bridge (recommended)** – run `collector/wazuh/wazuh-bridge.mjs` next to Wazuh. Outbound-only; Wazuh credentials never leave that host.
   `SPARK_URL=https://your-spark SPARK_INGEST_TOKEN=... WAZUH_API_URL=... WAZUH_API_USER=... WAZUH_API_PASSWORD=... WAZUH_INDEXER_URL=... WAZUH_INDEXER_USER=... WAZUH_INDEXER_PASSWORD=... node wazuh-bridge.mjs`
2. **Direct** – set the WAZUH_* server variables (`.env.example`). Sync runs on "Sync now" or by an external scheduler calling `POST /api/soc/wazuh/sync` with the ingest token.

## Credentials
Server environment only. Never in the frontend. Create dedicated users: Manager API user with the `readonly` role, Indexer user with read on `wazuh-alerts-*`. The health check flags accounts with write roles. TLS verification is always on; use `NODE_EXTRA_CA_CERTS` for a private CA.

## Read-only guarantee
The client only does GET, the authenticate POST and Indexer `_search`. No active response or agent commands exist in code.

## Endpoints
GET `/api/soc/wazuh/status` (read) · POST `wazuh/sync` (ingest) · POST `wazuh/test/connection|event|cleanup` (admin approve) · POST `ingest/wazuh`, GET `wazuh/cursor`, POST `wazuh/bridge-error|bridge-test` (ingest token). Apply `supabase/008_wazuh.sql`.

## Detections
Brute force, suspicious Windows logons, privilege escalation, suspicious PowerShell, malware indicators, file integrity (sensitive paths raised to high), suspicious network activity. Wazuh rule level ≥ `WAZUH_MIN_LEVEL` becomes an alert (`WZH-<rule id>`). MITRE comes from Wazuh; Spark infers only T1110 (brute force) and T1059.001 (PowerShell) and says so in the alert reasoning. Windows-channel alerts also run through Spark's Windows rules.

## Honest limits
- Tested only against local fake Wazuh servers, not a real deployment. Expect to verify TLS, roles and index names on first connection.
- Wazuh SCA and vulnerability data are not ingested; the Security Engineer agent uses Greenbone imports and Wazuh alerts.
- No scheduler in direct mode; the bridge polls.
- AI analysis needs `ANTHROPIC_API_KEY`.
- The static Hostinger/WordPress pages show demo/not-connected; deploy the backend for live data.

## Acceptance checklist
1. Status shows NOT CONNECTED before configuring.
2. Run "Test connection": 7 steps pass (read-only account step included).
3. Agents appear with correct online/offline.
4. A real failed-login burst creates a brute-force alert with evidence.
5. "Send security event test" appears labelled TEST; "Remove test data" removes it.
