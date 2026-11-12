# Spark NOC: real monitoring with Zabbix

This turns the NOC page from a demo into a view of real monitoring data. Read "What works and what does not" first.

## What works and what does not (honest status)

| Area | Status |
|---|---|
| Zabbix 6.4+ API (pull) and bridge (push) | Built. Tested only against a **fake Zabbix server** that mimics the API. Not yet tested against your real Zabbix. |
| SNMPv3, ICMP, Agent 2, HTTP checks | Collected **by Zabbix**. Spark reads the resulting items. Spark has no SNMP poller of its own. |
| Prometheus, Grafana | Alerts only, through `POST /api/soc/noc/alerts`. Metric scraping is not built. |
| Syslog | Not collected. Use Zabbix log items or forward alerts to the webhook. |
| Alerts to incidents, 14-step workflow, six agents, approvals, execution, verification | Built and tested (54 automated tests, mock Zabbix). |
| Real router / real switch / real alert / real approved action | **Needs your Zabbix and devices.** See the acceptance checklist. |
| Background monitoring | Spark does not poll by itself. Data arrives when the bridge pushes, when someone presses Sync, or when the page is open (the page only reads). To poll without the bridge, schedule `POST /api/soc/noc/sources/<id>/sync` (for example Vercel Cron). |
| Live push to browser | The page polls `/api/soc/noc/overview` every 10 s. SSE/WebSocket are not used because the backend is serverless. |

## Architecture

```
 Routers/switches/firewalls (SNMPv3)  Servers (Agent 2)  VMs  HTTP checks
              \                         |                 /
               +------------- Zabbix server (Ubuntu VM on VMware) ------------+
                                        |  (API on localhost / LAN)           |
                       zabbix-bridge.mjs (runs on the same VM, OUTBOUND only)  |
                                        v  HTTPS + ingest token               |
                        Spark backend /api/soc/noc/*  -->  database (Supabase)
                                        ^
                              Browser page (polls /noc/overview, admin token)
```

Why a bridge: your Zabbix VM is on a private network. A cloud-hosted backend (Vercel) cannot connect into it. The bridge makes only outbound HTTPS calls, so you open no inbound port. If your backend can reach Zabbix (same LAN, VPN, or tunnel), you can instead create a **pull** source and skip the bridge.

## 1. Backend setup

1. Run `supabase/004_soc_phase3.sql`, `005_noc.sql`, then `006_noc_realtime.sql` in the Supabase SQL editor.
2. Environment variables on the backend:
   - `SOC_ADMIN_TOKEN`, `SOC_ANALYST_TOKEN`, `SOC_VIEWER_TOKEN`, `SOC_INGEST_TOKEN` (16+ random characters each)
   - `NOC_SECRET_KEY` (32+ random characters). Without it the backend **refuses** to store any credential. Losing it makes stored credentials unreadable (you re-enter them).
   - Optional: `NOC_ALLOWED_HOSTS=zabbix.example.lan` (only these hosts may be used as source or webhook URLs), `ANTHROPIC_API_KEY` (adds AI text to analysis; labeled as hypotheses).
3. Open the site, go to NOC AI Agents, and sign in with the admin token (the page asks for it).

## 2. Zabbix server on an Ubuntu VMware VM

1. Install Zabbix 6.4 or newer (server, frontend, agent 2) following https://www.zabbix.com/download for your Ubuntu version.
2. In Zabbix: **Users > API tokens > Create** a token for a user with read access to the host groups (read-write only if you will use scripts). Copy the token.
3. Test from the VM: `curl -s -H 'Content-Type: application/json-rpc' -d '{"jsonrpc":"2.0","method":"apiinfo.version","id":1}' http://localhost/api_jsonrpc.php` should print a version.

## 3. Add devices

- **Routers, managed switches, firewalls (SNMPv3):** on the device enable SNMPv3 (authPriv, SHA + AES, a dedicated read-only user). In Zabbix: Data collection > Hosts > Create host, group `Routers` / `Switches` / `Firewalls`, add an SNMP interface (version SNMPv3, security level authPriv, your credentials), link template `Network Generic Device by SNMP` or the vendor template. Use SNMPv2c only for gear that cannot do v3 and only on an isolated management VLAN.
- **Linux/Windows servers:** install Zabbix Agent 2, point `Server=` at the Zabbix VM, link `Linux by Zabbix agent` / `Windows by Zabbix agent`. Put them in a group named `Linux servers` / `Windows servers`.
- **VMs:** link `VMware` templates (or agent). **HTTP checks:** a web scenario or `net.tcp.service` item. **Ping:** template `ICMP Ping`.
- Spark guesses a device's type from its host group, so name groups sensibly. A metric Zabbix does not collect for a device shows as **no data** and is listed under that device's unsupported metrics. Spark never fills it in.

## 4. Connect Spark

**Option A, bridge (recommended for a private Zabbix):**
1. In the NOC page, *Add a monitoring source*: type Zabbix, mode **push**, name it. Copy the source id from the API (`GET /api/soc/noc/overview` shows it).
2. On the Zabbix VM (Node 18+), copy the `collector/zabbix/` folder and run:
   ```
   ZABBIX_URL=http://localhost ZABBIX_TOKEN=<zabbix token> SPARK_URL=https://your-site \
   SPARK_INGEST_TOKEN=<ingest token> SPARK_SOURCE_ID=<source id> node zabbix-bridge.mjs
   ```
   Run it as a systemd service so it restarts. It pushes every 60 s and picks up approved actions.

**Option B, pull:** add a source with mode **pull**, the Zabbix base URL (e.g. `https://zabbix.example.lan`) and the token. Press **Test**, then **Sync now**.

The status column shows CONNECTED / DISCONNECTED / AUTHENTICATION FAILED / NO DATA / ERROR from real results. If data stops for longer than the stale window (default 300 s) the source flips to DISCONNECTED automatically and an incident is opened once.

## 5. Alerts

Alerts are also picked up by every sync/push (Zabbix problems). For faster delivery, create a Zabbix media type (Webhook) that POSTs JSON to
`https://your-site/api/soc/noc/alerts?source=<source id>` with header `Authorization: Bearer <ingest token>` and body:
`{"source":"zabbix","eventid":"{EVENT.ID}","host":"{HOST.NAME}","ip":"{HOST.IP}","name":"{EVENT.NAME}","severity":"{EVENT.SEVERITY}","status":"{EVENT.STATUS}","message":"{TRIGGER.DESCRIPTION}"}`.
Grafana (contact point: webhook) and Prometheus Alertmanager (webhook receiver) post their standard JSON to the same URL. Duplicate deliveries are ignored.

## 6. Automation (approved actions only)

Agents cannot run anything on their own. An administrator registers actions; agents may only **propose** them, and each needs an administrator's approval.
1. In Zabbix create a script (Alerts > Scripts) that does one specific safe thing, e.g. restart one service. Note its id.
2. Register it: `POST /api/soc/noc/actions` (admin) `{"name":"Restart web app","description":"...","kind":"zabbix_script","sourceId":"<id>","scriptId":"7","match":"cpu","risk":"high"}`. (`kind:"webhook"` with `webhookUrl` is also supported.)
3. When a matching incident appears, an approval request is created. Approve in the page: the backend (pull) or the bridge (push) runs the script. The result is "succeeded" only if Zabbix confirms; the incident is "Resolved" only when fresh data shows the problem cleared.
No registered action touches firewalls/routers/switches by default; do not register such scripts until you have tested them.

## API summary (all under /api/soc, Bearer token)

| Endpoint | Role |
|---|---|
| `GET noc/overview` | read |
| `POST noc/sources`, `POST noc/sources/:id/test`, `POST noc/sources/:id/sync`, `DELETE noc/sources/:id`, `POST noc/actions` | admin |
| `POST noc/approvals/:id/approve` or `/reject` | admin |
| `POST noc/agents/:supervisor\|engineer\|server\|performance\|responder\|automation/run` | analyst+ |
| `POST noc/incidents/:id/verify` | analyst+ |
| `POST noc/push`, `POST noc/alerts`, `GET noc/executions/pending`, `POST noc/executions/:id/result` | ingest token |

Security: tokens per role, credentials AES-256-GCM encrypted (never returned), URL validation (http/https only, link-local/metadata blocked, optional allowlist), per-instance rate limits, hash-chained audit log, all writes audited, nothing executes without approval.

## Acceptance checklist

Tested here means automated tests plus the fake-Zabbix browser run. It does not count as a real device test.

| # | Test | Status |
|---|---|---|
| 1 | Connects to a real Zabbix server | **Needs your Zabbix** (code tested with a fake) |
| 2 | At least one real router | **Needs your router in Zabbix** |
| 3 | At least one real managed switch | **Needs your switch in Zabbix** |
| 4 | Real metrics displayed | **Needs real source**; no-data handling tested |
| 5 | Real Zabbix alert received | **Needs real Zabbix**; webhook/problem parsing tested |
| 6 | AI agent analyzes the alert | Passed (rule-based; AI text needs ANTHROPIC_API_KEY) |
| 7 | Incident record created | Passed |
| 8 | Recommendation generated | Passed |
| 9 | Approved action executes | Passed against fake Zabbix via pull and bridge; **needs real script** |
| 10 | Fresh data verifies the result | Passed (fake Zabbix); needs real |
| 11 | Disconnection detected | Passed |
| 12 | All six agents demonstrate their functions | Passed on stored data |
