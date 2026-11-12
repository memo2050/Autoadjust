# Network Topology and Infrastructure Discovery

The NOC page has a topology platform: define an approved network, discover devices with an agent inside that network, see the generated map, monitor it, investigate, edit the map, and apply approved configuration changes.

## What runs where

| Piece | Where | Why |
|---|---|---|
| Web page (map, discovery, changes, health) | Browser | No credentials ever reach it |
| API, database, scope check, topology graph, change approvals, audit | Spark backend (`/api/soc/noc/*`) | Serverless; it cannot reach private networks |
| **Discovery agent** `collector/discovery/discovery-agent.mjs` | A machine **inside** your network | Does the ICMP/TCP/ARP/SNMP work and holds SNMP credentials. Outbound HTTPS only, no inbound port |
| Config executor (your script, optional) | Same machine | The only piece that logs in to devices |

**The Spark backend cannot scan.** Without an online agent, scan jobs stay *queued*. This is shown on the page.

## Setup
1. Backend: set `SOC_ADMIN_TOKEN`, `SOC_ANALYST_TOKEN`, `SOC_VIEWER_TOKEN`, `SOC_INGEST_TOKEN`, and `NOC_SECRET_KEY` (32+ random characters; needed to hold configs for rollback). Run `supabase/007_topology.sql` after `006`.
2. On a Linux box in the network (Node 18+, `ping`; optional `snmpget`/`snmpwalk` from net-snmp, `ip` or `arp`):
   ```
   SPARK_URL=https://your-site SPARK_INGEST_TOKEN=... AGENT_NAME=hq-agent \
   SNMP_COMMUNITY=... node collector/discovery/discovery-agent.mjs
   ```
   For SNMPv3 set `SNMP_V3_ARGS="-v3 -l authPriv -u user -a SHA -A ... -x AES -X ..."`. These values stay on that machine.
3. In the page: *Network Discovery* → approve a scope (tick the authorization box) → start a scan → watch progress → *Topology*.

## Safety rules enforced by the backend
- A scope needs an explicit authorization confirmation and the **admin** role. Only private ranges (10/8, 172.16/12, 192.168/16, 100.64/10) are accepted unless the operator sets `NOC_ALLOW_PUBLIC_SCAN=1`. Max size `NOC_MAX_SCAN_HOSTS` (default 65536).
- Results for hosts outside the scope are discarded and counted (`out-of-scope discarded`) and audited.
- Intensity low/normal/high = 10/50/200 probes per second; the agent obeys it. Scan starts are rate-limited. One active scan per scope.
- No credential is accepted, stored, or returned by any scan or topology endpoint. Config text is redacted for display (everything after `password`, `secret`, `community`, `key`, `auth`, `priv`, `token` …) and the original is stored AES-256-GCM encrypted. The diff is computed on redacted text, so a change to only a secret does not show in the diff.
- Every scope, scan, adoption, map save, backup, proposal, approval, result and rollback goes into the hash-chained audit log.

## Map editing never touches devices
Positions, labels, zones, VLAN/subnet/zone groups, manual devices and manual links are a versioned overlay (`noc_maps`, `noc_map_versions`). Saving needs the *analyst* role, uses optimistic versioning (409 on conflict), can be restored from history, and the API says "no network device was touched". Discovered IP/MAC cannot be edited because they come from evidence.

## Status honesty
- A device found only by a scan shows **Discovered (not monitored)**, never Healthy.
- Health, latency, loss, CPU come from a monitoring source (Zabbix bridge, push telemetry). No data means Unknown.
- Links come only from agent-reported neighbors (LLDP via SNMP), monitoring telemetry, or manual edits. If devices do not report neighbors, there are no links; nothing is guessed.
- Root cause / affected: offline devices are removed from the graph; devices cut off from the root are *affected* (status unknown, not failed); an offline device next to the reachable part is a *probable root cause*. A hypothesis, not proof.
- SOC overlay: alerts and open incidents whose host/IP matches a device; an open high/critical incident marks it *possibly compromised*. Discovered-but-unapproved devices are *unmanaged assets*; an admin can approve them. Firewall events appear only after a SOC log source for that firewall exists (none is built in).

## Configuration changes
`propose (analyst) → approve (admin, must type the device name) → agent runs executor: backup, apply, read back → result`.
- **applied** only if the executor succeeded **and** every proposed line is in the read-back running config. Missing read-back or missing lines → **unverified**. Executor failure → **failed**.
- Rollback creates a new proposal from the pre-change backup and needs approval again. No backup (or no `NOC_SECRET_KEY`) means no rollback.
- `CONFIG_EXECUTOR` is an executable you provide for your vendor (SSH/NETCONF/API). It gets JSON on stdin `{action: backup|apply|readback, device, proposed}` and prints the config text. **Spark ships no vendor executor**, so until you supply one every approved change ends **failed** with "No CONFIG_EXECUTOR is configured". Nothing is applied.

## Endpoints (all under `/api/soc/`)
Read: `noc/topology?map=`, `noc/discovery`, `noc/maps`, `noc/maps/:id/versions`, `noc/changes`. Analyst: `POST noc/maps`, `noc/maps/:id/save`, `/restore`, `noc/backups/:deviceId` (GET/POST), `POST noc/changes`. Admin: `noc/scopes` (POST/DELETE), `noc/scans` (POST), `/cancel`, `noc/devices/:id/adopt`, `noc/changes/:id/approve|reject|rollback`. Agent (ingest token): `GET noc/scans/pending`, `POST noc/scans/:id/progress|complete`, `GET noc/changes/pending`, `POST noc/changes/:id/backup|result`.

## Not built / honest limits
- Live updates are polling (about every 8 s), not WebSockets (serverless host).
- Scanning, SNMP/LLDP and config pushing were **not tested against real devices** here. Tested: all backend rules (`tests/noc-topology.test.ts`), the agent scanning loopback over TCP against a local backend, and the UI in a browser with an agent simulated by test requests.
- No vendor config executor, no NetFlow/sFlow, no wireless controller or cloud inventory adapters, no CDP-only parsing, no IPv6.
- Demo mode (no backend) uses a labeled sample network; saves stay in the browser; scanning and changes are disabled.

## Acceptance checklist (do these on your real network)
1. Start the agent; the page shows it online. 2. Approve a small scope, scan; hosts appear. 3. Confirm hosts outside the scope never appear. 4. With SNMP credentials on the agent, confirm names and LLDP links appear. 5. Connect Zabbix; confirm status turns from Discovered to Healthy/Warning. 6. Unplug an access switch; confirm offline, root cause and affected devices. 7. Open a SOC incident for a host; confirm the badge. 8. Move devices, save, restore an old version; confirm no device changed. 9. Provide an executor, propose a harmless change on a lab device, approve, confirm *applied* only after read-back; try rollback.
