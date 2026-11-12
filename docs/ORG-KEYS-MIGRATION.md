# Moving collectors from legacy shared tokens to organization keys

**Status: documented only. Nothing has been changed in production. Legacy tokens stay ON (`SOC_LEGACY_TOKENS` unset or `on`) until a real collector has been tested with an organization key and every collector has moved.**

## Why
A legacy token (`SOC_ADMIN_TOKEN` and friends) belongs to the Default organization and is shared by every collector that uses it. An organization key (`aa_live_…`) belongs to exactly one organization, is stored only as a hash, can be revoked on its own, shows its last-used time, and can send collector data only (the `ingest` permission). A leaked key exposes one organization's ingest path, nothing else.

## Collectors affected (all read `SPARK_URL` + `SPARK_INGEST_TOKEN`, so the change is the token value only; no code change)
| Collector | File | Where the token lives today |
|---|---|---|
| Wazuh bridge | `collector/wazuh/wazuh-bridge.mjs` | service environment / systemd unit / container env |
| Windows security collector | `collector/windows/Send-SecurityEvents.ps1` | scheduled-task environment or the script's env |
| Zabbix bridge | `collector/zabbix/zabbix-bridge.mjs` | service environment |
| Discovery agent | `collector/discovery/discovery-agent.mjs` | service environment |
| NOC Linux / Windows agents (new) | `collector/noc-agent/*` | service environment; **start these on an org key from day one** |

## Steps (per organization, per collector)
1. **Create the key** (owner or IT admin): Account page → Organization → API keys → *Create*, or `POST /api/soc/org/keys {"name":"wazuh-bridge-dc01"}`. Name it after the collector and host. The key is shown **once**; store it in the host's secret store, not in a repo or ticket.
2. **Add the new key next to the old one** on one collector host only: set `SPARK_INGEST_TOKEN=aa_live_…`, restart the collector. Leave every other collector on the legacy token.
3. **Test it for real** (see below). Watch the key's *last used* time update in the keys list and new events/devices arrive in *this* organization.
4. **Repeat** host by host. Keep a checklist; each collector gets its own key so one can be revoked alone.
5. **Prove nothing still uses the legacy token** before turning it off. Today the platform does **not** record per-request which credential type was used, so this cannot be read from a screen. Use the inventory instead: every collector host listed in the table above has a checklist tick for "now on an org key" AND each org key shows a recent *last used* time. Open item: add a "legacy token used" counter/audit line so the last legacy use is visible (recommended before step 6). Wait a full normal cycle (at least 7 days) after the last host moves.
6. **Only then**, with explicit approval from the owner: set `SOC_LEGACY_TOKENS=off` in the Hostinger environment and redeploy. Rollback = set it back to `on`.
7. **Rotate**: revoke and recreate a key whenever a host is retired or someone with access leaves.

## Real-collector test (required before step 6)
* Wazuh bridge: point it at a **real** Wazuh manager/indexer, run one cycle with the org key, confirm alerts appear in that org's SOC page and not in another org.
* Windows collector: run on a **real** Windows host, trigger a failed logon (4625), confirm the event arrives.
* NOC Linux agent: `ONCE=1 SPARK_URL=… SPARK_INGEST_TOKEN=aa_live_… collector/noc-agent/auto-adjust-linux-agent.sh` → prints `sent … bytes`; the device shows on the NOC page with real CPU/RAM/disk.
* NOC Windows agent: `.\Auto-Adjust-Windows-Agent.ps1 -DryRun` first (prints the JSON), then `-Once`. **This script has not yet run on a Windows host; treat the first run as its test.**
* Negative test: a wrong or revoked key must return 401 and the collector must log the failure rather than silently retry forever.

## What has and has not been proven so far
* Proven in automated tests: key creation/hash storage, org-scoped ingest, cross-org isolation, revoked/wrong key rejected, the Linux agent end to end over HTTP with an org key (`tests/live/agent-e2e.ts`).
* **Not yet proven:** any production collector on an org key; the Wazuh bridge and Windows security collector with an org key against real Wazuh / real Windows.
