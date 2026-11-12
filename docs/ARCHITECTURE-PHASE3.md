# Phase 3 – Network Operations Center (NOC) architecture

Auto Adjust NOC is organization-scoped end to end: every read and write goes through `ScopedStore`, so a request can only touch its own organization's rows; RLS and revoked table grants (Phase 1/4 SQL, **not yet applied to production**) are the second lock.

## Data flow
```
 Linux agent (bash)  ─┐                                         ┌─ noc_devices  (current state + short history)
 Windows agent (PS)  ─┼─ POST /api/soc/noc/telemetry ──► ingestAndEvaluate ─┼─ noc_metrics  (every sample, long history)
 Zabbix bridge/API   ─┤   (org key aa_live_…, ingest role)      │            ├─ noc_events   (problem / resolved, deduplicated)
 Discovery agent     ─┘                                         │            └─ noc_incidents (14-step workflow, 6 NOC agents)
                                                                ▼
                       thresholds (NOC_THRESHOLDS) → conditions() → open / update / resolve
 sweepDevices() on every overview request: device silent > staleAfterSec (default 300 s) → "No data from X" incident
```
## Modules
| Module | Role |
|---|---|
| `lib/soc/noc.ts` | device model, `ingestTelemetry`, `deviceStatus`, thresholds |
| `lib/noc/realtime.ts` (new) | evaluation of telemetry, dedupe, recovery, stale sweep, availability %, metric history |
| `lib/noc/ops.ts` | sources, Zabbix/webhook actions (SSRF-guarded), `processAlert` 14-step workflow, `onResolved` |
| `lib/noc/agents.ts` | the 6 NOC agents (supervisor, engineer, server, performance, responder, automation): rule-based, optional AI text; recommendations are only proposed, approvals enforced by role |
| `lib/noc/discovery*`, scopes/scans | network discovery, private ranges only unless `NOC_ALLOW_PUBLIC_SCAN=1`, scope approval required |
| `lib/tenant/ssrf.ts` (new, shared) | https-only, no credentials/paths, blocks loopback/link-local/metadata, private ranges only if the operator allows, re-checked at use time (DNS rebinding) |
| `collector/noc-agent/*` (new) | native Linux (tested) and Windows (untested) agents |

## Behaviour rules
* **Levels**: below warning = healthy; warning = shown on the dashboard, no incident; degraded/critical or "down" = event + incident via the existing workflow.
* **Deduplication**: one event per device+condition (`tel|device|cpu`), updated in place while the problem lasts; severity changes are recorded.
* **Recovery**: when fresh telemetry shows the metric below warning, the event is resolved and the incident closed with the reason "Fresh telemetry…". Recovery is never inferred from silence.
* **Silence** is its own condition ("No data from X"); it clears only when data returns.
* **Availability %** = up samples ÷ all stored samples in the window, reported with sample count, first/last sample and longest gap so thin data is visible. No stored samples → no number.
* **API**: `GET /noc/availability?hours=&device=`, `GET /noc/history?device=&key=&hours=` (key is letters only). Telemetry is rate-limited (240/min per principal) and capped at 500 devices per request.
* **Roles**: ingest role (org key, collector) can only post telemetry; `executive_readonly` cannot post; approvals for disruptive actions need an approver role.
* **AI**: the troubleshooting agent explains and proposes; evidence ids are validated, unsupported claims are flagged, nothing disruptive runs without human approval.

## Labels: real vs not
Real: Linux agent metrics (from `/proc`, `df`), TCP probes, threshold/incident/availability logic, org isolation (in-memory DB tests and earlier real-Postgres tests). Not yet real-world tested: the Windows agent, Zabbix against a live Zabbix, SNMP, any AI model output in production, load at scale.
