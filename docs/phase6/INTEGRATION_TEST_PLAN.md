# Integration test plan — Wazuh, Zabbix, AI, Windows Executor
Rule: a result is "PASS (real)" only when real software produced the data; mock/fake-model tests are labelled **mock** and never counted. Environment: **staging** only.

## A. Wazuh (real)
Needs: Wazuh 4.x VM + 1-2 agents + read-only API/indexer users (see docs/SOC-WAZUH.md and PHASE2_LAB_CHECKLIST.md R2). Bridge runs in the lab; secrets stay there.
| # | Test | Pass evidence |
|---|---|---|
| A1 | Connection test (API auth + indexer search) | staging status "connected"; bridge log line (no secrets) |
| A2 | 6 failed SSH logins on an agent | alert in staging with host, rule id, level, MITRE; matches Wazuh dashboard screenshot |
| A3 | New local user / file change (FIM) / sudo | 3 alerts correlate to Wazuh |
| A4 | Restart bridge | no duplicates; counts unchanged |
| A5 | Stop bridge 10 min, restart | backlog arrives exactly once |
| A6 | Wrong password / Wazuh stopped | clear error status, no invented data |
| A7 | Second org | sees none of it |
| A8 | Revoke the org key | ingestion stops immediately |
## B. Zabbix (real, 6.4+)
Needs: Zabbix VM + 2 agents + read-only user + API token (docs/NOC-ZABBIX.md, checklist R3).
| # | Test | Pass evidence |
|---|---|---|
| B1 | Connection test | version + host count |
| B2 | Hosts and metrics (CPU/RAM/disk/interfaces) | staging NOC matches Zabbix frontend (screenshots) |
| B3 | Stop a service / fill a disk / stop agent | problem opens in Zabbix then NOC alert in staging; latency measured; closes on resolve |
| B4 | Metric without a Zabbix item | shown "not monitored", never a number |
| B5 | Revoked token | clear auth error; stale data not shown as live |
| B6 | Plan limits (Free: 25 devices) in staging | 26th device refused with plan_limit error |
## C. AI (live model)
Needs: spend-capped Anthropic key as secret `ANTHROPIC_API_KEY` in GitHub environment `ai-live-test` (you add it). Run `ai-live` workflow manually. Built-in caps: 24 calls, 120,000 tokens, 1,500 output tokens/call (docs/LIVE-AI-TEST.md). Upper-bound cost <= ~$2 at a $15 per million tokens assumption; set a $5 console cap.
Tests: evidence-only answers (no invented IDs), refusal to act on injected log text (the injected scenarios in tests/live), proposals only (never executes), failure/timeout handling (bad key -> clear error), latency per call recorded.
Pass evidence: workflow run log (pass/fail per scenario, SPEND line), your confirmation of the key cap. Detection by the hijacked-stub suite does **not** count as live evidence.
## D. Windows Executor (real Windows)
Needs: Windows 11 Enterprise evaluation (free, 90 days) in VMware, 4 GB RAM, snapshot before tests (docs/WINDOWS-VM-CHECKLIST.md, docs/WINDOWS-TEST-PROCEDURE.md).
| # | Test | Pass evidence |
|---|---|---|
| D1 | Preflight script | output shows PowerShell version, execution policy, no admin needed for read-only |
| D2 | Enroll executor with org key (scope `executor`) | executor appears in staging; key scope enforced |
| D3 | Run each allowlisted read-only diagnostic | results returned, redacted, signed job accepted once |
| D4 | Replay same job | refused (single use) |
| D5 | Non-allowlisted command / tampered job / expired job | refused, audited |
| D6 | Owner kill switch | executor stops pulling jobs |
| D7 | Output with a planted fake secret | redacted in staging |
| D8 | Revoke key | executor rejected |
Disruptive actions stay disabled; no change commands run.
## Order and gates
Wazuh -> Zabbix -> Windows executor -> AI -> Stripe test-mode checkout (test card). Each gate: all PASS (real) or documented FAIL with a fix before the next.
