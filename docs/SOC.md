# Spark SOC module: AI SOC Analyst workspace

What this is: a working first milestone of an agentic SOC inside your Spark site. Click the **SOC Analyst** pill in the SOC Team picture (or the "Open the SOC Analyst AI workspace" button) to open the workspace.

## 1. What the existing site had, and what was missing

Already working: static landing page (`public/landing.html`) with the SOC Team section and "CISO" / "Ask the SOC Team" question boxes; Next.js app with `/api/analyze` (AI answers, text only), `/api/generate`, a Supabase-backed app database, hosting middleware.
Missing for a real SOC: any storage of security data, any log ingestion, detections, correlation, vulnerability import, incident tracking, approvals, audit log, role-based access. The question boxes answered general questions and never looked at real data.

## 2. What is built now

| Area | Status |
|---|---|
| Windows Event Log ingestion (`POST /api/soc/ingest/windows`) + read-only PowerShell collector | Built. Collector script untested on a real Windows machine (none available to the author). |
| 14 detection rules mapped to MITRE ATT&CK (brute force, spraying, success after failures, RDP from public IP, lockouts, privileged group changes, new accounts, scheduled tasks, services, log clearing, audit/Defender tampering, suspicious command lines, ransomware precursors, Defender detections, explicit-credential fan-out) | Built and unit-tested on synthetic events. |
| Correlation into incidents, severity escalation, recurrence tracking | Built, tested. |
| Greenbone/OpenVAS report import (XML and CSV), dedupe, priority score, fixed/reappeared tracking, optional CISA KEV file | Built, tested on synthetic reports. Not yet tested against a report from your own Greenbone. |
| Incident workflow Open / Investigating / Contained / Remediated / Closed with a remediation check that uses new telemetry | Built, tested. "Passed" is only possible when new events arrived from the asset after remediation and the same rules did not fire again. |
| AI SOC Analyst (Investigate Alert, Analyze Event, Generate Security Report, free questions) | Built. Evidence packet is built on the server, evidence ids cited by the model are validated (invented ids are dropped), findings are labeled hypotheses. Tested with a mock model; not yet run with a live Anthropic key. |
| Human approval for disruptive actions | Built: proposals are stored, only an admin can approve, **nothing is executed by Spark**. |
| Audit log, RBAC via server-side tokens, dev-auth disabled in production | Built, tested. |
| Workspace UI in the home page | Built; checked in a browser in sample mode and against a running test backend. |
| Other four agents (Vulnerability Analyst, Threat Hunter, Incident Responder, Security Advisor as separate agents) | **Not built yet.** The "Generate Security Report" button uses the analyst engine. |
| Firewall / EDR / SIEM API connectors, web-attack (SQLi/XSS) detection, phishing, DoS and exfiltration detection | **Not built.** They need their own log sources; the workspace shows "NOT BUILT YET". |
| Starting scans from the platform (Greenbone GMP) | **Not built.** Reports are imported by file. |
| Threat-intel feeds | Only the CISA KEV JSON file you import yourself. |

## 3. Safety rules in the code
- No scanning or testing is performed. Importing a scan report for hosts not yet marked authorized requires an explicit attestation, which is recorded with who and when.
- The AI can only recommend. Actions that block, isolate, disable, reset or scan become proposals that need an admin's approval. Approval is recorded; execution is manual.
- No exploit, malware or intrusion capability exists. The AI prompt forbids it.
- Sample data is generated client-side only, labeled SAMPLE everywhere, and never mixed into your stored data. Rows carry a source of `live`, `imported` or `demo`.
- Event data is treated as untrusted text in the AI prompt (prompt-injection guard).

## 4. Setup (about 30 minutes)
1. Create a Supabase project. In the SQL editor run `supabase/003_soc.sql`.
2. Deploy the app (Vercel). Set environment variables (see `.env.example`): `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `ANTHROPIC_API_KEY`, `SOC_ADMIN_TOKEN`, `SOC_INGEST_TOKEN` (and optionally `SOC_ANALYST_TOKEN`, `SOC_VIEWER_TOKEN`). Generate tokens with `openssl rand -base64 36`.
3. Without Supabase the app uses an in-memory store that is lost on restart and not shared between serverless instances. Use it only for local tests.
4. Open your site, click the SOC Analyst pill, paste `SOC_ADMIN_TOKEN`. The status badge should read CONNECTED · NO DATA.
5. Connect Windows: follow `collector/windows/README.md` using `SOC_INGEST_TOKEN`.
6. Import a Greenbone report: in Greenbone open a report, download XML or CSV, use "Import Greenbone report" in the workspace.
7. Optional: download CISA's `known_exploited_vulnerabilities.json` and POST it to `/api/soc/import/kev` (admin token) to flag known-exploited CVEs.

## 5. Tests
`npx tsx --test tests/soc.test.ts` runs 15 tests (normalizer, every rule family, idempotent ingest, incident workflow and verification, scan import and re-scan logic, XML safety, AI output validation, approvals, API auth and roles, Supabase request building). They use synthetic fixtures only. The Supabase layer was tested with a mocked HTTP client, not a real database: run one real ingest after deploying and check the tables.
Manual validation plan: (1) send 6 wrong-password logons to your test PC and confirm WIN-AUTH-001 appears; (2) clear a test log and confirm WIN-EVASION-001; (3) import one real Greenbone report and compare counts with Greenbone's own report; (4) click Investigate Alert and confirm every cited evidence id exists in the timeline.

## 6. Known limits
- Detection is rule-based on Windows events you enable auditing for. No auditing, no events, no alerts.
- Thresholds are fixed in `lib/soc/rules.ts` (`CFG`); there is no UI to tune them yet.
- Overview counts use the latest 1000 events and up to 20,000 findings; fine for one or a few hosts, not for a fleet.
- Tokens are shared secrets per role, not per-user accounts. Move to Supabase Auth/SSO before giving access to a team.
- Command lines in events can contain secrets. Restrict who can read the database and the workspace.
- Data is encrypted in transit (HTTPS) and at rest by Supabase; the app adds no extra field-level encryption.

## Phase 3: Real SOC upgrade (collection, detection, measured agents, approvals, incidents)

**Setup addition:** also run `supabase/004_soc_phase3.sql` (task runs, audit hash chain, collector heartbeat). Windows collector: `collector/windows/Send-SecurityEvents.ps1` (Security, System, Application, Sysmon; sends a heartbeat each run).

**What was tested (46 automated tests, `tsc` clean, plus a browser run against the dev harness with a mock AI):**
- Ingest of Security/System/Application/Sysmon events from a test payload; 18 events accepted, 3 alerts and 1 critical incident created by the rules; collector shown CONNECTED with last contact time; live panel filtered by event ID (14 of 18 matched 4625).
- Each of the six agents runs as a server task: every step is executed and timed by the backend, progress = completed steps / total steps (e.g. 5/5, 12/12), failed runs can be retried by an authorized role, history is read from the server.
- Collaboration Center ran all six agents in connected mode; the context and hand-off message from one agent is passed to the next through the server.
- Agents only PROPOSE disruptive actions. The Pending Approvals panel shows risk, affected device/user, evidence, and the approver; an agent cannot approve its own proposal. Approval history keeps user and timestamp.
- Audit log is hash-chained; `GET /api/soc/audit/verify` returned ok for 24 entries. Incident owner assignment is audited.

**Honest limits of this phase:**
- The Windows collector has been tested only against its API contract and a synthetic payload, never on a real Windows PC. Run it on your authorized test PC and compare.
- Supabase migrations 003/004, the real Anthropic key and a Next.js production build were not run in this environment.
- No response connector exists: Approve records the decision, a human performs the action and marks it done. Spark never isolates, blocks or disables anything.
- Identity is the API token's role, not a per-user account. Audit entries name the token, so use one token per person until SSO is added.
- Live view is polling every 5 s, not a push stream.
- Detections are rule-based; the agents' analyses are rule-based on stored events, and AI is used only where an API key is configured and labeled as hypotheses with event IDs.
- In SAMPLE mode the step playback is paced for viewing and is NOT measured; the interface says so.
- No collectors yet for firewall or network logs; Sentinel, Splunk and VirusTotal connectors are not built. Wazuh is built (read-only) — see SOC-WAZUH.md.

## Phase 4: Pages and the NOC AI Team

**Pages.** The site now has three views in one file: Home, **SOC AI Agents** (the SOC team, robots and workspace, moved off the home page) and **NOC AI Agents** (new). Links use `#/home`, `#/soc`, `#/noc`. On Hostinger the zip also contains `soc/index.html` and `noc/index.html` so `/soc/` and `/noc/` open directly.

**NOC page.** Seven agents (NOC Manager, Network Monitoring, Network Troubleshooting, Infrastructure Monitoring, Incident Management, Performance Optimization, Network Configuration), each with a workspace (responsibilities, status, task assignment, start investigation, step-by-step progress, results, recommendations, live activity, history, optional AI question box). Dashboard: health score, availability, latency, packet loss, bandwidth, server health, animated topology (click a node), incidents and history, workflow (Monitoring, Detection, Analysis, Troubleshooting, Resolution, Reporting), change approvals, audit log, and a shared NOC/SOC incident workflow with escalation history.

**Real vs simulated.** With no telemetry the page says SIMULATED TELEMETRY and every number is generated by the page. To use real data, POST devices to `POST /api/soc/noc/telemetry` (ingest token; run `supabase/005_noc.sql`). Status colors are derived from thresholds (healthy / warning / degraded / critical / offline) with the reason shown. SNMP, syslog, Zabbix, PRTG, Nagios, Prometheus/Grafana and cloud adapters are NOT built; the page lists them as such.

**Tested (48 automated tests, tsc clean, plus browser runs against the dev harness):** both views and deep links, all seven agents run step by step (progress = steps done / steps total), the six-stage workflow (34 steps), config proposals and approval, SOC-to-NOC and NOC-to-SOC escalations, telemetry ingest with live mode (5 devices, tickets, a proposal stored in the backend and approved), phone width.

**Limits:** NOC incidents, approvals-in-sample-mode, escalation history and agent run history are stored in the browser's localStorage, not shared. Escalations to the SOC are recorded and shown on the NOC page but the SOC console does not receive them yet. Agents are rule-based and read telemetry only: they never ping, trace, poll SNMP or change a device. Config review needs a `config` object per device. Packet animation speed follows link utilization; it is not real packet capture. The AI question box needs an AI service on the site and is labelled as a hypothesis.

## SOC Team role panels
All six icons open a workspace (`scripts/soc-workspace.part.html`, `soc-roles.js`). Tools are in `lib/soc/roles.ts` and run on the server and, bundled (`scripts/build-browser-engine.sh`), in the browser. Each panel shows SAMPLE data without a backend and real stored data with one. Playbook ticks, notes, drafts and sample status changes are stored only in the browser. Spark never executes a response action; approvals are only recorded. Run `npx tsx --test tests/*.test.ts`.


## Phase 5: real-time NOC

See `docs/NOC-ZABBIX.md` (Zabbix integration, bridge, alerts, approved automation, acceptance checklist). Run `supabase/006_noc_realtime.sql`; set `NOC_SECRET_KEY`.

## Network topology and discovery
See `docs/NOC-TOPOLOGY.md` (scopes, discovery agent, map editing, change approvals, limits).
