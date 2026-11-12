# Autoadjust.net: multi-tenant database architecture (Phase 1 proposal)

Status: **for review. Nothing has been run on your Supabase project.** The migrations were tested on a local PostgreSQL 16 that imitates Supabase, not on Supabase itself.

## 1. What exists today

| Group | Tables | Access | Tenant key |
|---|---|---|---|
| Website builder | `projects`, `versions`, `usage`, `sites`, `app_records` | per-user policies; `sites` is public by design | `user_id` |
| SOC (legacy) | `soc_assets/events/alerts/incidents/vulns/scans/agent_runs/actions/audit/tasks`, `soc_kev`, `soc_meta` | service role only (RLS on, no policies) | none |
| NOC (legacy) | `noc_devices/sources/interfaces/metrics/events/incidents/activities/workflows/approvals/executions/actions/scopes/scans/agents/links/maps/map_versions/changes/backups` | service role only | none |

Legacy tables use `text` ids and ISO text timestamps, and the app reaches them only through the server's service role key. There is no organization concept anywhere, and access control is four shared environment tokens.

Please run `supabase/inspect/inspect.sql` (read-only) in your project and send me the results. I could only inspect the schema as the repository defines it, so I can't confirm what your live database actually contains (for example whether the all-in-one SQL was run).

## 2. Decisions this design follows
- **Hybrid.** Cloud (Supabase + Autoadjust.net) holds organizations, users, permissions, jobs, results, reports. Agents and scanner workers run inside the customer network. Agents never receive a database key: they authenticate to the Autoadjust API with a per-agent credential (only its hash is stored here).
- **Internal networks only, for now.** The database itself refuses any scan scope that is not RFC 1918 / link-local / ULA, and any single range broader than /16. External scanning arrives in a later migration together with domain-ownership verification.
- **Vendor-neutral discovery.** Devices carry `vendor`, `adapter_key` and `capabilities`, each with a confirmed/inferred/unknown confidence. No vendor configuration tables exist yet; adapters plug in later without a schema change.
- **Non-destructive.** Existing tables keep their data and primary keys.

## 3. What the migrations add (`supabase/migrations`)
| File | Adds |
|---|---|
| `0100_tenancy` | `organizations`, `org_members` (5 roles), `org_invitations`, role helper functions, `create_organization()`, last-owner protection, a **Default organization** for legacy data |
| `0101_audit_approvals` | `audit_log` (append-only, hash-chained per organization, chain verifier) and `approvals` (separation of duties) |
| `0102_agents` | `network_agents`, `agent_enrollment_tokens` (single-use, hashed, max 7 days), atomic `enroll_agent()` |
| `0103_discovery_topology` | `scan_scopes`, `scan_jobs` (+ atomic `claim_next_job()`), `scan_schedules`, `net_devices`, `net_device_interfaces`, `net_device_services`, `net_links`, `net_segments`, `scan_results`, `topology_snapshots`, `topology_changes` |
| `0104_assessments_findings` | `assessments`, `vulnerability_findings`, `assessment_reports` |
| `0105_legacy_tables_org` | adds `org_id` (default: Default organization) and an index to the 29 legacy `soc_*`/`noc_*` tables; revokes direct client access |
| `ALL.sql` | the six above in order, for the SQL Editor |
| `rollback_0100_0105.sql` | removes only what these added |

## 4. How isolation works (two independent layers)
1. **Row level security** on every new table. A signed-in user sees a row only if they are a member of its organization with an allowed role.
2. **Composite foreign keys** `(org_id, id)` on every child table, so a row can never reference another organization's row, even if the backend has a bug.

Agents and the backend use the service role, which bypasses RLS. For those, the database still enforces the invariants that matter (below), and the application must filter by `org_id` itself.

## 5. Role matrix (enforced by policies and column privileges)
| | owner | it_admin | noc_operator | security_analyst | executive_readonly |
|---|---|---|---|---|---|
| Members, organization settings | manage | read | read | read | read |
| Agents, enrollment tokens | manage | manage | read agents | read agents | read agents |
| Scan scopes (authorize) | yes | yes | read | read | read |
| Discovery jobs / document devices & segments | yes | yes | yes | read | read |
| Assessment jobs, assessments, finding status | yes | yes | no access | yes | read |
| Approve / reject | yes | yes | no | no | no |
| Audit log | read | read | no | read | no |

## 6. Guarantees the database enforces itself
- A scope must be internal, at most /16, and an authorization needs an attestation of at least 20 characters. Authorization is stamped with the signed-in user and can only be given by owner or it_admin.
- A scan job cannot be queued or run unless its scope is authorized; vulnerability or configuration jobs also need an **approved** approval record. Withdrawing authorization cancels queued jobs and asks running ones to stop.
- An assessment cannot reach scanning, analysis or reporting without an administrator's recorded authorization, and the confirmed scope cannot be changed afterwards.
- A finding can only be `scanner_verified` if its source is a real scanner and it carries evidence. An AI-generated finding can only be an `ai_hypothesis`.
- An inferred link can never be stored as confirmed. A device type, vendor or OS carries a confidence.
- The audit log cannot be updated, deleted or truncated (even by the backend), and tampering is detectable with `private.verify_audit_chain()`.
- Approvals: people can only approve or reject a pending request, cannot edit it, cannot choose `decided_by`, and cannot approve their own request unless the organization sets `allow_self_approval`.
- An organization always keeps at least one owner, and is disabled instead of deleted.
- Agent credentials and invitation/enrollment token hashes are not readable through the API.

## 7. Existing data and the current application
- Every legacy row is placed in the Default organization by a column default, so the current app keeps working with no code change, and rows it inserts without an `org_id` land there too.
- `org_id` is **nullable-safe and not enforced yet** on legacy tables. The application code must become organization-aware first (a later phase), after which `NOT NULL` and policies are added.
- Not touched: the website builder tables, `soc_kev` (global reference data), `soc_meta` (its primary key needs an organization-aware redesign), and `soc_audit` (a separate global hash chain; a per-organization chain follows when the app writes `audit_log`).
- Revoking `anon`/`authenticated` privileges on legacy tables changes nothing in practice: they were already unreachable (RLS on, no policies) and the app uses the service role.

## 8. Scale
UUID keys, `org_id`-leading indexes on every table, and a verified plan: with 20,000 devices in each of two organizations, "latest 50 devices" runs in under 1 ms through the `(org_id, last_seen_at)` index, and a lookup by IP uses its index. `scan_results` is the table to partition by time once an organization holds millions of rows. Design target: thousands of devices per organization and many organizations.

## 9. Test results
`tests/db/run.sh` builds a throwaway PostgreSQL, loads the legacy schema with sample rows, applies the migrations, applies them a second time (must change nothing), runs 182 checks as different roles and users, then tests the rollback and re-application.
**Result: 182 passed, 0 failed.** The checks include: organization B reading or writing organization A in every tenant table; every role's allowed and refused actions; private-range enforcement (public IPv4/IPv6, carrier NAT, `172.32/16`, `/8` all refused); job and approval gates; audit immutability and tamper detection; single-use, expired and revoked enrollment tokens; cross-tenant job claiming; scanner-verified vs AI findings; cross-tenant references; last-owner protection; legacy rows kept and still writable by the app; and 40,000-device scale.
Every check that expects an error was reviewed for the actual error message, so tests do not pass for the wrong reason.

## 10. What is NOT verified
- Not run on a real Supabase project (different PostgreSQL build, `postgres` is not a superuser there, PostgREST/GoTrue are not involved). Requires PostgreSQL 15 or newer (column-list `ON DELETE SET NULL`).
- No application code uses these tables yet. The API, enrollment endpoints, agent changes, UI and the move of the existing NOC discovery data onto the new `net_*` tables are later phases.
- RLS was tested through role switching and `request.jwt.claim.sub`, which is how Supabase passes the signed-in user, but not through a real login.

## 11. Risks and open points for you
1. **Two inventories coexist** (legacy `noc_devices/noc_links/noc_scopes/noc_scans/noc_agents` and the new `net_*`). I recommend keeping legacy for telemetry (Zabbix, incidents) and moving discovery to `net_*` in Phase 3, with a one-time import. Tell me if you prefer otherwise.
2. **Self-approval is off by default.** A one-person organization must set `allow_self_approval` to approve its own requests.
3. **Deleting a user who is the only owner of an organization is blocked** until ownership is transferred.
4. The first administrator of the Default organization (your existing data) must be added by one SQL statement after you sign in once; I'll provide it with the review.

## 12. How to review and apply
1. Run `supabase/inspect/inspect.sql` and send me the output.
2. Read the six files in `supabase/migrations/`.
3. When you approve, paste `ALL.sql` into the SQL Editor of the **Autoadjust** project and run it once (it is safe to run again). The SQL Editor warns about destructive statements; the file contains only `drop trigger/policy if exists` for its own objects.
4. Send me a screenshot of the result, then we start Phase 2 (organization-aware API and agent enrollment).
