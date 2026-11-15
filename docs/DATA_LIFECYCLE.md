# Customer data export and deletion (staging-first)

## Export (owner only)
Account page -> "Your organization's data" -> **Export my data**, or `POST /api/soc/org/export`. Returns a link that works **once**, for **10 minutes**, bound to that owner (their owner role is re-checked at download). The ZIP holds `manifest.json` (row counts, SHA-256 per file, which secret fields were redacted), `organization.json` and one JSON file per table. Credentials, key hashes, invitation-token hashes and encrypted integration credentials are replaced with `[redacted]`. User sign-in accounts belong to the person and are not included. Requires `EXPORT_SIGNING_SECRET` (>= 32 chars).
Limits of this first version: built on demand (not a background job) and capped at 100,000 rows per table / 50 MB; larger organizations get a clear error. The background-job + object-storage version comes with the Gateway/Worker service (staging foundation).

## Deletion (owner request -> 14-day hold -> second person approves)
1. Owner types the organization name: `POST /api/soc/org/deletion {"confirm":"<name>"}`. Nothing is deleted. The owner can cancel any time (`DELETE /api/soc/org/deletion`) and should export first.
2. After 14 days a **platform administrator who is not the requester**, signed in with MFA, approves: `POST /api/soc/admin/deletions/<id>/approve` (list: `GET /api/soc/admin/deletions`). Platform admins must belong to some organization to sign in. Refused if the organization still has a live Stripe subscription (cancel it first) or the hold has not ended.
3. `hard_delete_org()` (migration 0113) deletes every row of the organization in **one transaction** (all public tables with an `org_id` column, found dynamically, plus `soc_meta`), lifts the append-only/last-owner guards for that organization only, writes a tombstone (name hashed, per-table row counts, final audit-chain seq + hash), then removes the organization. If anything fails, nothing is removed.
User accounts (`auth.users`) are kept; remove them in Supabase Auth if the person asks.

## Evidence (staging/scratch only)
- Scratch Postgres: organization A (51 tables of data incl. append-only audit tables and an `on delete restrict` billing row) deleted atomically; organization B untouched; guards re-enabled; refusals verified (no approval, hold active, Default org). Not run against production.
- `tests/data-lifecycle.test.ts`: API flow, ZIP validity (CRC checked), redaction, paging of 2,500 rows, single-use/expired/forged links, separation of duties, MFA, hold, billing guard, failure handling, and a guard that fails the build if a new table is not classified as organization data (exported + deleted) or not.
- NOT TESTED: against a real Supabase/PostgREST instance (PostgREST `rpc` call and `offset` paging are implemented but unproven), large exports, backups containing deleted data (they age out per your Supabase backup retention).
