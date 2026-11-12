# Auto Adjust — Phase 4: organization-aware architecture

Status: implemented and tested in the DEVELOPMENT copy only. Nothing has been applied to production.

## 1. Model
- **Organization** = tenant. **Membership** (`org_members`) gives a user exactly one role in an organization. A user may belong to several organizations.
- Roles (already in the Supabase model, migration 0100): `owner`, `it_admin`, `noc_operator`, `security_analyst`, `executive_readonly`.

| Role | Read SOC+NOC | Write SOC | Write NOC | Approve / configure | Manage members, invites, keys | Change roles |
|---|---|---|---|---|---|---|
| owner | yes | yes | yes | yes | yes | yes |
| it_admin | yes | yes | yes | yes | yes (cannot invite another it_admin or owner) | no |
| security_analyst | yes | yes | no | no | no | no |
| noc_operator | yes | no | yes | no | no | no |
| executive_readonly | yes | no | no | no | no | no |
| collector API key | no | ingest only | ingest only | no | no | no |

## 2. Two locks
1. **Application tier (`lib/tenant/scoped-store.ts`)** — the server uses the Supabase service-role key, which bypasses row level security, so the application must isolate tenants itself.
   Every request gets a `ScopedStore` bound to ONE organization. Every select/remove is filtered by `org_id`; every written row is stamped; a caller-supplied `orgId` can never widen a query;
   a row for another organization is rejected. Because the legacy primary keys are bare `id`s (the same host name in two organizations would collide and overwrite), the `id` column is
   namespaced `<orgId>:<id>` on write and stripped on read. The Default organization keeps bare ids, so all existing data keeps working unchanged. Tables the wrapper does not know are refused.
2. **Database (RLS + grants)** — direct API access by signed-in users is blocked on every SOC/NOC table; `organizations`, `org_members`, `org_invitations` are readable only for one's own organizations (migration 0100); the hardening SQL removes the remaining anonymous/legacy grants.

## 3. Authentication
- **People**: Supabase Auth (email + password; hashing, rate limits, email confirmation, MFA are Supabase's). The browser sends the Supabase access token as a Bearer token. The server verifies it (HS256 with `SUPABASE_JWT_SECRET`, otherwise Supabase `/auth/v1/user`), rejecting wrong signature, expiry, other algorithms (incl. `none`), wrong audience, and anon/service keys.
- **Membership and role are read from the database on every request**, never from the token: removing someone or changing a role takes effect immediately.
- **Organization choice**: `x-org-id` header (strict), or the user's stored preference (`user_metadata.active_org`) — honoured only if the database confirms membership. Several memberships and neither → HTTP 409 with the list.
- **Collectors**: per-organization API keys `aa_live_…`, only a SHA-256 hash stored (`org_api_keys`, migration 0106), revocable, scoped to ingest for that organization only.
- **Legacy shared tokens** (`SOC_ADMIN_TOKEN`, …): still accepted (compatibility) but ONLY inside the Default organization; `SOC_LEGACY_TOKENS=off` disables them. They are never customer credentials.
- **Platform admins** (`PLATFORM_ADMIN_USER_IDS`, or the legacy admin token) are the only ones allowed to update shared CISA KEV reference data.

## 4. API (all under `/api/soc/`)
`org/create` POST, `org/mine` GET, `org/current` GET, `org/members` GET, `org/members/{userId}` PATCH/DELETE, `org/invitations` GET/POST, `org/invitations/{id}` DELETE,
`org/invitations/accept` POST, `org/keys` GET/POST, `org/keys/{id}` DELETE, `org/audit` GET. `me` now also returns the organization and role. Every existing SOC/NOC endpoint is unchanged and now operates inside the caller's organization.
UI: `/account.html` (new standalone page; the existing Home/SOC/NOC pages are unchanged and receive the sign-in through the existing token mechanism).

## 5. Audit
One hash chain per organization (`soc_audit`, unique `(org_id, seq)` via migration 0107). Organization management actions (create, invite, accept, role change, remove, key create/revoke) are recorded in that organization's chain. Hashing now uses canonical JSON (the previous form made verification fail for any record whose detail had 2+ keys once stored in Postgres jsonb).

## 6. Database changes (all additive, none applied to production)
- `0106_org_api_keys.sql` (+ `rollback_0106.sql`): new table, RLS on, no client grants.
- `0107_audit_seq_per_org.sql` (+ `rollback_0107.sql`): replaces the global unique index on `soc_audit.seq` by a per-organization one. No data touched.
- Previously prepared: `hardening.sql` (+ `hardening_revert.sql`, `capture_rollback.sql`).

## 7. Known limits (honest list)
- Invitation emails are NOT sent; the owner copies the token to the invitee (shown once).
- Access tokens last about an hour (Supabase default); the account page refreshes them when opening SOC/NOC, the existing SOC/NOC pages do not refresh them on their own yet.
- `soc_meta` (integration state) has no `org_id` column; it is isolated by the namespaced id only.
- `soc_kev` is shared reference data by design.
- Billing, per-plan limits and SSO/SAML are not part of Phase 4.
- Organization-specific **dashboards** are the existing SOC/NOC pages scoped to the caller's organization; no new dashboard design was made (design is approved as is).
- `next build` could not be run here (npm registry unreachable).
