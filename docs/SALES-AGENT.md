# AutoAdjust AI Sales Agent (staging only)

Operator-side sales tooling for AutoAdjust itself. It is **not** tenant/organization data and never reads or writes customer organization data.

## What exists
| # | Capability | Where |
|---|---|---|
| 1 | Lead qualification (score 0-100, grade A-D, reasons, missing fields; disposable/no-consent rejected) | `lib/sales/model.ts` `qualify` |
| 2 | Plan recommendation from the real pricing catalogue (tier, add-ons, annual price, soon/planned features never sold) | `lib/sales/model.ts` `recommend`, `POST /api/sales/recommend` (stateless) |
| 3 | Demo request collection: public form and conversational agent (EN/AR), dedupe by email, explicit consent | `POST /api/sales/intake`, `POST /api/sales/agent`, page `/sales-agent` |
| 4 | Follow-up sequence: bilingual DRAFTS, human approval, dry-run outbox, auto-cancel on won/lost/unsubscribe/erasure | `followups/*` |
| 5 | CRM + pipeline: leads, notes, status machine, assignment, re-score, erasure, activity timeline | `leads/*`, `pipeline` |
| 6 | Dashboard: totals, funnel, win/demo rate, plan mix, weighted pipeline value, leads/day, follow-up counts | `dashboard`, page `/sales` |

## Safety
- **No real email is sent by this code.** There is no mail provider integration. `SALES_EMAIL_MODE=outbox` only marks approved follow-ups `dry_run`; `off` (default) does nothing. "Live" does not exist.
- Off by default: nothing is stored until `SALES_ENABLED=on` AND migration 0118 is applied AND the environment-isolation checks pass (refuses to write to the production project from a non-production app). `/api/sales/recommend` works without storage.
- Roles come only from server env lists of Supabase user ids: `SALES_ADMIN_USER_IDS` (and `PLATFORM_ADMIN_USER_IDS`), `SALES_REP_USER_IDS`, `SALES_VIEWER_USER_IDS`. A signed-in customer who is not listed gets 403.
  - viewer: read leads, pipeline, dashboard, follow-ups. rep: + create/edit leads they own or unassigned, notes, status, re-score, edit/cancel drafts. admin: + approve follow-ups, run follow-ups, reassign, erase personal data, view audit.
- Database: RLS on, no policies, no grants to anon/authenticated (server-only). `sales_audit` is append-only (trigger). Audit metadata holds ids and field names, not personal data.
- Public endpoints: same-origin, JSON only, size caps, honeypot, rate limits (shared limiter when `RATE_LIMIT_STORE=supabase`), input sanitised.
- Product questions inside the agent go through the existing guarded support assistant (injection/scope guards, quotas).

## Configuration to turn it on (staging, after approving migration 0118)
`SALES_ENABLED=on`, `SALES_ADMIN_USER_IDS` (and optionally REP/VIEWER), optional `SALES_EMAIL_MODE=outbox`. The public page `/sales-agent` is not linked from the site; linking it from the landing page needs approval (design is unchanged).

## Rollback
`supabase/migrations/rollback_0118.sql` drops the four tables (no other table is touched).

## Tests
`tests/sales.test.ts` (12 tests), plus scratch-Postgres verification of 0118 and a Playwright run against the real handlers with an in-memory store.
