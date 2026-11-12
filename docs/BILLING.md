# Billing (Stripe subscriptions) — status and setup

**Status:** implemented in the development copy and tested against a LOCAL FAKE Stripe (10 tests in `tests/billing.test.ts`). **NOT TESTED against the real Stripe test environment** (no Stripe test keys/account access in the build sandbox). Live mode is disabled by code unless `BILLING_MODE=live` is set — do not set it until production approval.

## What exists
- `POST /api/soc/billing/checkout {plan:"pro"|"enterprise"}` — owner only → Stripe Checkout (subscription). Redirect URLs are fixed server-side (`APP_URL` + `/account.html`).
- `POST /api/soc/billing/portal` — owner only → Stripe Billing Portal.
- `GET /api/soc/billing/status` — plan, entitlements, subscription state (any member).
- `POST /api/soc/billing/webhook` — public, authenticated only by the Stripe signature (HMAC-SHA256 over the raw body, 5-minute tolerance, constant-time). Idempotent by event id; stale events ignored; test/live mismatch rejected; organization resolved only from our own metadata or the stored customer id (a customer bound to org A can never be re-bound to org B).
- Entitlements (`lib/billing/plans.ts`): free 3 executors / 5 API keys; pro 25/25; enterprise 500/200. Enforced server-side (HTTP 402) when registering executors and creating API keys. Past-due keeps access only until the paid period ends. Unknown price ids never grant a paid plan.
- Migration `0109_billing.sql` (+ rollback). **Not applied anywhere.** Existing `organizations.plan` is kept in sync.
- No Stripe SDK: plain REST, so no new dependency to pin.

## Real-Stripe verification procedure (test mode; needs your Stripe account)
1. Stripe Dashboard → toggle **Test mode**. Create products/prices "Auto Adjust Pro" and "Enterprise" (recurring). Note the two `price_...` ids.
2. Developers → API keys → create a **restricted** test key (write: Customers, Checkout Sessions, Customer portal; read: Subscriptions). Store as `STRIPE_SECRET_KEY` in the dev environment's secret store (never in chat/Git).
3. Developers → Webhooks → add endpoint `https://<dev-host>/api/soc/billing/webhook`, events: `checkout.session.completed`, `customer.subscription.created|updated|deleted`, `invoice.payment_failed`. Store the signing secret as `STRIPE_WEBHOOK_SECRET`.
4. Settings → Billing → Customer portal → activate.
5. Set `STRIPE_PRICE_PRO`, `STRIPE_PRICE_ENTERPRISE`, `APP_URL` (dev). Apply `0109_billing.sql` to the **dev** database only.
6. As an owner: start checkout with card `4242 4242 4242 4242`; confirm status becomes `pro`; open portal and cancel; confirm return to `free`; try `4000 0000 0000 0341` (payment fails) and confirm behaviour. Record results.

## Plan limits, device limits and data retention (opt-in)

**Nothing is limited or deleted unless `BILLING_ENFORCE=1` is set on the server.** With it unset (default) every limit is "unlimited", `GET /api/soc/billing/status` reports `enforced:false`, and existing organizations behave exactly as before.

When enforced, limits are **per organization**:

| | Free | Pro | Enterprise |
|---|---|---|---|
| API keys | 25 | 100 | 1000 (raise per contract) |
| Executors | 3 | 50 | 1000 |
| Monitored devices | 25 | 500 | 100000 |
| Metric retention | 7 days | 30 days | 365 days |

* **Devices:** only *new* devices beyond the limit are refused (telemetry ingest and Zabbix sync). Existing devices keep updating even if the org is already over the limit; nothing is ever removed. The response lists `deviceLimitSkipped` / `skippedDevices`.
* **Retention:** `POST /api/soc/noc/retention` is a **dry run** (report only) by default. `{ "apply": true }` deletes old `noc_metrics` samples only, requires enforcement to be on, is audited, and is capped at 5000 rows per call. The audit log, events, incidents and evidence are never touched. Nothing runs automatically.
* Enabling enforcement: set `BILLING_ENFORCE=1` only after reviewing which organizations exceed the limits (the dry run and `billing/status` show this).

## SaaS subscription system (stages 1-4)

Everything below stays **inert until `BILLING_ENFORCE=1`**; Stripe is **test mode only** (`sk_test_…` keys; a live key is refused unless `BILLING_MODE=live`, which is not enabled anywhere).

**Defaults (editable by the platform administrator, no deploy needed):** Free/Trial 14 days, 25 devices, 25 API keys, 3 executors, 7-day retention; Professional $49/month ($490/year), 100 devices, 100 keys, 10 executors, 30-day retention; Enterprise custom (large defaults, per-organization overrides).

**Database (migration `0110_billing_plans.sql`, additive, rollback provided, scratch DB only):** `billing_plans`, `billing_settings`, `billing_invoices`, `billing_payments`, and new columns on `org_billing` (interval, trial dates, overrides, last payment failure). RLS on, no anon/authenticated access. If the tables are missing the code falls back to the built-in defaults and the Free plan.

**Trial:** starts the first time enforcement sees an organization (existing organizations get a full trial from that moment). After it ends, with no subscription, the organization is *restricted*: existing devices, keys, data and monitoring keep working; only adding new devices/keys/executors is refused (HTTP 402, `code: trial_expired`, `upgradeUrl`). An admin can grant a promotional trial.

**Limit errors:** HTTP 402 with `code` (`plan_limit` / `trial_expired`), `limit`, `max`, `current`, `plan`, `upgradeUrl`. Lowering a limit never deletes anything.

**Grace period:** `past_due` keeps the paid plan until period end + `graceDays` (default 7, admin-configurable 0-90).

**Owner endpoints** (`/api/soc/billing/…`): `status`, `usage`, `invoices` (owner), `payments` (owner), `checkout` (`plan`, `interval: month|year`), `change` (upgrade/downgrade/interval), `cancel`, `resume`, `portal` (billing details/payment method). The plan only changes when Stripe's signed webhook confirms it.

**Webhook events handled:** `checkout.session.completed`, `customer.subscription.created/updated/deleted`, `invoice.created/finalized/updated/paid/payment_succeeded/payment_failed/voided`, `charge.refunded`. Each is signature-verified, idempotent by event id, and bound to an organization only via our own metadata or the stored customer id.

**Admin endpoints** (platform administrators only, `PLATFORM_ADMIN_USER_IDS`): `admin/plans` (GET, PUT `:id`), `admin/settings`, `admin/stats`, `admin/coupons`, `admin/orgs`, `admin/orgs/:id/overrides|trial|discount|refund`. Every change is audited. Pages: `/billing.html` (owners), `/billing-admin.html` (administrators).

**Env vars:** `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_PRO`, `STRIPE_PRICE_PRO_ANNUAL`, `STRIPE_PRICE_ENTERPRISE`, `STRIPE_PRICE_ENTERPRISE_ANNUAL`, `APP_URL`, `BILLING_ENFORCE`. Webhook events to enable in the Stripe test dashboard: the list above.

**Not covered / honest limits:** plan ids are fixed at free/pro/enterprise (limits, names and prices are editable, new plan ids are not); Stripe portal is used for card and billing-detail updates; verified only against a local fake Stripe, not the real Stripe test environment.

## Enforcement preview (read-only)
`GET /api/soc/billing/admin/preview` (platform admins; shown on `/billing-admin.html`) lists every organization with its usage, the limits that WOULD apply, violations, and whether it would start a fresh trial. It works whether or not `BILLING_ENFORCE` is on and writes nothing. Review it before setting `BILLING_ENFORCE=1`.
