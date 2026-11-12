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
