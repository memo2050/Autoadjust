# Spark — AI website builder (starter)

Next.js + Supabase + Claude API. Solo-founder stack: everything managed.

## Setup
1. `npm install`
2. Copy `.env.example` to `.env.local` and fill in keys.
3. Create a Supabase project, run `supabase/schema.sql` in the SQL editor.
4. `npm run dev` → http://localhost:3000

## Structure
- `app/page.tsx` — prompt box + streaming preview
- `app/api/generate` — auth, quota, Claude streaming, saves versions
- `app/api/publish` — publishes a project to `slug.SITES_DOMAIN` (self-hosted)
- `lib/prompt.ts` — system prompt (your main product lever)
- `supabase/schema.sql` — projects, versions, usage, row-level security

## Build order
1. Sign-in page (Supabase Auth) — `/api/generate` already requires a user
2. Projects list + save versions + rollback
3. Publish to Cloudflare Pages, then custom domains
4. Stripe subscriptions to raise DAILY_LIMIT
5. Per-app database via Supabase management API
6. Sandboxed multi-file apps (E2B / WebContainers) instead of single HTML

## Hosting (the project is also the website platform)
Run `supabase/002_hosting.sql` after `schema.sql`.

- `middleware.ts` maps `slug.SITES_DOMAIN` and customer custom domains to `app/serve/route.ts`, which returns the saved HTML.
- Publishing = copy a project's latest version into the `sites` table (`POST /api/publish {projectId, slug}`).
- **Local test:** set `APP_HOST=localhost:3000` and `SITES_DOMAIN=sites.localhost:3000`, then open `http://myslug.sites.localhost:3000`.
- **Production:** deploy on Vercel. Use two domains: `spark.com` for the app and `sparksites.com` for user sites (add `*.sparksites.com` as a wildcard domain). Keep them separate for security.
- **Custom domains:** user adds a CNAME to your app; you add the domain to Vercel via its Domains API, then store it in `sites.custom_domain`.
- Safety: served pages use a `sandbox` CSP, so user JS can't read your cookies. Add abuse reporting and phishing checks before opening signups.
