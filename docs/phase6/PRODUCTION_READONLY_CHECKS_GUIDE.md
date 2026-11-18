# The three read-only production checks — step by step
All three are **read-only**: you look and copy text; you change nothing. Menu names can differ slightly by Hostinger/Supabase version. If a screen differs, send me a screenshot (hide secrets) and I will adapt the instructions. I cannot open these sites myself (my browser tool refuses them), and I cannot produce true screenshots of your dashboards, so each step ends with "what to send me".

## Check 1 — Which migrations are applied in production (Supabase)
1. Sign in at supabase.com -> Dashboard -> choose the **production** project (check the project name at top left).
2. Left menu -> **SQL Editor** -> **New query**.
3. Paste exactly this and click **Run** (it only reads):
   `select version, name, applied_at from private.app_migrations order by version;`
   - If you get "relation does not exist", that itself is the answer (none of 0100+ applied): tell me that.
4. Optional second query (read-only): `select tablename, rowsecurity from pg_tables where schemaname='public' order by 1;`
5. **Send me:** the result table as text (copy cells) or a screenshot. No keys are visible in it.

## Check 2 — Is Hostinger auto-deploying `main`?
1. Sign in at hpanel.hostinger.com -> **Websites** -> **Manage** on autoadjust.net.
2. Find the deployment settings: look for **Git** (under Advanced) or **Node.js / Deployments** (GitHub-connected app). 
3. Look for: connected repository (`memo2050/Autoadjust`?), **branch**, and **Auto deployment / Webhook** toggle.
4. Also note the **latest deployment date/status**.
5. **Send me:** screenshot of that panel (webhook URLs are secrets: hide them) or text: repo, branch, auto-deploy ON/OFF, last deployed date.
6. If auto-deploy for `main` is ON: tell me, and (only if you agree) switch it OFF, because merging PR #1 would otherwise deploy it. Do not change anything else.

## Check 3 — `APP_HOST` / `SITES_DOMAIN` (set or not; never the values)
1. In hPanel on the same site -> **Environment variables** (Node.js apps: Settings / Environment). 
2. Look at the list of **names**. Is `APP_HOST` present? Is `SITES_DOMAIN` present?
3. **Send me only:** "APP_HOST: set / not set; SITES_DOMAIN: set / not set." Do not send values or any other variable.
4. Why it matters: if both are set, the middleware rewrites requests for other hosts to a route that does not exist, giving 404 pages.

## What I do with the answers
- Check 1 decides which migrations must be applied (0100-0113) and in what order.
- Check 2 decides whether a merge could deploy by itself (it must not).
- Check 3 tells me whether the middleware can break the live site.
