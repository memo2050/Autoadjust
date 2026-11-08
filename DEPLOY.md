# Put Spark online (about 20 minutes, no Supabase needed to start)

1. Get an API key: console.anthropic.com → API Keys. Add a payment method there.
   Set a monthly spend limit so costs can't surprise you.
2. Create a free GitHub account, make a new repository, upload this folder's contents.
3. Create a free Vercel account (vercel.com), "Add New Project", import that repository.
4. In Vercel → Settings → Environment Variables add:
   ANTHROPIC_API_KEY = your key
   REQUIRE_AUTH = false
   FREE_DAILY_LIMIT = 10
5. Click Deploy. Vercel gives you a public link (yourname.vercel.app). Test both tabs.
6. Add your own domain: Vercel → Settings → Domains.

## Then, to earn money
- Turn REQUIRE_AUTH=true (needs Supabase, see README) so each user has an account.
- Add Stripe Checkout and raise the limit for paying users.
- The per-IP limit is in memory and resets on redeploy; fine for a first launch.

## What visitors see
- `/` is the landing page with your demo video (`public/landing.html`, `public/demo.mp4`). Its "Build your website" box calls your own server, no Claude login needed.
- `/studio` is the plain tool with an "Ask anything" chat tab.
- To edit the home page, edit `public/landing.html`. To change the video, replace `public/demo.mp4`.

## Built-in backend and database (needed for apps that save data)
1. Create a free project at supabase.com. In its SQL editor, run `supabase/app_records.sql`.
2. In Supabase, Project Settings, API: copy the Project URL and the `service_role` key.
3. In Vercel add: `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` (keep the service key secret, never put it in the page).
4. Redeploy. Every app the builder generates now gets a `db` object (list/add/update/remove) that talks to `/api/db/...` on your site.

How it works: each generated app gets a random, unguessable app id; its data lives in one shared table, separated by that id. Limits: 10 KB per record, 2,000 records per app, 120 requests per minute per visitor.
Important: this database is PUBLIC to anyone who has the generated app (good for forms, guestbooks, lists; not for private user data). User logins per app are the next feature to add.

## Speed
First builds use `BUILD_MODEL` (best quality). Follow-up edits use `FAST_MODEL` (faster and cheaper). Output streams to the preview as it is written. Change both models in Vercel env vars to test speed/quality trade-offs.

## SOC module
The SOC Analyst workspace is documented in `docs/SOC.md` (run `supabase/003_soc.sql`, set the SOC_* variables from `.env.example`).
