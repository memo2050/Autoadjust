# Put Autoadjust online (about 20 minutes, no Supabase needed to start)

1. Get an API key: console.anthropic.com → API Keys. Add a payment method there.
   Set a monthly spend limit so costs can't surprise you.
2. Create a free GitHub account, make a new repository, upload this folder's contents.
3. Create a free Vercel account (vercel.com), "Add New Project", import that repository.
4. In Vercel → Settings → Environment Variables add:
   ANTHROPIC_API_KEY = your key
   REQUIRE_AUTH = false
   FREE_DAILY_LIMIT = 10
5. Click Deploy. Vercel gives you a public link (yourname.vercel.app). Open the Home, SOC and NOC pages.
6. Add your own domain: Vercel → Settings → Domains.

## Then, to earn money
- Turn REQUIRE_AUTH=true (needs Supabase, see README) so each user has an account.
- Add Stripe Checkout and raise the limit for paying users.
- The per-IP limit is in memory and resets on redeploy; fine for a first launch.

## What visitors see
- `/` is the landing page (`public/landing.html`) with the Home, SOC and NOC pages.
- To edit it, edit `public/landing.html`.

## Database
The SOC module needs `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` (server only, never in the page). See `docs/SOC.md`.

## SOC module
The SOC Analyst workspace is documented in `docs/SOC.md` (run `supabase/003_soc.sql`, set the SOC_* variables from `.env.example`).
