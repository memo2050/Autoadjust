# Autoadjust.net: AI SOC, NOC and intelligent agents

Next.js app. The Home, SOC and NOC pages are a static page (`public/landing.html`, routes `#/home`, `#/soc`, `#/noc`).

- `app/api/soc/[...path]` SOC backend (see `docs/SOC.md`, `docs/SOC-WAZUH.md`)
- `app/api/analyze` AI SOC Analyst, CISO and SOC Team questions
- `lib/soc`, `lib/noc` SOC and NOC logic; `collector/` data collectors
- `lib/supabase.ts` Supabase auth helper (kept for sign-in)
- `docs/` SOC, NOC and database documentation

The former Website Builder (generate, publish, hosting, studio) has been removed. Its database tables are kept untouched.
