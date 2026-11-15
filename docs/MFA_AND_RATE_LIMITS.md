# MFA enforcement and shared rate limiting (staging-first)

## MFA
- Users enrol a TOTP authenticator on the account page (Supabase Auth). The sign-in token then carries `aal2` once a code is verified.
- `MFA_ENFORCE=on` makes the API refuse **changes** (anything except GET/HEAD) from owners, IT admins and platform admins without `aal2`, with `403 {code:"mfa_required"}`. Reads still work so the page can show the prompt.
- An owner/IT admin can also require MFA for every member of the organization (`POST /api/soc/org/mfa {requireMfa:true}`, needs `aal2`; audited as `org.mfa_policy`).
- Collector API keys are not people and are unaffected.
- Default is **off**: existing deployments do not change until you set `MFA_ENFORCE=on`. Turn it on in staging first, enrol every admin, then production with your approval.
- **Break-glass:** if every admin loses their authenticator, set `MFA_ENFORCE=off` (environment variable, then redeploy), sign in, re-enrol, set it back to `on`. Supabase also lets a project owner remove a user's factor in the dashboard. Record each use.

## Rate limiting
- Counters live in Postgres (`rate_limit_hit()`, migration 0112), so every server instance shares one count. Fixed 60 s windows; responses are `429` with `Retry-After`.
- Sensitive routes (accounts, keys, billing, approvals) **fail closed** with `503` if the counter is unreachable. Collector ingest routes **fail open** to a per-process limit and log an error so monitoring can alert.
- Without migration 0112 on a Supabase database, sensitive routes would fail closed: apply 0112 before deploying this code to any environment that uses Supabase.
- Redis is only needed if load tests show Postgres is the bottleneck.
