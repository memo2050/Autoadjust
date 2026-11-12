# Auto Adjust – dependency pins and lockfile status

**Lockfile status: NOT GENERATED.** `package-lock.json` cannot be created in the Claude sandbox (its egress proxy returns 403 for registry.npmjs.org). **Build verification: NOT CLAIMED.** It is claimed only after `scripts/verify-build.sh` passes completely on a machine/CI with npm access.

`latest` is gone: every dependency in `package.json` is an exact version (`.npmrc` has `save-exact=true`).

| Package | Pinned | Evidence the version exists | Notes |
|---|---|---|---|
| next | 16.4.3 | Listed (23 Oct 2026) in a public release feed (releases.sh); NOT checked against the registry | ≥2 weeks old on purpose; newer 16.4.x patches exist |
| react / react-dom | 19.2.0 | Known release (Oct 2025); NOT checked against the registry | Next 16 targets React 19.2 |
| @supabase/supabase-js | 2.109.0 | Release page seen (30 Jun 2026); a newer 2.119.0 is listed | |
| @supabase/ssr | 0.7.0 | From memory; NOT verified | Used by `lib/supabase.ts` |
| @anthropic-ai/sdk | 0.39.0 | From memory; NOT verified | Used only by `app/api/analyze/route.ts`; old, bump deliberately |
| ~~stripe~~ | **removed 2026-11-11** | – | Audit found no code, route, webhook, SQL or script depending on it (see `phase5/STRIPE_AUDIT.md`). Rollback: `phase5/rollback/package.json.before-stripe-removal` |
| typescript | 5.9.3 | From memory; NOT verified | Local tests/type-check were run with TypeScript 7.0.2 (global); 5.9.3 is untested here |
| tsx | 4.23.12 | Installed in the sandbox (so it exists) | Runs the unit tests |
| @types/node | 22.10.2 | From memory; NOT verified | Matches Node 22 |
| @types/react | 19.0.0 | From memory; NOT verified | |

Because several pins are unverified, **the first step on your machine is `scripts/generate-lockfile.sh`**: it fails immediately if any pinned version does not exist, then writes `package-lock.json` without installing or running scripts. Fix any failing pin (choose a real, ≥2-week-old version), re-run, review `npm audit`, and commit `package.json` + `package-lock.json`.

## Reproducible build procedure
1. `scripts/generate-lockfile.sh` (once; commit the result).
2. `scripts/verify-build.sh` – refuses to run without the lockfile or with any range/mismatch; runs `npm ci --ignore-scripts`, both type-checks, the unit tests and `next build`; prints a PASS line only if all pass.
3. Send me the full output. Until then: build verification = **NOT TESTED**.
