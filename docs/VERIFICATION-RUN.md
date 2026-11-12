# Build verification run — for a machine or CI WITH npm access

**Status: NOT VERIFIED.** The Claude sandbox cannot reach the npm registry (proxy refuses it), so no lockfile exists and `next build` has never run. This kit lets you produce the evidence. Nothing is filtered or suppressed.

## Run (one command)
```
bash scripts/run-verification.sh
```
Creates `verification-logs/<UTC time>/` with `00-environment.txt`, `01-check-pins.log`, `02-generate-lockfile.log`, `03-verify-build.log`, `SHA256SUMS`. Each log is timestamped line by line and ends with the real exit code. All three steps always run, so you see every failure. **Send the whole folder unedited.**
Or in GitHub: Actions → `verify-build` → Run workflow (uploads the same logs plus the generated lockfile).

## What each step answers
| Step | Question | Meaning of result |
|---|---|---|
| `check-pins.mjs` | Does every pinned version really exist? | PASS / FAIL (does not exist, with real versions ≥14 days old listed) / ERROR (registry unreachable: proves nothing) |
| `generate-lockfile.sh` | Can a lockfile be resolved from the pins? | creates `package-lock.json` (no install scripts run) + informational `npm audit` |
| `verify-build.sh` | Clean `npm ci`, both type-checks, unit tests, `next build` | final line `PASS:` appears only if every step passed |

## Resolving a rejected pin (no bypass)
1. Do **not** use `latest`, ranges, `--force`, `--legacy-peer-deps`, or delete the check.
2. Take the version from the FAIL line's list of real, ≥14-day-old releases; confirm the changelog does not break us (Next, React, Supabase majors especially).
3. Edit `package.json` to that exact version, re-run `run-verification.sh`, keep **both** logs (before/after).
4. A change that makes type-check or tests fail is a finding to report, not something to silence.
5. When everything passes, commit `package.json` + `package-lock.json`. Only then may the build be called verified.

## Known risk to expect
`typescript` is pinned 5.9.3 but local checks here ran with 7.0.2; the first run on 5.9.3 may show type errors. Report them as-is.
