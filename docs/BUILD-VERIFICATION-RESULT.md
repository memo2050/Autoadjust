# Build verification — result (CI, GitHub Actions, 2026-11-12 UTC)

**Status: PASS in CI** (workflow `verify-build`, PR #1, Node 20.19.0, npm 10.8.2, Ubuntu runner). Evidence: GitHub run conclusion `success`; every step `success`; the wrapper exits non-zero if ANY of the three steps fails.
Steps covered: (1) all 10 pinned versions exist in the npm registry; (2) lockfile generation; (3) `npm ci --ignore-scripts` from the lockfile, `tsc` on `tsconfig.soc.json` (server libs + tests) and `tsconfig.json` (app), 150 unit/integration tests, `next build` (Next 16.4.3).

## Problems found by the real run and fixed (none were suppressed)
| # | Failure on the real runner | Cause | Fix |
|---|---|---|---|
| 1 | TS2688 cannot find type definitions for 'node' | `tsconfig.soc.json` had a sandbox-only `typeRoots` path | removed; sandbox config kept separately |
| 2 | TS2769 in `scripts/dev-harness.ts` | `Object.fromEntries(Headers)` not iterable under the project's TS lib | `headers.forEach` |
| 3 | `net.listen` fallback test: "unexpected header in /proc/net/tcp6" | real kernels label the IPv6 remote column `remote_address` (IPv4 files: `rem_address`); my fixtures copied the IPv4 wording. The fallback correctly failed closed with UNSUPPORTED | parser accepts both; tests now use the real IPv6 header and still refuse unknown names |
| 4 | `next build` type-check failed on 3 test files (`NODE_ENV` in ProcessEnv) | Next type-checks every `.ts` under the project, including tests | `tsconfig.json` excludes tests/scripts/collector (tests remain checked by `tsconfig.soc.json`) |

## Not covered by this verification
`npm audit` results (informational step; output not reviewed), Windows, live AI model, real Stripe test mode, Wazuh/Zabbix live connections, load, production deployment. The `next build` emits a deprecation notice: Next 16 renames `middleware` to `proxy` (works today; migrate later).
`package-lock.json` was generated and committed by CI after the PASS; versions equal the pins.
