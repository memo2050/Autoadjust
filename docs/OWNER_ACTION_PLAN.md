# Owner action plan — everything that needs YOU, in one place

Everything else is finished or prepared. Each item says exactly what to do and what to send back. **No production access is needed for any of it. Never paste a key anywhere except the GitHub secret form.**

## A. Dependency verification (≈10 minutes, once)  — status: BLOCKED (sandbox has no npm access)
Easiest path (no local tooling):
1. Create a **private** GitHub repository (e.g. `autoadjust-dev`). Unzip `autoadjust-all.zip`; upload the contents of `home/claude/dev/spark-dev/` as the repo root (GitHub: *Add file → Upload files*; or `git init && git add . && git commit && git push`). `.gitignore` already keeps keys and `.env*` out.
2. GitHub → **Actions** → workflow **verify-build** → **Run workflow**.
3. When it finishes (green or red), open the run → **Artifacts** → download `verification-logs` and `package-lock`. Send me the `verification-logs` folder **unedited**. (If the run is red, that is expected on the first attempt: rejected pins are listed with real versions; I fix them and you re-run once.)
Alternative on any machine with Node ≥20.9: `bash scripts/run-verification.sh`, then send the `verification-logs/` folder.

## B. Live AI test secret (≈5 minutes)  — status: NOT TESTED (needs your key)
1. Anthropic Console → create a **new workspace** named `autoadjust-ci` → set a **monthly spend limit (e.g. $5)** on it → create an API key in that workspace named `autoadjust-ci-livetest`. Copy it only into step 3.
2. GitHub repo → **Settings → Environments → New environment** → name exactly `ai-live-test` → enable **Required reviewers** (yourself) → under *Deployment branches* choose *Selected branches: main*.
3. In that environment → **Environment secrets → Add secret** → Name `ANTHROPIC_API_KEY` → paste the key → *Add secret*. (Use an *environment* secret, not a repository secret.)
4. Actions → **ai-live-test** → *Run workflow* (repeats = 2) → approve the deployment when GitHub asks.
5. Download artifact `ai-live-log` and send it. Afterwards **delete the key** in the Console. The script stops itself after 24 calls / 120,000 tokens.

## C. Windows VM (≈45 minutes of hands-on)  — status: NOT TESTED
Use a disposable Windows 10/11 or Server VM you own, a standard (non-admin) user, a **dev** server only. Take a snapshot first.
1. Copy `collector/noc-agent/Auto-Adjust-Windows-Agent.ps1` and `Windows-Preflight.ps1` to `C:\aatest\` on the VM.
2. In a normal (non-admin) PowerShell: `cd C:\aatest; powershell -NoProfile -ExecutionPolicy Bypass -File .\Windows-Preflight.ps1`. This automates the environment record, script hash, W-01 (syntax) and W-03 (dry-run) and writes `preflight-result.txt`. **Send me that file now**: I fix any syntax/runtime problem before you spend time on the rest.
3. Then follow `docs/WINDOWS-TEST-PROCEDURE.md` section 1 (setup) and fill `docs/WINDOWS-VM-CHECKLIST.md` (W-02, W-04…W-19). These steps need a running dev server reachable from the VM, an org key created in the dashboard, and screenshots — the parts only you can do. Send the filled sheet and screenshots.
Windows support is **not claimed** until all 19 are PASS.

## D. Stripe — things only your dashboards can answer (≈10 minutes)  — status: code audit PASS, external audit BLOCKED
Code, packages and config were audited here (see `STRIPE_AUDIT.md` addendum): no reference remains. Please check and reply "none" or list what you find:
1. Stripe Dashboard → **Developers → Webhooks**: any endpoint pointing at autoadjust.net or your hosting domain? (list URL + events)
2. Stripe Dashboard → **Developers → API keys**: is a key used by this app? Check *Last used*.
3. Stripe Dashboard → **Products / Payment links / Subscriptions**: any active subscriptions or payment links for Auto Adjust?
4. Hosting provider (where autoadjust.net runs) → **Environment variables**: is `STRIPE_SECRET_KEY` (or any `STRIPE_*`) set? If yes, leave it until we confirm; removal is a later, separate step.
5. Supabase → **Database → Functions / Edge Functions**: any function whose name or body mentions stripe? (the repo's migrations contain none).

## E. After A–D: send me the results. I will fix pins, rebuild the verification, update the reports and only then present the production-approval request.
