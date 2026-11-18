# Only what needs YOUR accounts (3 actions, about 20 minutes). Everything else is done or runs automatically.
Why you: I cannot sign in to Supabase, GitHub settings or Hostinger from my environment (their API paths and hosts are blocked for me), and secrets must never pass through chat.

## 1. Create the staging Supabase project (5 min)  — supabase.com
New project -> name `autoadjust-staging` -> Free plan -> save the DB password in your password manager. When it is "healthy": Authentication -> Sign In / Providers -> turn **Confirm email** OFF (staging only) and make sure TOTP MFA is on. Then press **Connect** and keep the "Direct connection" string handy.
(Not the project `bfsfwsjksxzonmatatyf` unless you tell me it is a brand-new empty staging project.)

## 2. Run one command on your computer (5 min)  — needs `gh` (logged in), `psql`, `node`
`git clone https://github.com/memo2050/Autoadjust && cd Autoadjust && git checkout staging && gh auth login` (once), then:
`bash scripts/staging-bootstrap.sh`  (try `--dry-run` first: it only checks the guard.)
It asks for 5 values with hidden input, and itself: creates the GitHub environments (production requires you as reviewer), stores secrets/variables, applies baseline.sql + ALL.sql to STAGING only (the guard refuses anything that is not the staging project), creates 2 test users with random passwords stored only as GitHub secrets, and prints the migration list. Then tell me "bootstrap done".

## 3. Create the Hostinger staging site (10 min)  — hPanel
Websites -> Add website -> Node.js Apps -> subdomain `staging.autoadjust.net` (own site) -> import GitHub `memo2050/Autoadjust`, branch **staging** -> Next.js, Node 22. Add the variables listed in `docs/phase7/hostinger-staging.env.template` (values from Supabase -> Project Settings -> API; make 2 fresh random strings for the two SECRET lines). Deploy. Do not change the production site. Then tell me "staging deployed" (build failures: send me the log).

## What happens automatically after that
I run `staging-verify` (build, smoke test with the two users, load test), analyse results, fix findings, and continue with MFA, isolation, Stripe test-mode, and the rest. Later asks (only when we reach them): Anthropic capped key, Stripe test keys, lab VMs.
