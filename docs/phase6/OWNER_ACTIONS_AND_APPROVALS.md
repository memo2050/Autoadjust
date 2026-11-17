# What needs YOUR account, credentials or approval
| # | Action | Type | Where secrets go |
|---|---|---|---|
| 1 | Run the 3 read-only production checks | your account access (read-only) | none; send text/screenshot without secrets |
| 2 | Turn Hostinger auto-deploy for `main` OFF if ON | production setting change = **approval** (yours to do) | n/a |
| 3 | Create the staging Supabase project | your account | keys go only into the staging host's environment settings |
| 4 | Create staging site/subdomain; DNS record for the new subdomain | your account; DNS = **approval** | n/a |
| 5 | Approve any paid item (VPS, AI spend cap) with exact price | **approval** | n/a |
| 6 | Create GitHub environment `staging` / `ai-live-test` and secrets | your GitHub account | secrets stored in GitHub only |
| 7 | Stripe: test-mode keys into staging env | your account | staging env only; never live keys |
| 8 | Lab: install Wazuh, Zabbix, Windows VM; create read-only users/tokens; run bridges | your hardware | `chmod 600` env files in the lab |
| 9 | Merge PR #1 then PR #2 | **approval** (separate, explicit) | n/a |
| 10 | Production migrations 0100-0113 (after backup) | **approval** | n/a |
| 11 | Production deploy | **approval** | n/a |
| 12 | `MFA_ENFORCE=on`, disable legacy tokens, `BILLING_ENFORCE`, Stripe live | each a separate **approval** | n/a |
I never need your passwords, API keys or tokens in chat.
