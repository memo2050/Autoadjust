# Remaining integration requirements (Wazuh, Zabbix, AI, Windows Executor, Stripe)
| Integration | Needs from you | Cost | Can I test now without it? |
|---|---|---|---|
| Wazuh | lab VM(s), read-only users, bridge env file, staging org key | $0 | No (real Wazuh required). Mock tests exist and are labelled mock |
| Zabbix | lab VM(s), Zabbix 6.4+, read-only API token, bridge env, staging org key | $0 | No |
| AI live | spend-capped Anthropic key as GitHub secret in environment `ai-live-test` | capped; <= ~$2 per full run (built-in 24 calls / 120k tokens), cap $5 | No (fake-model tests only) |
| Windows Executor | Windows 11 evaluation VM (free 90 days), snapshot, executor key (`executor` scope) | $0 | No (logic tests pass; Windows run needs the VM) |
| Stripe | Stripe account in TEST mode, test secret key, test webhook secret, one test price per plan | $0 | Partly: webhook signature + billing logic tests already pass (mock); real test-mode checkout needs keys |
Order: Wazuh -> Zabbix -> Windows executor -> AI -> Stripe test.
