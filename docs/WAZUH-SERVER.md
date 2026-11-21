# Wazuh server: tenant isolation status and acceptance checklist

## What is proven (automated, mock Wazuh)
- AutoAdjust side: per-organization keys, encrypted per-org Wazuh config, SSRF guard, org-scoped ingest (`tests/tenant.test.ts`, `tests/wazuh-org.test.ts`).
- Bridge side (`tests/wazuh-bridge.test.ts`): two tenants on one Wazuh server see only their own agents and alerts; the bridge discards out-of-tenant agents/alerts even if the server ignores filters, and reports it; the health check verifies the account is limited; missing/invalid tenant config exits 2 (fail closed); legacy unfiltered mode unchanged.

## Not proven until a real server exists
Wazuh RBAC resource syntax (`agent:group:<g>`), indexer DLS on `agent.labels.tenant`, the label appearing in alerts, index/field names, TLS node-name matching, firewall exposure, backup/restore.

## Bridge env (added)
`WAZUH_TENANT_GROUP`, `WAZUH_TENANT_LABEL`, `WAZUH_TENANT_LABEL_KEY` (default `tenant`), `REQUIRE_TENANT_FILTER=1` (refuse to start unfiltered), `BRIDGE_ONCE=1` (single cycle), SIGTERM/SIGINT graceful shutdown, `NODE_EXTRA_CA_CERTS` for a private CA.

## Enrollment
`GET` enrollment command accepts `group`; it adds `WAZUH_AGENT_GROUP='<group>'`. The registration password is entered by the administrator on the endpoint; it is never stored or shown by AutoAdjust.

## Acceptance checklist (run on the real staging server; all must pass before any production use)
- [ ] `external-check.mjs` exits 0 from outside.
- [ ] Two test tenants, one agent each: tenant A bridge returns only A's agents/alerts; B likewise.
- [ ] A's Wazuh API user gets 403 for B's agent id; A's indexer user gets zero hits for B's alerts.
- [ ] Bridge health shows "Account is limited to this tenant".
- [ ] Stopping the bridge raises a NOC alert; restore drill passes; disk/cert monitor OK.
- [ ] Rotate a tenant key; old key rejected.
