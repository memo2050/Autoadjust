# Wazuh server kit (staging first)

Everything here is **unverified against a real server** (the repository has no Wazuh host yet). Review each script with `DRY_RUN=1` before running it. Nothing here provisions or buys infrastructure, and no secrets are stored in these files.

Order on a fresh Ubuntu 24.04 server (4 vCPU / 16 GB / 160 GB, all-in-one Wazuh install from Wazuh's official installer):

1. `harden-ufw.sh` (set `ADMIN_IPS`; also mirror the rules in the provider firewall). Public ports: 1514 and 1515 only.
2. Install Wazuh with the official assistant, then `bind-localhost.sh` so 55000 and 9200 listen on 127.0.0.1 only. Restart the services.
3. Load `ism-retention-90d.json` into the Indexer (90-day alert retention).
4. Per customer: `create-tenant.sh` (group `t-<tenant>`, label, read-only API user, DLS indexer user). Passwords go to a root-only file, never to the terminal.
5. Copy `wazuh-bridge@.service` into `/etc/systemd/system/`, create `/etc/autoadjust/wazuh-bridge/<tenant>-staging.env` from `bridge.env.example` (you type the keys), then `systemctl enable --now wazuh-bridge@<tenant>-staging`.
6. `backup.sh` daily (cron/timer), `restore-drill.sh` quarterly, `monitor.sh` every 5 minutes.
7. From another machine: `node external-check.mjs <server>`; must exit 0.

Tenant isolation layers: Wazuh RBAC + indexer DLS (server), bridge group filter + label check + out-of-tenant discard (`collector/wazuh/tenant-filter.mjs`), per-organization AutoAdjust key. See `docs/WAZUH-SERVER.md`.
