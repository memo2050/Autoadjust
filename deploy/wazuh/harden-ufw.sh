#!/usr/bin/env bash
# Host firewall for the Wazuh server (defence in depth: ALSO set the same rules in the cloud provider's firewall).
# Public: only the Wazuh agent ports. SSH only from ADMIN_IPS. Everything else denied. The Wazuh API (55000) and Indexer (9200) are NEVER opened.
# Usage: sudo ADMIN_IPS="203.0.113.10 198.51.100.7" [ENROLL_FROM="1.2.3.0/24"] [DRY_RUN=1] ./harden-ufw.sh
# ENROLL_FROM limits enrollment (1515); empty = anywhere (protected by the registration password) - close it with `ufw delete allow 1515/tcp` once agents are enrolled.
set -euo pipefail
: "${ADMIN_IPS:?Set ADMIN_IPS to your fixed admin address(es), space separated. Never leave SSH open to the world.}"
run() { if [ "${DRY_RUN:-0}" = 1 ]; then echo "+ $*"; else "$@"; fi; }
for ip in $ADMIN_IPS ${ENROLL_FROM:-}; do [[ "$ip" =~ ^[0-9a-fA-F:./]+$ ]] || { echo "Not an address: $ip" >&2; exit 2; }; done
run ufw --force reset
run ufw default deny incoming
run ufw default deny outgoing
run ufw default deny routed
for ip in $ADMIN_IPS; do run ufw allow from "$ip" to any port 22 proto tcp; done
run ufw allow 1514/tcp
if [ -n "${ENROLL_FROM:-}" ]; then for ip in $ENROLL_FROM; do run ufw allow from "$ip" to any port 1515 proto tcp; done; else run ufw allow 1515/tcp; fi
# outbound: DNS, time, web (packages, Let's Encrypt, AutoAdjust, backups). Narrow 443 to named hosts at the provider firewall if it supports it.
run ufw allow out 53
run ufw allow out 123/udp
run ufw allow out 443/tcp
run ufw allow out 80/tcp comment 'apt mirrors; remove if your mirror uses https'
run ufw --force enable
run ufw status verbose
