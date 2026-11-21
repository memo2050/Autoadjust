#!/usr/bin/env bash
# Quarterly restore drill: restore the latest backup into a scratch directory on a SCRATCH machine and check the files that matter exist. Never restores over a live server.
set -euo pipefail
source /etc/autoadjust/backup.env; T=$(mktemp -d /var/tmp/wazuh-drill.XXXXXX)
restic restore latest --tag wazuh-config --target "$T"
for f in var/ossec/etc/client.keys var/ossec/etc/ossec.conf etc/wazuh-indexer/certs/root-ca.pem; do [ -s "$T/$f" ] && echo "OK   $f" || { echo "FAIL $f missing"; exit 1; }; done
echo "Restore drill passed in $T (delete it when done)"
