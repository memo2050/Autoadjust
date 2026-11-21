#!/usr/bin/env bash
# Make the Wazuh Manager API and the Indexer listen on 127.0.0.1 ONLY (they must never be reachable from the network).
# Review the diff, then restart. Usage: sudo [DRY_RUN=1] ./bind-localhost.sh
set -euo pipefail
API=/var/ossec/api/configuration/api.yaml; IDX=/etc/wazuh-indexer/opensearch.yml
run() { if [ "${DRY_RUN:-0}" = 1 ]; then echo "+ $*"; else "$@"; fi; }
setkey() { # file key value  (replace an existing line or append)
  local f=$1 k=$2 v=$3; run cp -n "$f" "$f.orig"
  if grep -Eq "^[#[:space:]]*$k:" "$f"; then run sed -i -E "s|^[#[:space:]]*$k:.*|$k: $v|" "$f"; else if [ "${DRY_RUN:-0}" = 1 ]; then echo "+ append '$k: $v' to $f"; else echo "$k: $v" >> "$f"; fi; fi
}
setkey "$IDX" network.host 127.0.0.1
setkey "$API" host 127.0.0.1
echo "Restart: systemctl restart wazuh-indexer wazuh-manager   (then run external-check.mjs from OUTSIDE to prove 55000 and 9200 are closed)"
