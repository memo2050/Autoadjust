#!/usr/bin/env bash
# Daily encrypted backup of the Wazuh server configuration and identity (NOT the alert indices: those are covered by provider snapshots + snapshot repository, see README).
# Needs restic and /etc/autoadjust/backup.env (root, 600) with RESTIC_REPOSITORY and RESTIC_PASSWORD_FILE. The password file lives OFFLINE-backed-up, not only here.
set -euo pipefail
source /etc/autoadjust/backup.env
PATHS=(/var/ossec/etc /var/ossec/api/configuration /etc/wazuh-indexer/certs /etc/wazuh-manager /etc/filebeat /etc/autoadjust)
[ "${DRY_RUN:-0}" = 1 ] && { echo "+ restic backup ${PATHS[*]}"; exit 0; }
restic backup "${PATHS[@]}" --tag wazuh-config
restic forget --tag wazuh-config --keep-daily 7 --keep-weekly 4 --prune
