#!/usr/bin/env bash
# Local health checks for cron or an AutoAdjust NOC/Zabbix item. Exit 0 = healthy; any problem prints a line and exits 1. Prints no secrets.
set -u; bad=0; say() { echo "PROBLEM: $*"; bad=1; }
for u in wazuh-manager wazuh-indexer; do systemctl is-active --quiet "$u" || say "$u is not running"; done
ls /etc/autoadjust/wazuh-bridge/*.env >/dev/null 2>&1 && for f in /etc/autoadjust/wazuh-bridge/*.env; do n=$(basename "$f" .env); systemctl is-active --quiet "wazuh-bridge@$n" || say "bridge $n is not running"; done
use=$(df --output=pcent / | tail -1 | tr -dc 0-9); [ "${use:-0}" -lt 80 ] || say "disk ${use}% full"
exp=$(openssl x509 -enddate -noout -in /etc/wazuh-indexer/certs/indexer.pem 2>/dev/null | cut -d= -f2); if [ -n "$exp" ]; then d=$(( ($(date -d "$exp" +%s) - $(date +%s)) / 86400 )); [ "$d" -gt 30 ] || say "indexer certificate expires in $d day(s)"; fi
[ "$bad" = 0 ] && echo "OK"; exit "$bad"
