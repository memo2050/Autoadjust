#!/usr/bin/env bash
# Create ONE tenant on a shared Wazuh server: agent group + tenant label, a read-only Manager API user limited to that group, and an Indexer user
# limited to that tenant's alerts (document-level security). Prints NO secrets: the generated passwords go to a root-only file.
# Usage (on the Wazuh server): sudo TENANT=acme ORG_ID=<AutoAdjust organization id> [DRY_RUN=1] ./create-tenant.sh
# Needs the Wazuh admin passwords: they are read from the terminal (hidden) and never stored. UNVERIFIED against a real server: review with DRY_RUN=1 first.
set -euo pipefail
: "${TENANT:?}"; : "${ORG_ID:?}"
[[ "$TENANT" =~ ^[a-z0-9][a-z0-9-]{1,40}$ ]] || { echo "TENANT: lowercase letters, digits, dash" >&2; exit 2; }
[[ "$ORG_ID" =~ ^[A-Za-z0-9._:-]{1,80}$ ]] || { echo "ORG_ID has characters that are not allowed" >&2; exit 2; }
GROUP="t-$TENANT"; API_USER="br-$TENANT"; IDX_USER="ix-$TENANT"; OUT="/root/wazuh-tenant-$TENANT.secrets"
API=${WAZUH_API:-https://wazuh-manager:55000}; IDX=${WAZUH_INDEXER:-https://wazuh-indexer:9200}; CA=${WAZUH_CA:-/etc/wazuh-indexer/certs/root-ca.pem}
DRY=${DRY_RUN:-0}
if [ "$DRY" = 1 ]; then APASS=DRY; IPASS=DRY; else read -r -s -p "Wazuh API admin password: " APASS; echo; read -r -s -p "Wazuh Indexer admin password: " IPASS; echo; fi
BRPASS=$(openssl rand -base64 24 | tr -d '=+/' | cut -c1-24)A1a; IXPASS=$(openssl rand -base64 24 | tr -d '=+/' | cut -c1-24)A1a   # satisfy complexity rules
show() { sed -e "s/$BRPASS/***/g" -e "s/$IXPASS/***/g"; }
jid() { python3 -c 'import sys,json; print(json.load(sys.stdin)["data"]["affected_items"][0]["id"])'; }
api() { # method path [json]
  if [ "$DRY" = 1 ]; then echo "+ API $1 $2 ${3:-}" | show; echo 1; return; fi
  [ -n "${JWT:-}" ] || JWT=$(curl -sS --cacert "$CA" -u "wazuh:$APASS" -X POST "$API/security/user/authenticate?raw=true"); export JWT
  curl -sS --cacert "$CA" -X "$1" -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" ${3:+-d "$3"} "$API$2"; }
ix() { if [ "$DRY" = 1 ]; then echo "+ INDEXER $1 $2 $3" | show; return; fi; curl -sS --cacert "$CA" -u "admin:$IPASS" -X "$1" -H "Content-Type: application/json" -d "$3" "$IDX$2" >/dev/null; }

# 1) group and the tenant label every member agent inherits (centrally managed, so enrolling into the group is all an endpoint needs)
if [ "$DRY" = 1 ]; then echo "+ create group $GROUP and write /var/ossec/etc/shared/$GROUP/agent.conf with <label key=\"tenant\">$ORG_ID</label>"; else
  /var/ossec/bin/agent_groups -a -g "$GROUP" -q || true
  printf '<agent_config>\n  <labels>\n    <label key="tenant">%s</label>\n  </labels>\n</agent_config>\n' "$ORG_ID" > "/var/ossec/etc/shared/$GROUP/agent.conf"; chown wazuh:wazuh "/var/ossec/etc/shared/$GROUP/agent.conf"; fi
# 2) Manager API: read-only role limited to this group (agents), plus manager version
PID=$(api POST /security/policies "{\"name\":\"$API_USER-agents\",\"policy\":{\"actions\":[\"agent:read\",\"group:read\"],\"resources\":[\"agent:group:$GROUP\",\"group:id:$GROUP\"],\"effect\":\"allow\"}}" | { [ "$DRY" = 1 ] && cat >/dev/null && echo 1 || jid; })
MID=$(api POST /security/policies "{\"name\":\"$API_USER-manager\",\"policy\":{\"actions\":[\"manager:read\"],\"resources\":[\"*:*:*\"],\"effect\":\"allow\"}}" | { [ "$DRY" = 1 ] && cat >/dev/null && echo 2 || jid; })
RID=$(api POST /security/roles "{\"name\":\"$API_USER\"}" | { [ "$DRY" = 1 ] && cat >/dev/null && echo 3 || jid; })
api POST "/security/roles/$RID/policies?policy_ids=$PID,$MID" >/dev/null
UID_=$(api POST /security/users "{\"username\":\"$API_USER\",\"password\":\"$BRPASS\"}" | { [ "$DRY" = 1 ] && cat >/dev/null && echo 4 || jid; })
api POST "/security/users/$UID_/roles?role_ids=$RID" >/dev/null
# 3) Indexer: read-only on wazuh-alerts-* filtered to this tenant's label (document-level security) + cluster health
ix PUT "/_plugins/_security/api/roles/$IDX_USER" "{\"cluster_permissions\":[\"cluster:monitor/health\"],\"index_permissions\":[{\"index_patterns\":[\"wazuh-alerts-*\"],\"dls\":\"{\\\"term\\\":{\\\"agent.labels.tenant\\\":\\\"$ORG_ID\\\"}}\",\"allowed_actions\":[\"read\",\"indices:admin/get\"]}]}"
ix PUT "/_plugins/_security/api/internalusers/$IDX_USER" "{\"password\":\"$IXPASS\",\"backend_roles\":[]}"
ix PUT "/_plugins/_security/api/rolesmapping/$IDX_USER" "{\"users\":[\"$IDX_USER\"]}"
# 4) secrets to a root-only file (never printed)
if [ "$DRY" != 1 ]; then umask 077; { echo "WAZUH_API_USER=$API_USER"; echo "WAZUH_API_PASSWORD=$BRPASS"; echo "WAZUH_INDEXER_USER=$IDX_USER"; echo "WAZUH_INDEXER_PASSWORD=$IXPASS"; echo "WAZUH_TENANT_GROUP=$GROUP"; echo "WAZUH_TENANT_LABEL=$ORG_ID"; } > "$OUT"; chmod 600 "$OUT"; fi
echo "Tenant $TENANT ready: group $GROUP. Credentials: $OUT (root-only). Copy them into /etc/autoadjust/wazuh-bridge/$TENANT.env, add SPARK_URL and SPARK_INGEST_TOKEN yourself, then delete $OUT."
