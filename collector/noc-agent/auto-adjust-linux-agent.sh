#!/usr/bin/env bash
# Auto Adjust NOC agent for Linux. Reads REAL metrics from /proc and posts them to POST $SPARK_URL/api/soc/noc/telemetry.
# Needs: bash, curl, awk. No root required. Use an ORGANIZATION key (aa_live_...) as SPARK_INGEST_TOKEN.
#   SPARK_URL=https://autoadjust.net SPARK_INGEST_TOKEN=aa_live_xxx ./auto-adjust-linux-agent.sh           # loop every INTERVAL s
#   ONCE=1 ... ./auto-adjust-linux-agent.sh                                                                 # one sample (cron / test)
#   DRY_RUN=1 ... prints the JSON instead of sending
# Optional: DEVICE_ID, DEVICE_NAME, INTERVAL (default 60), DISK_PATH (default /), NET_IF (default: first non-lo), PING_TARGETS="10.0.0.1 10.0.0.2:443" (availability/latency probes: host = ICMP, host:port = TCP connect; one device each)
set -u
URL="${SPARK_URL:-}"; TOKEN="${SPARK_INGEST_TOKEN:-}"; INTERVAL="${INTERVAL:-60}"; DISK_PATH="${DISK_PATH:-/}"
NAME="${DEVICE_NAME:-$(hostname)}"; ID="${DEVICE_ID:-$(echo "$NAME" | tr 'A-Z ' 'a-z-' | tr -cd 'a-z0-9._-')}"
[ -z "${DRY_RUN:-}" ] && { [ -z "$URL" ] || [ -z "$TOKEN" ] && { echo "SPARK_URL and SPARK_INGEST_TOKEN are required" >&2; exit 2; }; }
cpu_snap() { awk '/^cpu /{t=0;for(i=2;i<=NF;i++)t+=$i; print t, $5+$6}' /proc/stat; }
net_snap() { local i="${NET_IF:-}"; [ -z "$i" ] && i=$(awk -F'[: ]+' 'NR>2 && $2!="lo"{print $2; exit}' /proc/net/dev); awk -v i="$i" -F'[: ]+' '$2==i{print $3, $11}' /proc/net/dev; }
speed() { local i="${NET_IF:-$(awk -F'[: ]+' 'NR>2 && $2!="lo"{print $2; exit}' /proc/net/dev)}"; cat "/sys/class/net/$i/speed" 2>/dev/null | awk '$1>0{print $1}'; }
sample() {
  read t1 i1 < <(cpu_snap); read r1 x1 < <(net_snap); local s=$(date +%s.%N); sleep 2; read t2 i2 < <(cpu_snap); read r2 x2 < <(net_snap); local e=$(date +%s.%N)
  local cpu mem disk bwin bwout cap; cpu=$(awk -v t1=$t1 -v t2=$t2 -v i1=$i1 -v i2=$i2 'BEGIN{d=t2-t1; printf "%.1f", (d>0)?100*(1-(i2-i1)/d):0}')
  mem=$(awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{printf "%.1f", (t>0)?100*(t-a)/t:0}' /proc/meminfo)
  disk=$(df -P "$DISK_PATH" | awk 'NR==2{gsub("%","",$5); print $5}')
  bwin=$(awk -v a=$r1 -v b=$r2 -v s=$s -v e=$e 'BEGIN{printf "%.3f", (b-a)*8/1e6/(e-s)}'); bwout=$(awk -v a=$x1 -v b=$x2 -v s=$s -v e=$e 'BEGIN{printf "%.3f", (b-a)*8/1e6/(e-s)}'); cap=$(speed)
  printf '{"id":"%s","name":"%s","type":"server","ip":"%s","up":true,"metrics":{"cpu":%s,"mem":%s,"disk":%s,"bwInMbps":%s,"bwOutMbps":%s%s},"config":{"os":"%s","kernel":"%s","uptimeSec":%s,"agent":"linux-1.0"}}' \
    "$ID" "$NAME" "$(hostname -I 2>/dev/null | awk '{print $1}')" "$cpu" "$mem" "$disk" "$bwin" "$bwout" "${cap:+,\"bwCapMbps\":$cap}" "$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-linux}")" "$(uname -r)" "$(cut -d. -f1 /proc/uptime)"
}
probe() { # $1 = "host" (ICMP ping, needs the ping tool) or "host:port" (TCP connect time, no extra tools). A failed check is reported as a REAL "down".
  local t="$1" id; id=$(echo "probe-$1" | tr -cd 'a-zA-Z0-9._:-' | tr ':' '-')
  if [[ "$t" == *:* ]]; then
    local h="${t%:*}" p="${t##*:}" s e; s=$(date +%s%N)
    if timeout 3 bash -c "exec 3<>/dev/tcp/$h/$p" 2>/dev/null; then e=$(date +%s%N); printf '{"id":"%s","name":"%s","type":"server","ip":"%s","up":true,"metrics":{"latencyMs":%s,"lossPct":0}}' "$id" "$t" "$h" "$(awk -v a=$s -v b=$e 'BEGIN{printf "%.1f",(b-a)/1e6}')"
    else printf '{"id":"%s","name":"%s","type":"server","ip":"%s","up":false,"metrics":{"lossPct":100}}' "$id" "$t" "$h"; fi; return; fi
  command -v ping >/dev/null || { echo "ping not installed; use host:port targets instead" >&2; return; }
  local o loss avg; o=$(ping -c 3 -W 2 "$t" 2>/dev/null); loss=$(echo "$o" | sed -n 's/.* \([0-9.]*\)% packet loss.*/\1/p'); avg=$(echo "$o" | awk -F'/' '/rtt|round-trip/{print $5}')
  if [ -z "$avg" ]; then printf '{"id":"%s","name":"%s","type":"server","ip":"%s","up":false,"metrics":{"lossPct":%s}}' "$id" "$t" "$t" "${loss:-100}"; else
    printf '{"id":"%s","name":"%s","type":"server","ip":"%s","up":true,"metrics":{"latencyMs":%s,"lossPct":%s}}' "$id" "$t" "$t" "$avg" "${loss:-0}"; fi
}
send() {
  local devs; devs=$(sample); for p in ${PING_TARGETS:-}; do r=$(probe "$p"); [ -n "$r" ] && devs="$devs,$r"; done
  local body="{\"source\":\"linux-agent:$ID\",\"devices\":[$devs]}"
  if [ -n "${DRY_RUN:-}" ]; then echo "$body"; return 0; fi
  local code; code=$(curl -sS -o /tmp/.aa-agent-resp -w '%{http_code}' -m 20 -X POST "$URL/api/soc/noc/telemetry" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "$body") || { echo "$(date -u +%FT%TZ) send failed (network)" >&2; return 1; }
  [ "$code" = "200" ] && echo "$(date -u +%FT%TZ) sent $(wc -c <<<"$body") bytes -> $(cat /tmp/.aa-agent-resp)" || { echo "$(date -u +%FT%TZ) HTTP $code: $(cat /tmp/.aa-agent-resp)" >&2; return 1; }
}

# ===================== EXECUTOR (optional, EXECUTOR=1): read-only diagnostics approved by humans in Auto Adjust =====================
# SAFETY MODEL: (1) outbound HTTPS only; (2) every job is HMAC-signed with a key derived from THIS host's organization key, bound to this host, single-use and
# short-lived; (3) the command is built HERE from the fixed templates below - the server only names a template and parameters; (4) NO shell: commands run as
# argv arrays with a clean environment (your API key is never visible to them); (5) the host-local policy file decides what may run (fail closed: no file = nothing);
# (6) timeouts, output caps and secret redaction are enforced here; (7) refuses to run as root unless EXECUTOR_ALLOW_ROOT=1. Needs: jq, openssl, timeout, curl.
#   Policy file (EXECUTOR_POLICY, default /etc/auto-adjust/executor-policy.conf), one rule per line:  template <id> | service <unit> | logunit <unit> | target <exact host name or IPv4 address>   (no wildcards, ranges or CIDR: they make net.* refuse)
EXEC_POLL="${EXEC_POLL:-10}"; POLICY="${EXECUTOR_POLICY:-/etc/auto-adjust/executor-policy.conf}"; XSTATE="${EXECUTOR_STATE:-${HOME:-/var/lib/auto-adjust}/.auto-adjust-executor}"
SAFE_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
declare -A T_TIMEOUT=([sys.uptime]=10 [sys.cpu_top]=10 [sys.mem]=10 [sys.disk]=15 [sys.load]=5 [svc.status]=10 [net.listen]=10 [net.reach]=5 [net.ping]=15 [dns.lookup]=10 [log.tail]=20)
declare -A T_LINES=([sys.uptime]=20 [sys.cpu_top]=16 [sys.mem]=20 [sys.disk]=40 [sys.load]=5 [svc.status]=20 [net.listen]=120 [net.reach]=5 [net.ping]=20 [dns.lookup]=10 [log.tail]=200)
declare -A T_BYTES=([sys.uptime]=4096 [sys.cpu_top]=4096 [sys.mem]=4096 [sys.disk]=8192 [sys.load]=1024 [svc.status]=4096 [net.listen]=12288 [net.reach]=1024 [net.ping]=2048 [dns.lookup]=2048 [log.tail]=16384)
declare -A P=()
RE_UNIT='^[A-Za-z0-9][A-Za-z0-9@._-]{0,63}$'
RE_HOSTNAME='^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$'
RE_IPV4='^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$'
policy_has() { [ -r "$POLICY" ] && grep -qxF -- "$1 $2" "$POLICY"; }
# There is NO wildcard target. A policy file with any target rule that is not an exact IPv4 address or host name makes every net.* job refuse (fail closed, visible misconfiguration).
policy_targets_ok() { [ -r "$POLICY" ] || return 1; local l v; while IFS= read -r l; do case "$l" in "target "*) v="${l#target }"; [[ "$v" =~ $RE_IPV4 || "$v" =~ $RE_HOSTNAME ]] || return 1;; esac; done <"$POLICY"; return 0; }
forbidden_target() { local h="$1"; [[ "$h" =~ ^127\. || "$h" =~ ^0\. || "$h" =~ ^169\.254\. || "$h" =~ ^2(2[4-9]|[3-5][0-9])\. || "${h,,}" == localhost || "${h,,}" == *.localhost ]]; }
redact_file() { sed -E -i -e 's/aa_live_[A-Za-z0-9_-]{8,}/[REDACTED API KEY]/g' -e 's/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/[REDACTED JWT]/g' \
  -e 's/(Bearer|Basic) +[A-Za-z0-9._~+\/=-]{8,}/\1 [REDACTED]/Ig' -e 's/\b(AKIA|ASIA)[A-Z0-9]{16}\b/[REDACTED AWS KEY]/g' \
  -e 's/((pass(word|wd)?|pwd|secret|token|api[_-]?key|apikey|auth|credential|private[_-]?key|access[_-]?key)[A-Za-z0-9_.-]*[[:space:]]*[=:][[:space:]]*)("[^"]*"|'"'"'[^'"'"']*'"'"'|[^[:space:],;&]+)/\1[REDACTED]/Ig' \
  -e 's/(\/\/[^\/[:space:]:@]+:)[^@[:space:]\/]+@/\1[REDACTED]@/g' -e 's/-----BEGIN [A-Z ]*PRIVATE KEY-----.*/[REDACTED PRIVATE KEY]/' "$1"; }
# Validates P[] for a template; returns 0 if every parameter is acceptable AND allowed by the local policy. Sets REASON on refusal.
validate_job() {
  local t="$1" k v; REASON=""
  case "$t" in
    sys.uptime|sys.cpu_top|sys.mem|sys.disk|sys.load|net.listen) [ ${#P[@]} -eq 0 ] || { REASON="unexpected parameters"; return 1; };;
    svc.status) [ ${#P[@]} -eq 1 ] && [[ "${P[unit]:-}" =~ $RE_UNIT ]] || { REASON="bad unit"; return 1; }; policy_has service "${P[unit]}" || { REASON="unit not in local policy (service)"; return 1; };;
    log.tail) [ ${#P[@]} -eq 2 ] && [[ "${P[unit]:-}" =~ $RE_UNIT ]] && [[ "${P[n]:-}" =~ ^[0-9]{1,3}$ ]] && [ "${P[n]}" -ge 1 ] && [ "${P[n]}" -le 200 ] || { REASON="bad unit or n"; return 1; }
      policy_has logunit "${P[unit]}" || { REASON="unit not in local policy (logunit)"; return 1; };;
    net.reach) [ ${#P[@]} -eq 2 ] && [[ "${P[host]:-}" =~ $RE_IPV4 || "${P[host]:-}" =~ $RE_HOSTNAME ]] && [[ "${P[port]:-}" =~ ^[0-9]{1,5}$ ]] && [ "${P[port]}" -ge 1 ] && [ "${P[port]}" -le 65535 ] || { REASON="bad host or port"; return 1; }
      forbidden_target "${P[host]}" && { REASON="forbidden target"; return 1; }; policy_targets_ok || { REASON="host policy has an invalid or wildcard target rule (only exact host names / IPv4 addresses are allowed)"; return 1; }; policy_has target "${P[host]}" || { REASON="target not in local policy"; return 1; };;
    net.ping) [ ${#P[@]} -eq 1 ] && [[ "${P[host]:-}" =~ $RE_IPV4 || "${P[host]:-}" =~ $RE_HOSTNAME ]] || { REASON="bad host"; return 1; }
      forbidden_target "${P[host]}" && { REASON="forbidden target"; return 1; }; policy_targets_ok || { REASON="host policy has an invalid or wildcard target rule (only exact host names / IPv4 addresses are allowed)"; return 1; }; policy_has target "${P[host]}" || { REASON="target not in local policy"; return 1; };;
    dns.lookup) [ ${#P[@]} -eq 1 ] && [[ "${P[name]:-}" =~ $RE_HOSTNAME ]] || { REASON="bad name"; return 1; };;
    *) REASON="unknown template"; return 1;;
  esac
  policy_has template "$t" || { REASON="template not enabled in local policy"; return 1; }
  return 0
}
ARGV=()
build_argv() {
  case "$1" in
    sys.uptime) ARGV=(uptime);; sys.cpu_top) ARGV=(ps -eo pid,pcpu,pmem,comm --sort=-pcpu);; sys.mem) ARGV=(free -m);; sys.disk) ARGV=(df -hP);; sys.load) ARGV=(cat /proc/loadavg);;
    svc.status) ARGV=(systemctl show "${P[unit]}" --no-pager -p "Id,LoadState,ActiveState,SubState,UnitFileState,MainPID,ExecMainStatus,ActiveEnterTimestamp");;
    net.listen) if PATH="$SAFE_PATH" command -v ss >/dev/null 2>&1; then ARGV=(ss -tuln); else ARGV=(__proc_listen); fi;; net.ping) ARGV=(ping -c 3 -W 2 "${P[host]}");; dns.lookup) ARGV=(getent hosts "${P[name]}");;
    log.tail) ARGV=(journalctl -u "${P[unit]}" -n "${P[n]}" --no-pager -o short-iso);;
    net.reach) ARGV=(__tcp_connect);; *) return 1;;
  esac
}
tcp_connect() { # built-in TCP connect (no external program, no shell string): prints result, exit 0 only if the port accepted a connection
  local h="$1" p="$2" s e
  s=$(date +%s%N); if (exec 3<>"/dev/tcp/$h/$p") 2>/dev/null; then e=$(date +%s%N); echo "CONNECTED $h:$p in $(( (e - s) / 1000000 )) ms"; return 0; fi; echo "FAILED to connect to $h:$p"; return 1
}
# BEGIN proc_listen
# net.listen FALLBACK, used only when the 'ss' program is not installed. READ-ONLY, bash builtins only: no external program, no shell string, no extra privilege.
# Reads /proc/net/{tcp,udp,tcp6,udp6} (the network namespace of THIS process). Prints "Netid State Local Address:Port" rows like `ss -tuln`: TCP sockets in LISTEN (st 0A) and
# UDP sockets that are unconnected (st 07). Parsing is STRICT: if anything is missing, unreadable, malformed or ambiguous it prints "UNSUPPORTED: <why>" ONLY (no partial rows) and returns 127.
# Reliability rules:  tcp and udp must be readable;  tcp6/udp6 may be absent (IPv6 disabled) but if present must be readable;  the header must match;  EVERY row must be
# well-formed (index, 8- or 32-hex address + 4-hex port, 2-hex state);  tcp6 and udp6 must be BOTH present or BOTH absent;  zero visible sockets of any state is treated as ambiguous (restricted namespace?) -> unsupported.
# Limitations: no process/user info (neither has `ss -tuln`); kernel row order (not sorted); IPv6 shown as 8 uncompressed groups (except :: and ::1); only this process's network namespace;
# a snapshot (sockets opening/closing during the read can differ); it cannot tell a firewall-blocked port from an open one.
proc_listen() {
  local dir="${1:-/proc/net}" f net hdr line nv6=0 sl la ra st rest total=0 v6="present" out="" hx re4='^[0-9A-Fa-f]{8}:[0-9A-Fa-f]{4}$' re6='^[0-9A-Fa-f]{32}:[0-9A-Fa-f]{4}$' stre='^[0-9A-Fa-f]{2}$'
  for f in tcp udp tcp6 udp6; do
    if [ ! -e "$dir/$f" ]; then case "$f" in tcp6|udp6) continue;; *) echo "UNSUPPORTED: $dir/$f does not exist"; return 127;; esac; fi
    [ -r "$dir/$f" ] || { echo "UNSUPPORTED: cannot read $dir/$f"; return 127; }
    case "$f" in tcp6|udp6) nv6=$((nv6 + 1));; esac
    case "$f" in tcp*) net=tcp;; *) net=udp;; esac
    local first=1 want; if [ "$net" = tcp ]; then want="0A"; else want="07"; fi
    while IFS= read -r line || [ -n "$line" ]; do
      read -r sl la ra st rest <<<"$line"
      if [ "$first" = 1 ]; then first=0; [ "$sl" = "sl" ] && [ "$la" = "local_address" ] && { [ "$ra" = "rem_address" ] || [ "$ra" = "remote_address" ]; } && [ "$st" = "st" ] || { echo "UNSUPPORTED: unexpected header in $dir/$f"; return 127; }; continue; fi
      [[ "$sl" =~ ^[0-9]+:$ ]] || { echo "UNSUPPORTED: malformed row in $dir/$f"; return 127; }
      case "$f" in *6) [[ "$la" =~ $re6 && "$ra" =~ $re6 ]] || { echo "UNSUPPORTED: malformed address in $dir/$f"; return 127; };; *) [[ "$la" =~ $re4 && "$ra" =~ $re4 ]] || { echo "UNSUPPORTED: malformed address in $dir/$f"; return 127; };; esac
      [[ "$st" =~ $stre ]] || { echo "UNSUPPORTED: malformed state in $dir/$f"; return 127; }
      total=$((total + 1)); st="${st^^}"; [ "$st" = "$want" ] || continue
      local addr="${la%%:*}" port=$((16#${la##*:})) ip
      case "$f" in
        *6) local w g="" i; for i in 0 8 16 24; do w="${addr:$i:8}"; hx="${w:6:2}${w:4:2}${w:2:2}${w:0:2}"; g+="${hx:0:4}:${hx:4:4}:"; done; g="${g%:}"
            if [ "$addr" = "00000000000000000000000000000000" ]; then ip="[::]"; elif [ "$addr" = "00000000000000000000000001000000" ]; then ip="[::1]"
            else local -a p; IFS=: read -r -a p <<<"$g"; local o="" x; for x in "${p[@]}"; do x="${x,,}"; x="${x#"${x%%[!0]*}"}"; o+="${x:-0}:"; done; ip="[${o%:}]"; fi;;
        *)  ip="$((16#${addr:6:2})).$((16#${addr:4:2})).$((16#${addr:2:2})).$((16#${addr:0:2}))";;
      esac
      if [ "$net" = tcp ]; then out+="tcp LISTEN $ip:$port"$'\n'; else out+="udp UNCONN $ip:$port"$'\n'; fi
    done <"$dir/$f"
    [ "$first" = 0 ] || { echo "UNSUPPORTED: $dir/$f is empty (no header)"; return 127; }
  done
  [ "$nv6" -eq 0 ] || [ "$nv6" -eq 2 ] || { echo "UNSUPPORTED: only one of tcp6/udp6 exists in $dir (inconsistent IPv6 state)"; return 127; }; [ "$nv6" -eq 2 ] || v6="absent"
  [ "$total" -gt 0 ] || { echo "UNSUPPORTED: no sockets visible at all in $dir (restricted network namespace?) - result would be ambiguous"; return 127; }
  echo "# origin: /proc/net fallback (ss is not installed); TCP LISTEN + UDP unconnected; no process info; this network namespace only; ipv6 files: $v6"
  echo "Netid State Local-Address:Port"
  if [ -n "$out" ]; then printf '%s' "$out"; else echo "(no listening sockets found; $total sockets in other states were seen)"; fi
  return 0
}
# END proc_listen
run_job() { # $1 = template; output in $OUTF, exit code in RC, timed out flag in TMO
  local t="$1" T="${T_TIMEOUT[$1]}" cap="${T_BYTES[$1]}" tmp; tmp=$(mktemp); OUTF=$(mktemp); TMO=0; RC=0
  build_argv "$t" || { echo "no such template" >"$OUTF"; RC=126; return; }
  if [ "${ARGV[0]}" = "__tcp_connect" ] || [ "${ARGV[0]}" = "__proc_listen" ]; then if [ "${ARGV[0]}" = "__tcp_connect" ]; then tcp_connect "${P[host]}" "${P[port]}" >"$tmp" 2>&1 & else proc_listen /proc/net >"$tmp" 2>&1 & fi; local pid=$!; local i=0; while kill -0 $pid 2>/dev/null && [ $i -lt $((T*10)) ]; do sleep 0.1; i=$((i+1)); done
    if kill -0 $pid 2>/dev/null; then kill -9 $pid 2>/dev/null; TMO=1; RC=124; else wait $pid; RC=$?; fi
  elif ! PATH="$SAFE_PATH" command -v "${ARGV[0]}" >/dev/null 2>&1; then
    echo "UNSUPPORTED: the required tool '${ARGV[0]}' is not installed on this host. Nothing was run." >"$tmp"; RC=127   # never reported as success
  else
    env -i PATH="$SAFE_PATH" LC_ALL=C LANG=C HOME=/nonexistent timeout -k 1 "$T" "${ARGV[@]}" 2>&1 | head -c $((cap + 1)) >"$tmp"; RC=${PIPESTATUS[0]}
    [ "$RC" -eq 124 ] || [ "$RC" -eq 137 ] && TMO=1; [ "$RC" -eq 141 ] && RC=0
  fi
  head -n "${T_LINES[$t]}" "$tmp" | head -c "$cap" | iconv -f UTF-8 -t UTF-8 -c 2>/dev/null | tr -d '\000-\010\013\014\016-\037' >"$OUTF"
  [ "$(wc -c <"$tmp")" -gt "$cap" ] || [ "$(wc -l <"$tmp")" -gt "${T_LINES[$t]}" ] && TRUNC=1 || TRUNC=0
  redact_file "$OUTF"; rm -f "$tmp"
}
report() { # $1 job id, $2 lease id ; uses RC TMO OUTF TRUNC
  local sha sig body started="$3"; sha=$(sha256sum "$OUTF" | cut -d' ' -f1); [ "$TMO" = 1 ] && local t=1 || local t=0
  sig=$(printf '%s' "v1result|$1|$2|$RC|$t|$sha" | openssl dgst -sha256 -hmac "$KEYHASH" -hex | awk '{print $NF}')
  body=$(jq -n --arg lease "$2" --argjson rc "$RC" --argjson tmo "$([ "$TMO" = 1 ] && echo true || echo false)" --rawfile out "$OUTF" --arg sig "$sig" --arg st "$started" --argjson tr "$([ "${TRUNC:-0}" = 1 ] && echo true || echo false)" '{leaseId:$lease,exitCode:$rc,timedOut:$tmo,output:$out,sig:$sig,startedAt:$st,truncated:$tr}')
  curl -sS -m 20 -o /dev/null -w '%{http_code}' -X POST "$URL/api/soc/noc/executor/jobs/$1/result" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "$body"
}
exec_poll() {
  command -v jq >/dev/null && command -v openssl >/dev/null || { echo "executor needs jq and openssl" >&2; return 1; }
  if [ "$(id -u)" = 0 ] && [ -z "${EXECUTOR_ALLOW_ROOT:-}" ]; then echo "executor refuses to run as root (set EXECUTOR_ALLOW_ROOT=1 only if you must)" >&2; return 1; fi
  KEYHASH=$(printf 'aa-key:%s' "$TOKEN" | sha256sum | cut -d' ' -f1); mkdir -p "$XSTATE" && chmod 700 "$XSTATE"
  local resp; resp=$(curl -sS -m 20 "$URL/api/soc/noc/executor/jobs?host=$ID" -H "Authorization: Bearer $TOKEN") || { echo "executor poll failed (network)" >&2; return 1; }
  [ "$(jq -r '.jobs|length' <<<"$resp" 2>/dev/null)" = "1" ] || return 0
  local jid org hid tpl exp nonce lease sig canon want now
  jid=$(jq -r '.jobs[0].id' <<<"$resp"); org=$(jq -r '.jobs[0].orgId' <<<"$resp"); hid=$(jq -r '.jobs[0].hostId' <<<"$resp"); tpl=$(jq -r '.jobs[0].template' <<<"$resp")
  exp=$(jq -r '.jobs[0].expiresAt' <<<"$resp"); nonce=$(jq -r '.jobs[0].nonce' <<<"$resp"); lease=$(jq -r '.jobs[0].leaseId' <<<"$resp"); sig=$(jq -r '.jobs[0].sig' <<<"$resp")
  canon="v1|$jid|$org|$hid|$tpl|$(jq -r '.jobs[0].params|to_entries|sort_by(.key)|map("\(.key)=\(.value)")|join("&")' <<<"$resp")|$exp|$nonce|$lease"
  want=$(printf '%s' "$canon" | openssl dgst -sha256 -hmac "$KEYHASH" -hex | awk '{print $NF}')
  refuse() { echo "$(date -u +%FT%TZ) job $jid REFUSED: $1" >&2; OUTF=$(mktemp); echo "Refused by the executor: $1" >"$OUTF"; RC=126; TMO=0; TRUNC=0; report "$jid" "$lease" "$(date -u +%FT%TZ)" >/dev/null; rm -f "$OUTF"; return 0; }
  [ "$want" = "$sig" ] || { echo "$(date -u +%FT%TZ) job $jid IGNORED: bad signature" >&2; return 0; }          # not even reported: it did not come from our organization
  [ "$hid" = "$ID" ] || { refuse "job is for another host"; return 0; }
  now=$(date +%s); [ "$(date -d "$exp" +%s 2>/dev/null || echo 0)" -ge $((now - 60)) ] || { refuse "job expired"; return 0; }
  [ ! -e "$XSTATE/seen-$jid" ] || { echo "$(date -u +%FT%TZ) job $jid IGNORED: already seen (replay)" >&2; return 0; }
  : >"$XSTATE/seen-$jid"                                                                                           # recorded BEFORE running: a crash can never cause a re-run
  P=(); while IFS=$'\t' read -r k v; do [ -n "$k" ] && P[$k]="$v"; done < <(jq -r '.jobs[0].params|to_entries[]|"\(.key)\t\(.value)"' <<<"$resp")
  validate_job "$tpl" || { refuse "$REASON"; return 0; }
  local started; started=$(date -u +%FT%TZ); run_job "$tpl"
  echo "$(date -u +%FT%TZ) job $jid $tpl rc=$RC timeout=$TMO -> report HTTP $(report "$jid" "$lease" "$started")"; rm -f "$OUTF"
}

if [ -n "${ONCE:-}" ]; then send; rc=$?; [ -n "${EXECUTOR:-}" ] && exec_poll; exit $rc; fi
last_send=0
while true; do
  now=$(date +%s); if [ $((now - last_send)) -ge "$INTERVAL" ]; then send || true; last_send=$now; fi
  if [ -n "${EXECUTOR:-}" ]; then exec_poll || true; sleep "$EXEC_POLL"; else sleep "$INTERVAL"; fi
done
