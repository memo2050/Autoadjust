#!/usr/bin/env bash
# Runs the three verification steps on a machine/CI with npm access and keeps COMPLETE, UNEDITED, timestamped logs in verification-logs/<UTC time>/.
# Nothing is filtered or suppressed; every step runs even if an earlier one fails, so you get the full picture. Final exit code is non-zero if ANY step failed.
set -u; cd "$(dirname "$0")/.."
D="verification-logs/$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$D"
{ echo "uname: $(uname -a)"; echo "node: $(node -v 2>&1)"; echo "npm: $(npm -v 2>&1)"; echo "registry: $(npm config get registry 2>&1)"; echo "git: $(git rev-parse HEAD 2>&1 || true)"
  echo "package.json sha256: $(sha256sum package.json | cut -d' ' -f1)"; [ -f package-lock.json ] && echo "package-lock.json sha256: $(sha256sum package-lock.json | cut -d' ' -f1)" || echo "package-lock.json: absent"; } >"$D/00-environment.txt" 2>&1
run() { local n="$1"; shift; echo ">>> $n  ($(date -u +%FT%TZ))"; { echo "# $n"; echo "# command: $*"; echo "# started: $(date -u +%FT%TZ)"; "$@" 2>&1 | while IFS= read -r l; do printf '%s %s\n' "$(date -u +%T)" "$l"; done; echo "# exit-code: ${PIPESTATUS[0]}"; echo "# ended: $(date -u +%FT%TZ)"; } >"$D/$n.log"; local rc; rc=$(grep -o '^# exit-code: .*' "$D/$n.log" | tail -1 | cut -d' ' -f3); echo "<<< $n exit=$rc"; if [ "${rc:-1}" != "0" ] || [ -n "${CI:-}" ]; then echo "----- BEGIN FULL LOG $n (unedited) -----"; cat "$D/$n.log"; echo "----- END FULL LOG $n -----"; fi; if [ -n "${GITHUB_ACTIONS:-}" ] && [ "${rc:-1}" != "0" ]; then grep -E "error TS|FAIL|not ok|ERR!|Error:|failed|Failed" "$D/$n.log" | head -8 | while IFS= read -r l; do echo "::error title=$n::${l:0:500}"; done; if grep -q "^[0-9:. ]*not ok" "$D/$n.log"; then echo "::notice title=$n first-failure::$(grep -A45 -m1 "not ok" "$D/$n.log" | cut -c1-400 | sed "s/%/%25/g" | awk 'BEGIN{ORS="%0A"}{print}')"; fi; echo "::notice title=$n tail::$(tail -n 40 "$D/$n.log" | cut -c1-300 | sed "s/%/%25/g" | awk 'BEGIN{ORS="%0A"}{print}')"; fi; return "${rc:-1}"; }
rc=0
run 01-check-pins node scripts/check-pins.mjs || rc=1
run 02-generate-lockfile bash scripts/generate-lockfile.sh || rc=1
run 03-verify-build bash scripts/verify-build.sh || rc=1
( cd "$D" && sha256sum *.txt *.log > SHA256SUMS )
echo; echo "Logs: $D  (send the whole folder, unedited)"; [ $rc -eq 0 ] && echo "ALL THREE STEPS PASSED" || echo "AT LEAST ONE STEP FAILED - see logs. Build is NOT verified."
exit $rc
