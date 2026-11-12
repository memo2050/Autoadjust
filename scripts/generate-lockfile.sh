#!/usr/bin/env bash
# ONE-TIME step (run on a machine with npm access): turns the exact versions pinned in package.json into package-lock.json WITHOUT installing anything or running install scripts.
# It fails if any pinned version does not exist in the registry - that is the first real check of the pins. Review the diff, then commit package.json + package-lock.json.
set -eu; cd "$(dirname "$0")/.."
node -e '
const p=require("./package.json"); const bad=[]; for (const sec of ["dependencies","devDependencies"]) for (const [k,v] of Object.entries(p[sec]||{})) if(!/^\d+\.\d+\.\d+$/.test(v)) bad.push(sec+": "+k+"@"+v);
if(bad.length){console.error("FAIL: not an exact version:\n  "+bad.join("\n  ")); process.exit(1)}'
npm install --package-lock-only --ignore-scripts
[ -f package-lock.json ] || { echo "FAIL: package-lock.json was not created"; exit 1; }
echo "OK: package-lock.json created. Next: git add package.json package-lock.json && scripts/verify-build.sh"
npm audit --package-lock-only --audit-level=high || echo "NOTE: npm audit reported findings above - review before release (this is informational here)."
