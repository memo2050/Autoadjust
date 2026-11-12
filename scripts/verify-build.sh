#!/usr/bin/env bash
# Auto Adjust - REPRODUCIBLE build verification. Run on a machine/CI with npm access (the Claude sandbox cannot reach registry.npmjs.org: its egress proxy answers 403).
# Prints PASS/FAIL per step; exits non-zero on the first FAIL; only prints the final PASS line if EVERY step passed. Touches no database and no production system.
# Needs a committed package-lock.json and exact versions in package.json (create once with scripts/generate-lockfile.sh).
set -u; cd "$(dirname "$0")/.."; step() { echo; echo "=== $1"; }; fail() { echo; echo "FAIL: $1"; echo "Build is NOT verified."; exit 1; }
step "Node version (need >= 20.9)"; node -v; node -e 'const [a,b]=process.versions.node.split(".").map(Number); process.exit(a>20||(a===20&&b>=9)?0:1)' || fail "Node < 20.9"
step "Reproducibility: exact pins + lockfile present"
[ -f package-lock.json ] || fail "package-lock.json is missing. Run scripts/generate-lockfile.sh once and commit the result."
node -e '
const p=require("./package.json"), l=require("./package-lock.json"); const bad=[];
for (const sec of ["dependencies","devDependencies"]) for (const [k,v] of Object.entries(p[sec]||{})) { if(!/^\d+\.\d+\.\d+$/.test(v)) bad.push(k+"@"+v+" is not an exact version"); const r=l.packages&&l.packages["node_modules/"+k]; if(!r||r.version!==v) bad.push(k+": lockfile has "+(r?r.version:"nothing")+", package.json pins "+v); }
if(bad.length){console.error(bad.join("\n")); process.exit(1)}' || fail "package.json and package-lock.json disagree or contain a range"
step "Clean install from the lockfile (npm ci, install scripts disabled)"; rm -rf node_modules; npm ci --ignore-scripts || fail "npm ci"
step "Lockfile unchanged by install"; git diff --quiet -- package-lock.json 2>/dev/null || { [ -d .git ] && fail "npm ci changed package-lock.json"; }
step "Type-check (server libs + tests)"; npx tsc --noEmit -p tsconfig.soc.json || fail "tsc (tsconfig.soc.json)"
step "Type-check (whole app, incl. app/ routes)"; npx tsc --noEmit -p tsconfig.json || fail "tsc (tsconfig.json)"
step "Unit/integration tests"; npx tsx --test tests/*.test.ts || fail "unit tests"
step "next build"; npx next build || fail "next build"
echo; echo "PASS: reproducible install, type-check, tests and next build all succeeded on node $(node -v), next $(node -p 'require("next/package.json").version'), lockfile sha256 $(sha256sum package-lock.json | cut -c1-16)"
