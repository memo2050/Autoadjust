#!/usr/bin/env node
// Checks EVERY pin in package.json against the real npm registry. Needs npm + network. Never edits package.json.
// For a pin that does not exist it lists real, published versions that are at least MIN_AGE_DAYS old (default 14) so you can choose one deliberately.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
const MIN_AGE_DAYS = Number(process.env.MIN_AGE_DAYS ?? 14), pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const npm = (...a) => execFileSync("npm", a, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
let bad = 0, err = 0;
for (const sec of ["dependencies", "devDependencies"]) for (const [name, ver] of Object.entries(pkg[sec] ?? {})) {
  let ok = false, missing = false, why = "";
  try { ok = npm("view", `${name}@${ver}`, "version") !== ""; missing = !ok; } catch (e) {
    const t = String(e.stderr || e.message); missing = /E404|ETARGET|notarget|No matching version/.test(t); why = t.split("\n").find((l) => /E404|ETARGET|notarget|No matching|ENOTFOUND|E403|ECONN|ETIMEDOUT/.test(l)) || t.split("\n")[0];
  }
  if (ok) { console.log(`PASS   ${sec}  ${name}@${ver}  exists in registry`); continue; }
  if (!missing) { err++; console.log(`ERROR  ${sec}  ${name}@${ver}  could not be checked: registry unreachable or refused (${why}). This is NOT a verdict on the pin.`); continue; }
  bad++; console.log(`FAIL   ${sec}  ${name}@${ver}  DOES NOT EXIST (${why})`);
  try {
    const times = JSON.parse(npm("view", name, "time", "--json")), cutoff = Date.now() - MIN_AGE_DAYS * 864e5;
    const cands = Object.entries(times).filter(([v]) => /^\d+\.\d+\.\d+$/.test(v) && Date.parse(times[v]) <= cutoff).sort((a, b) => Date.parse(b[1]) - Date.parse(a[1])).slice(0, 8);
    console.log(`       real versions >= ${MIN_AGE_DAYS} days old (newest first): ${cands.map(([v, t]) => `${v} (${t.slice(0, 10)})`).join(", ") || "none"}`);
  } catch (e) { console.log(`       could not list versions: ${String(e.message).split("\n")[0]}`); }
}
console.log(bad ? `\nRESULT: FAIL - ${bad} pin(s) do not exist. Choose a real version from the list, edit package.json deliberately, re-run. Do not suppress.` : err ? `\nRESULT: NOT VERIFIED - ${err} pin(s) could not be checked (registry unreachable). Nothing is proven.` : "\nRESULT: PASS - every pin exists in the registry (this does NOT mean the build passes).");
process.exit(bad || err ? 1 : 0);
