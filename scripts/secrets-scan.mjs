#!/usr/bin/env node
// Fails if a tracked file contains something shaped like a real secret. Placeholders in .env.example / docs are allowed by the explicit allow-list below.
import { execSync } from "node:child_process"; import { readFileSync } from "node:fs";
const RULES = [["private key", /-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----/], ["Anthropic key", /sk-ant-[A-Za-z0-9_-]{20,}/], ["Stripe live/test secret", /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/], ["Stripe webhook secret", /\bwhsec_[A-Za-z0-9]{16,}/],
  ["JWT (Supabase key)", /\beyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}/], ["GitHub token", /\bgh[pousr]_[A-Za-z0-9]{30,}/], ["AWS access key", /\bAKIA[0-9A-Z]{16}\b/], ["Postgres URL with password", /postgres(?:ql)?:\/\/[^\s:@\/]+:[^\s:@\/]{6,}@(?!localhost|127\.0\.0\.1)/], ["Organization API key", /\baa_live_[A-Za-z0-9_-]{32,64}\b/]];
const ALLOW = [/tests\//, /\.md$/, /\.env\.example$/];     // test fixtures sign throw-away tokens at run time; docs show placeholders
const files = execSync("git ls-files", { encoding: "utf8" }).split("\n").filter(Boolean); const hits = [];
for (const f of files) { if (/\.(png|jpg|jpeg|gif|ico|woff2?|zip|lock)$/.test(f) || f === "package-lock.json") continue; let t; try { t = readFileSync(f, "utf8"); } catch { continue; }
  for (const [n, re] of RULES) { const m = re.exec(t); if (m && !ALLOW.some((a) => a.test(f))) hits.push(`${f}: looks like a ${n}`); } }
if (hits.length) { console.error("SECRET SCAN FAILED (values not printed):\n" + hits.join("\n")); process.exit(1); }
console.log(`secrets scan: ${files.length} tracked files, no secret-shaped values outside tests/docs/.env.example`);
