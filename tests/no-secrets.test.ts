// Guards "never expose API keys in source, logs or Git": scans the repository files for key-shaped strings.
import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const ROOT = new URL("..", import.meta.url).pathname, SKIP = new Set(["node_modules", ".next", ".git", "logos"]);
const PATTERNS: [string, RegExp][] = [["Anthropic API key", /sk-ant-[A-Za-z0-9_-]{20,}/], ["AWS access key", /\b(AKIA|ASIA)[A-Z0-9]{16}\b/], ["private key block", /-----BEGIN [A-Z ]*PRIVATE KEY-----/], ["Stripe live key", /\b[sr]k_live_[A-Za-z0-9]{16,}/], ["organization API key literal", /\baa_live_[A-Za-z0-9_-]{24,}/], ["JWT literal", /\beyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/]];
function* walk(d: string): Generator<string> { for (const e of readdirSync(d)) { if (SKIP.has(e)) continue; const p = join(d, e), st = statSync(p); if (st.isDirectory()) yield* walk(p); else if (st.size < 2_000_000 && !/\.(png|jpg|mp4|zip)$/i.test(e)) yield p; } }
test("no API keys, tokens or private keys are present in the source tree; .env files are git-ignored", () => {
  // The ONLY allowed matches are obviously fake redaction fixtures (alphabet placeholder or "MIIabc") in the two redaction tests.
  const FAKE = /ABCDEFGHIJKLMNOP|MIIabc/, FIXTURE_FILES = new Set(["tests/exec-framework.test.ts", "tests/live/executor-e2e.ts"]);
  const hits: string[] = []; for (const f of walk(ROOT)) { const rel = relative(ROOT, f), lines = readFileSync(f, "utf8").split("\n"); for (const [n, re] of PATTERNS) for (const l of lines) if (re.test(l) && !(FIXTURE_FILES.has(rel) && FAKE.test(l))) { hits.push(`${n} in ${rel}`); break; } }
  assert.deepEqual(hits, [], "key-shaped strings found"); const gi = readFileSync(join(ROOT, ".gitignore"), "utf8"); assert.match(gi, /^\.env$/m); assert.match(gi, /^!\.env\.example$/m);
});
test("the live AI test script reads the key only from the environment and scrubs its output", () => {
  const s = readFileSync(join(ROOT, "tests/live/ai-live.ts"), "utf8"); assert.ok(/scrub/.test(s) && !/sk-ant-[A-Za-z0-9]/.test(s) && !/process\.argv.*KEY/i.test(s));
});

test("no source file imports or requires the removed 'stripe' package (regression guard; add it back deliberately if payments are built)", () => {
  const hits: string[] = []; for (const f of walk(ROOT)) { if (!/\.(ts|tsx|js|mjs|cjs)$/.test(f) || /no-secrets\.test\.ts$/.test(f)) continue; if (/(from|require\(|import\()\s*["']stripe["']/.test(readFileSync(f, "utf8"))) hits.push(relative(ROOT, f)); }
  assert.deepEqual(hits, []);
});

test("config template lists Stripe settings only as EMPTY placeholders (billing is built on REST without the SDK; test mode in development)", () => {
  const lines = readFileSync(join(ROOT, ".env.example"), "utf8").split("\n").filter((l) => /stripe/i.test(l) && !l.trim().startsWith("#"));
  assert.ok(lines.length > 0); for (const l of lines) assert.match(l, /^[A-Z_]+=\s*$/, "Stripe settings in .env.example must be empty: " + l.split("=")[0]);
});
