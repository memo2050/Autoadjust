import test from "node:test"; import assert from "node:assert/strict";
import { clientIp, configFrom, makeGuard, sameOrigin } from "../lib/analyze/guard";
const cfg = configFrom({} as any); const H = (o: Record<string, string>) => new Headers(o);
test("defaults: anonymous is tight, signed-in higher, global cap set", () => { assert.deepEqual([cfg.anonHour, cfg.anonDay, cfg.userHour, cfg.userDay, cfg.globalDay], [4, 8, 40, 150, 400]); });
test("anonymous per-hour quota, then Retry-After; other clients unaffected", () => {
  let t = 0; const g = makeGuard(cfg, () => t);
  for (let i = 0; i < 4; i++) assert.equal(g.check("anon", "1.1.1.1", 100, "chat", false), null);
  const r: any = g.check("anon", "1.1.1.1", 100, "chat", false); assert.equal(r.status, 429); assert.ok(r.retryAfter > 3000 && r.retryAfter <= 3600);
  assert.equal(g.check("anon", "2.2.2.2", 100, "chat", false), null, "different client");
  t = 3_600_001; assert.equal(g.check("anon", "1.1.1.1", 100, "chat", false), null, "hour window resets");
});
test("anonymous per-day quota holds across hours", () => {
  let t = 0; const g = makeGuard(cfg, () => t); let ok = 0;
  for (let h = 0; h < 10; h++) { t = h * 3_700_000; for (let i = 0; i < 4; i++) if (!g.check("anon", "9.9.9.9", 50, "chat", false)) ok++; }
  assert.equal(ok, 8, "8 per day for an anonymous client");
});
test("signed-in users have their own higher limits, keyed by user id (not IP)", () => {
  const g = makeGuard(cfg); for (let i = 0; i < 40; i++) assert.equal(g.check("user", "u1", 5000, "analyst", false), null);
  assert.equal((g.check("user", "u1", 5000, "analyst", false) as any).status, 429); assert.equal(g.check("user", "u2", 5000, "analyst", false), null);
});
test("size caps differ by tier; images need sign-in; bad modes refused", () => {
  const g = makeGuard(cfg);
  assert.equal((g.check("anon", "a", 6001, "chat", false) as any).status, 413); assert.equal(g.check("user", "a", 29000, "analyst", false), null); assert.equal((g.check("user", "b", 30001, "analyst", false) as any).status, 413);
  assert.equal((g.check("anon", "c", 10, "describe", true) as any).status, 401); assert.equal(g.check("user", "c", 0, "describe", true), null);
  assert.equal((g.check("anon", "d", 10, "evil", false) as any).status, 400); assert.equal(g.check("anon", "e", 10, undefined, false), null);
});
test("global daily budget stops everyone, then resets next day (bounded cost)", () => {
  let t = 0; const g = makeGuard({ ...cfg, globalDay: 5 }, () => t); for (let i = 0; i < 5; i++) assert.equal(g.check("user", "u" + i, 10, "chat", false), null);
  assert.equal((g.check("user", "new", 10, "chat", false) as any).status, 503); assert.equal((g.check("anon", "new2", 10, "chat", false) as any).status, 503);
  t = 86_400_001; assert.equal(g.check("anon", "new2", 10, "chat", false), null);
});
test("blocked requests do not consume quota", () => { const g = makeGuard(cfg); for (let i = 0; i < 20; i++) g.check("anon", "x", 99999, "chat", false); assert.equal(g.globalCount(), 0); assert.equal(g.check("anon", "x", 10, "chat", false), null); });
test("client IP: spoofed left-most x-forwarded-for entries cannot dodge limits", () => {
  assert.equal(clientIp(H({ "x-forwarded-for": "6.6.6.6, 7.7.7.7, 203.0.113.9" }), 1), "203.0.113.9");
  assert.equal(clientIp(H({ "x-forwarded-for": "198.51.100.1" }), 1), "198.51.100.1");
  assert.equal(clientIp(H({ "x-forwarded-for": "6.6.6.6, 198.51.100.1, 10.0.0.1" }), 2), "198.51.100.1");
  assert.equal(clientIp(H({}), 1), "unknown"); assert.equal(clientIp(H({ "x-real-ip": "192.0.2.4" }), 1), "192.0.2.4"); assert.equal(clientIp(H({ "x-forwarded-for": "x".repeat(100) }), 1), "unknown");
  const g = makeGuard(cfg); const spoof = (n: number) => clientIp(H({ "x-forwarded-for": `10.0.0.${n}, 203.0.113.9` }), 1);
  for (let i = 0; i < 4; i++) assert.equal(g.check("anon", spoof(i), 10, "chat", false), null); assert.equal((g.check("anon", spoof(99), 10, "chat", false) as any).status, 429);
});
test("same-origin: browsers from our site pass; other sites and bare scripts do not", () => {
  assert.equal(sameOrigin(H({ host: "stg.example", origin: "https://stg.example" })), true); assert.equal(sameOrigin(H({ host: "stg.example", origin: "https://evil.example" })), false);
  assert.equal(sameOrigin(H({ host: "stg.example" })), false); assert.equal(sameOrigin(H({ host: "stg.example", "sec-fetch-site": "same-origin" })), true); assert.equal(sameOrigin(H({ host: "stg.example", "sec-fetch-site": "cross-site" })), false);
});
