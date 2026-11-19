// Sign-out revocation: a token whose session was deleted (sign-out) must stop working, instead of living until it expires.
// Evidence class: LOCAL (real JWT crypto; Supabase Auth is a stub that tracks sessions like GoTrue: /user -> 200 while the session exists, 403 afterwards).
import test from "node:test"; import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { identifyUser, signOutToken, sessionAlive, _resetSessionCache, _resetJwksCache } from "../lib/tenant/auth";
const REF = "abcdefghijklmnopqrst", URLS = `https://${REF}.supabase.co`, ISS = URLS + "/auth/v1";
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = { ...(publicKey.export({ format: "jwk" }) as object), kid: "k1", alg: "ES256", use: "sig" };
const mint = (sid: string, sub = randomUUID()) => { const h = b64({ alg: "ES256", typ: "JWT", kid: "k1" }), p = b64({ sub, role: "authenticated", aud: "authenticated", iss: ISS, session_id: sid, exp: Math.floor(Date.now() / 1000) + 3600 }); return `${h}.${p}.${sign("sha256", Buffer.from(`${h}.${p}`), { key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url")}`; };
function stub() {
  const live = new Set<string>(), calls = { user: 0, logout: 0 };
  const f = (async (url: string, init: any) => {
    if (url.endsWith("/jwks.json")) return new Response(JSON.stringify({ keys: [jwk] }), { status: 200 });
    const tok = (init?.headers?.Authorization ?? "").slice(7), sid = JSON.parse(Buffer.from(tok.split(".")[1], "base64url").toString()).session_id;
    if (url.endsWith("/auth/v1/user")) { calls.user++; return live.has(sid) ? new Response("{}", { status: 200 }) : new Response('{"code":"session_not_found"}', { status: 403 }); }
    if (url.endsWith("/auth/v1/logout")) { calls.logout++; live.delete(sid); return new Response(null, { status: 204 }); }
    throw new Error("unexpected " + url);
  }) as unknown as typeof fetch;
  return { f, live, calls };
}
const req = (t: string) => new Request("https://x/api", { headers: { authorization: "Bearer " + t } });
const setEnv = (o: Record<string, string | undefined> = {}) => { for (const k of ["SESSION_REVOCATION_CHECK", "SESSION_CHECK_TTL_MS"]) delete process.env[k]; process.env.SUPABASE_URL = URLS; process.env.SUPABASE_ANON_KEY = "anon-public"; Object.assign(process.env, o); _resetSessionCache(); _resetJwksCache(); };
const D = (f: typeof fetch) => ({ raw: null as any, fetcher: f });

test("valid session accepted; after sign-out at Supabase the same token is refused (once the short cache lapses)", async () => {
  setEnv({ SESSION_CHECK_TTL_MS: "0" }); const s = stub(); s.live.add("s1"); const t = mint("s1");
  assert.ok(await identifyUser(req(t), D(s.f)), "accepted while session exists");
  s.live.delete("s1");                                              // user signs out elsewhere (e.g. directly at Supabase)
  assert.equal(await identifyUser(req(t), D(s.f)), null, "refused after the session is deleted");
  s.live.add("s1"); assert.equal(await identifyUser(req(t), D(s.f)), null, "a dead session stays dead");
});
test("sign-out through this server revokes immediately, even with a long cache", async () => {
  setEnv({ SESSION_CHECK_TTL_MS: "600000" }); const s = stub(); s.live.add("s2"); const t = mint("s2");
  assert.ok(await identifyUser(req(t), D(s.f)));
  assert.equal(await signOutToken(t, s.f), true); assert.equal(s.calls.logout, 1, "session deleted at Supabase Auth");
  assert.equal(await identifyUser(req(t), D(s.f)), null, "immediately refused");
});
test("other sessions of the same user are not affected", async () => {
  setEnv(); const s = stub(); s.live.add("a"); s.live.add("b"); const sub = randomUUID(), ta = mint("a", sub), tb = mint("b", sub);
  await signOutToken(ta, s.f); assert.equal(await identifyUser(req(ta), D(s.f)), null); assert.ok(await identifyUser(req(tb), D(s.f)), "second device still signed in");
});
test("sign-out refuses invalid or forged tokens", async () => {
  setEnv(); const s = stub(); assert.equal(await signOutToken("a.b.c", s.f), false); assert.equal(await signOutToken(mint("x").slice(0, -6) + "AAAAAA", s.f), false);
});
test("positive answers are cached (Supabase is not called on every request)", async () => {
  setEnv({ SESSION_CHECK_TTL_MS: "60000" }); const s = stub(); s.live.add("c"); const t = mint("c");
  for (let i = 0; i < 5; i++) assert.ok(await identifyUser(req(t), D(s.f))); assert.equal(s.calls.user, 1);
});
test("fails closed when Supabase Auth is unreachable and the session was never confirmed; brief grace for a known-good session", async () => {
  setEnv({ SESSION_CHECK_TTL_MS: "0" }); const s = stub(); s.live.add("d"); const t = mint("d");
  const down = (async (url: string, init: any) => { if (url.endsWith("/jwks.json")) return s.f(url, init); throw new Error("network"); }) as unknown as typeof fetch;
  assert.equal(await identifyUser(req(t), D(down)), null, "unknown session + auth down -> refused");
  assert.ok(await identifyUser(req(t), D(s.f)), "confirmed once"); assert.ok(await identifyUser(req(t), D(down)), "auth down shortly after -> still accepted (grace)");
  const c = { session_id: "d" }; assert.equal(await sessionAlive(t, c, down, process.env, Date.now() + 11 * 60_000), false, "grace expires after 10 minutes");
});
test("SESSION_REVOCATION_CHECK=off restores the old behaviour; missing config skips the check", async () => {
  setEnv({ SESSION_REVOCATION_CHECK: "off" }); const s = stub(); const t = mint("never-live"); assert.ok(await identifyUser(req(t), D(s.f)));
  setEnv(); delete process.env.SUPABASE_ANON_KEY; delete process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY; assert.ok(await identifyUser(req(t), D(s.f)));
});
