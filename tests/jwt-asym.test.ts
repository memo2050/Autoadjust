// JWT verification for Supabase asymmetric signing keys (ES256/RS256) via JWKS. Keys are generated locally; the JWKS endpoint is a stub fetch.
// Evidence class: LOCAL (cryptography is real, the Supabase server is not). Real-project JWKS is verified by the staging smoke test.
import test from "node:test"; import assert from "node:assert/strict";
import { generateKeyPairSync, createSign, randomUUID, sign } from "node:crypto";
import { verifyJwtAsym, _resetJwksCache } from "../lib/tenant/auth";
const ISS = "https://abcd.supabase.co/auth/v1", URL = ISS + "/.well-known/jwks.json";
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
function mk(alg: "ES256" | "RS256", kid: string) {
  const { publicKey, privateKey } = alg === "ES256" ? generateKeyPairSync("ec", { namedCurve: "P-256" }) : generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = { ...(publicKey.export({ format: "jwk" }) as object), kid, alg, use: "sig" } as any;
  const tok = (claims: object = {}, head: object = {}) => { const h = b64({ alg, typ: "JWT", kid, ...head }), p = b64({ sub: randomUUID(), role: "authenticated", aud: "authenticated", iss: ISS, exp: Math.floor(Date.now() / 1000) + 600, ...claims });
    const sig = alg === "ES256" ? sign("sha256", Buffer.from(`${h}.${p}`), { key: privateKey, dsaEncoding: "ieee-p1363" }) : createSign("RSA-SHA256").update(`${h}.${p}`).sign(privateKey); return `${h}.${p}.${sig.toString("base64url")}`; };
  return { jwk, tok };
}
const jwksFetch = (keys: any[], count = { n: 0 }) => (async () => { count.n++; return new Response(JSON.stringify({ keys }), { status: 200 }); }) as unknown as typeof fetch;
for (const alg of ["ES256", "RS256"] as const) test(`${alg}: valid accepted; wrong issuer/audience/role/expiry/signature/alg/kid refused`, async () => {
  _resetJwksCache(); const a = mk(alg, "k1"), other = mk(alg, "k1"), f = jwksFetch([a.jwk]);
  assert.ok(await verifyJwtAsym(a.tok(), URL, ISS, f), "valid");
  assert.equal(await verifyJwtAsym(a.tok({ iss: "https://evil.supabase.co/auth/v1" }), URL, ISS, f), null, "issuer");
  assert.equal(await verifyJwtAsym(a.tok({ aud: "x" }), URL, ISS, f), null, "audience");
  assert.equal(await verifyJwtAsym(a.tok({ role: "anon" }), URL, ISS, f), null, "anon");
  assert.equal(await verifyJwtAsym(a.tok({ role: "service_role" }), URL, ISS, f), null, "service role");
  assert.equal(await verifyJwtAsym(a.tok({ exp: Math.floor(Date.now() / 1000) - 5 }), URL, ISS, f), null, "expired");
  assert.equal(await verifyJwtAsym(a.tok({ sub: "not-a-uuid" }), URL, ISS, f), null, "sub");
  assert.equal(await verifyJwtAsym(other.tok(), URL, ISS, f), null, "signed by a different key with the same kid");
  const t = a.tok(); const [h, p, s] = t.split("."); assert.equal(await verifyJwtAsym(`${h}.${b64({ sub: randomUUID(), role: "authenticated", aud: "authenticated", iss: ISS, exp: 9999999999 })}.${s}`, URL, ISS, f), null, "tampered payload");
  assert.equal(await verifyJwtAsym(`${b64({ alg: "none", kid: "k1" })}.${p}.`, URL, ISS, f), null, "alg none");
  assert.equal(await verifyJwtAsym(`${b64({ alg: "HS256", kid: "k1" })}.${p}.${s}`, URL, ISS, f), null, "algorithm confusion (HS256 with public key material)");
  assert.equal(await verifyJwtAsym(a.tok({}, { kid: "unknown" }), URL, ISS, f), null, "unknown kid");
});
test("JWKS: cached; unknown kid refetch is rate limited; key rotation picked up", async () => {
  _resetJwksCache(); const a = mk("ES256", "k1"), b = mk("ES256", "k2"), c = { n: 0 }; let keys = [a.jwk]; const f = (async () => { c.n++; return new Response(JSON.stringify({ keys }), { status: 200 }); }) as unknown as typeof fetch;
  const t0 = Date.now(); await verifyJwtAsym(a.tok(), URL, ISS, f, t0); await verifyJwtAsym(a.tok(), URL, ISS, f, t0 + 1000); assert.equal(c.n, 1, "cached");
  for (let i = 0; i < 20; i++) await verifyJwtAsym(b.tok(), URL, ISS, f, t0 + 2000 + i); assert.equal(c.n, 1, "unknown kids inside the 30 s window cause no refetch");
  keys = [a.jwk, b.jwk]; assert.ok(await verifyJwtAsym(b.tok(), URL, ISS, f, t0 + 40_000), "rotated-in key accepted after the refetch window"); assert.equal(c.n, 2);
});
test("JWKS endpoint down: fails closed", async () => { _resetJwksCache(); const a = mk("ES256", "k1"); const f = (async () => new Response("no", { status: 500 })) as unknown as typeof fetch; assert.equal(await verifyJwtAsym(a.tok(), URL, ISS, f), null); });
