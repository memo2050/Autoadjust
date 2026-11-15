// T9: customer data export and deletion (staging only). The SQL hard-delete function is proved separately on a scratch Postgres (see docs/DATA_LIFECYCLE.md); here: the API flow and the in-memory store.
import test from "node:test";
import assert from "node:assert/strict";
import { createHmac, createHash, randomUUID } from "node:crypto";
import { inflateRawSync } from "node:zlib";
import { readdirSync, readFileSync } from "node:fs";
import { TestStore } from "./test-store";
import { handleSoc } from "../lib/soc/api";
import { OWNED_TABLES, NOT_ORG_DATA, zip, exportLink, verifyExportLink } from "../lib/tenant/lifecycle";
import { ORG_TABLES } from "../lib/tenant/scoped-store";

process.env.SUPABASE_JWT_SECRET = "test-jwt-secret-test-jwt-secret-1234567890"; delete process.env.SOC_ADMIN_TOKEN;
const SECRET = "e".repeat(40), b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (sub: string, aal = "aal2") => { const h = b64({ alg: "HS256", typ: "JWT" }), p = b64({ sub, email: sub.slice(0, 6) + "@x.io", role: "authenticated", aud: "authenticated", aal, exp: Math.floor(Date.now() / 1000) + 3600 }); return `${h}.${p}.${createHmac("sha256", process.env.SUPABASE_JWT_SECRET!).update(`${h}.${p}`).digest("base64url")}`; };
const A = "a1000000-0000-4000-8000-0000000000a1", B = "b1000000-0000-4000-8000-0000000000b1";
async function world(extraEnv: Record<string, string> = {}) {
  const s = new TestStore(), u = { ownerA: randomUUID(), adminA: randomUUID(), ownerB: randomUUID(), plat: randomUUID() };
  const env = { EXPORT_SIGNING_SECRET: SECRET, PLATFORM_ADMIN_USER_IDS: u.plat + "," + u.ownerA, MFA_ENFORCE: "on", ...extraEnv };
  await s.upsert("organizations", [{ id: A, name: "Acme Corp", slug: "acme", plan: "free", settings: {}, createdAt: "2026-01-01T00:00:00Z" }, { id: B, name: "Bravo", slug: "bravo", plan: "free", settings: {} }] as any);
  await s.upsert("org_members", [{ orgId: A, userId: u.ownerA, role: "owner" }, { orgId: A, userId: u.adminA, role: "it_admin" }, { orgId: B, userId: u.ownerB, role: "owner" }, { orgId: B, userId: u.plat, role: "executive_readonly" }] as any, "org_id,user_id");
  const call = async (method: string, p: string, tok: string | null, body?: unknown, headers: Record<string, string> = {}) => { const r = await handleSoc(new Request("http://x/api/soc/" + p, { method, headers: { ...(tok ? { authorization: "Bearer " + tok } : {}), "content-type": "application/json", ...headers }, body: body === undefined ? undefined : JSON.stringify(body) }), p.split("?")[0].split("/"), { store: s, model: null, env } as any);
    const ct = r.headers.get("content-type") ?? ""; return { status: r.status, headers: r.headers, body: ct.includes("json") ? ((await r.json().catch(() => ({}))) as any) : Buffer.from(await r.arrayBuffer()) }; };
  // data in both organizations, including secrets that must never be exported
  const ev = (org: string, i: number) => ({ id: `${org}:evt_${String(i).padStart(6, "0")}`, orgId: org, host: "h", summary: "e" + i, time: "2026-01-01T00:00:00Z" });
  await s.upsert("soc_events", [...Array.from({ length: 2500 }, (_, i) => ev(A, i)), ev(B, 1)] as any);
  await s.upsert("noc_sources", [{ id: `${A}:src1`, orgId: A, name: "zabbix", hasSecret: true, secret: "SUPER-SECRET-VALUE" }, { id: `${B}:srcb`, orgId: B, name: "b-src", secret: "B-SECRET" }] as any);
  await s.upsert("org_api_keys", [{ id: "k1", orgId: A, name: "collector", keyHash: "HASHVALUE-A", keyPrefix: "aa_live_abcd" }] as any);
  await s.upsert("org_invitations", [{ id: "i1", orgId: A, email: "x@y.io", tokenHash: "TOKHASH-A" }] as any);
  await s.upsert("soc_meta", [{ id: `${A}:wazuh`, data: { enc: "ENCRYPTED-CREDS", apiUrl: "https://w" } }, { id: `${B}:wazuh`, data: { enc: "B-CREDS" } }] as any);
  await s.upsert("soc_audit", [{ id: "aud_1", orgId: A, actor: "x", role: "owner", action: "t", target: "t", detail: {}, seq: 1, prevHash: "genesis", hash: "h1", time: "2026-01-01T00:00:00Z" }] as any);
  return { s, call, u, tokOwner: jwt(u.ownerA), tokAdmin: jwt(u.adminA), tokOwnerB: jwt(u.ownerB), tokPlat: jwt(u.plat) };
}
/** Minimal ZIP reader (central directory) so the test checks the archive for real. */
function unzip(buf: Buffer): Record<string, Buffer> {
  const eocd = buf.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06])), n = buf.readUInt16LE(eocd + 10); let p = buf.readUInt32LE(eocd + 16); const out: Record<string, Buffer> = {};
  for (let i = 0; i < n; i++) { const method = buf.readUInt16LE(p + 10), crc = buf.readUInt32LE(p + 16), csz = buf.readUInt32LE(p + 20), nl = buf.readUInt16LE(p + 28), off = buf.readUInt32LE(p + 42), name = buf.subarray(p + 46, p + 46 + nl).toString();
    const lnl = buf.readUInt16LE(off + 26), lel = buf.readUInt16LE(off + 28), data = buf.subarray(off + 30 + lnl + lel, off + 30 + lnl + lel + csz), raw = method === 8 ? inflateRawSync(data) : data;
    let c = 0xffffffff; for (const b of raw) { c ^= b; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; } assert.equal((c ^ 0xffffffff) >>> 0, crc, "crc of " + name);
    out[name] = raw; p += 46 + nl; }
  return out;
}
const dl = (w: any, url: string) => w.call("GET", url.replace("/api/soc/", ""), null);

test("export: owner gets a valid ZIP of ONLY their organization; secrets and hashes are redacted; >1000 rows are paged, none lost", async () => {
  const w = await world(); const r = await w.call("POST", "org/export", w.tokOwner); assert.equal(r.status, 200); assert.equal(r.body.singleUse, true);
  const d = await dl(w, r.body.downloadUrl); assert.equal(d.status, 200); assert.equal(d.headers.get("content-type"), "application/zip"); assert.equal(d.headers.get("cache-control"), "no-store");
  const f = unzip(d.body), m = JSON.parse(f["manifest.json"].toString());
  assert.equal(JSON.parse(f["data/soc_events.json"].toString()).length, 2500, "paged read exports every row"); assert.equal(m.tables.soc_events.rows, 2500); assert.ok(!m.tables.soc_events.truncated);
  assert.equal(JSON.parse(f["data/soc_events.json"].toString())[0].id.startsWith("evt_"), true, "org prefix stripped from ids");
  const all = Object.values(f).map((b) => b.toString()).join("\n");
  for (const bad of ["SUPER-SECRET-VALUE", "HASHVALUE-A", "TOKHASH-A", "ENCRYPTED-CREDS", "B-SECRET", "B-CREDS", B, "Bravo"]) assert.ok(!all.includes(bad), "export must not contain " + bad);
  assert.ok(all.includes("[redacted]") && m.redactedFields.includes("secret") && m.redactedFields.includes("keyHash") && m.redactedFields.includes("enc"));
  assert.ok(JSON.parse(f["data/noc_sources.json"].toString())[0].hasSecret === true, "non-secret fields are kept");
  for (const [t, info] of Object.entries<any>(m.tables)) assert.equal(createHash("sha256").update(f[`data/${t}.json`]).digest("hex"), info.sha256, "manifest hash for " + t);
  assert.ok(!("orgId" in JSON.parse(f["data/soc_events.json"].toString())[0]));
  const aud = (await w.s.select<any>("soc_audit")).filter((a) => a.orgId === A).map((a) => a.action); assert.ok(aud.includes("org.export_requested") && aud.includes("org.export_downloaded"));
});
test("export links: single use, expire, cannot be forged, bound to the owner; non-owners cannot request; MFA applies", async () => {
  const w = await world(); const r = await w.call("POST", "org/export", w.tokOwner);
  assert.equal((await dl(w, r.body.downloadUrl)).status, 200); assert.equal((await dl(w, r.body.downloadUrl)).status, 410, "second use refused");
  assert.equal((await w.call("POST", "org/export", w.tokAdmin)).status, 403, "it_admin is not the owner"); assert.equal((await w.call("POST", "org/export", w.tokOwnerB)).status, 200, "other org's owner exports their own org only");
  const bd = await dl(w, (await w.call("POST", "org/export", w.tokOwnerB)).body.downloadUrl); assert.ok(!Object.values(unzip(bd.body)).map((x) => x.toString()).join("").includes("Acme"), "org B export holds no org A data");
  const t = (await w.call("POST", "org/export", w.tokOwner)).body.downloadUrl; const tok = decodeURIComponent(t.split("t=")[1]);
  const env = { EXPORT_SIGNING_SECRET: SECRET }, parts = tok.split("."); assert.ok(verifyExportLink(env, tok));
  assert.equal(verifyExportLink(env, [parts[0], B, ...parts.slice(2)].join(".")), null, "org id cannot be swapped"); assert.equal(verifyExportLink(env, tok.slice(0, -2) + "xx"), null);
  assert.equal(verifyExportLink(env, tok, Date.now() + 11 * 60000), null, "expired after 10 minutes"); assert.equal(verifyExportLink({ EXPORT_SIGNING_SECRET: "z".repeat(40) }, tok), null, "other secret");
  assert.equal((await w.call("GET", "org/export/download?t=garbage", null)).status, 403);
  assert.throws(() => exportLink({}, A, "u"), /not configured/);
  const noMfa = await w.call("POST", "org/export", jwt(w.u.ownerA, "aal1")); assert.equal(noMfa.status, 403); assert.equal(noMfa.body.code, "mfa_required");
  await w.s.upsert("org_members", [{ orgId: A, userId: w.u.ownerA, role: "it_admin" }] as any, "org_id,user_id"); assert.equal((await dl(w, t)).status, 403, "demoted before download: refused");
});
test("zip(): empty and many-file archives are readable", () => { const f = unzip(zip([{ name: "a.txt", data: Buffer.from("hello") }, { name: "b/c.json", data: Buffer.alloc(100000, 7) }])); assert.equal(f["a.txt"].toString(), "hello"); assert.equal(f["b/c.json"].length, 100000); assert.deepEqual(unzip(zip([])), {}); });

const past = async (w: any, id: string) => { const [r] = await w.s.select("org_deletion_requests", { where: { id } }); await w.s.upsert("org_deletion_requests", [{ ...r, holdUntil: new Date(Date.now() - 1000).toISOString() }]); };
test("deletion: confirm name, 14-day hold, cancel, separation of duties, billing guard, then real removal of every org row; other org untouched; tombstone kept", async () => {
  const w = await world();
  assert.equal((await w.call("POST", "org/deletion", w.tokAdmin, { confirm: "Acme Corp" })).status, 403, "only the owner");
  assert.equal((await w.call("POST", "org/deletion", w.tokOwner, { confirm: "acme" })).body.code, "confirm_mismatch");
  const q = await w.call("POST", "org/deletion", w.tokOwner, { confirm: "Acme Corp" }); assert.equal(q.status, 201);
  const days = (Date.parse(q.body.request.holdUntil) - Date.parse(q.body.request.requestedAt)) / 86400000; assert.equal(Math.round(days), 14);
  assert.equal((await w.call("POST", "org/deletion", w.tokOwner, { confirm: "Acme Corp" })).status, 409, "one open request");
  assert.equal((await w.call("GET", "org/deletion", w.tokAdmin)).body.request.id, q.body.request.id);
  assert.equal((await w.call("DELETE", "org/deletion", w.tokOwner)).status, 200); assert.equal((await w.call("GET", "org/deletion", w.tokOwner)).body.request, null, "cancelled");
  const id = (await w.call("POST", "org/deletion", w.tokOwner, { confirm: "Acme Corp" })).body.request.id;
  const ap = (tok: string) => w.call("POST", `admin/deletions/${id}/approve`, tok);
  assert.equal((await ap(w.tokOwner)).status, 403, "the requester cannot approve (even if they are a platform admin)"); assert.equal((await ap(w.tokAdmin)).status, 403, "not a platform admin");
  assert.equal((await w.call("GET", "admin/deletions", w.tokAdmin)).status, 403);
  const early = await ap(w.tokPlat); assert.equal(early.status, 409); assert.equal(early.body.code, "hold_active"); assert.equal((await w.s.select("organizations", { where: { id: A } })).length, 1, "nothing deleted during the hold");
  assert.equal((await ap(jwt(w.u.plat, "aal1"))).body.code, "mfa_required", "platform admin needs MFA to approve");
  await past(w, id);
  await w.s.upsert("org_billing", [{ orgId: A, plan: "pro", status: "active", subscriptionId: "sub_1", customerId: "cus_1" }] as any, "org_id"); assert.equal((await ap(w.tokPlat)).body.code, "subscription_active");
  await w.s.upsert("org_billing", [{ orgId: A, plan: "free", status: "canceled", subscriptionId: "sub_1", customerId: "cus_1" }] as any, "org_id");
  const bBefore = JSON.stringify(Object.fromEntries(["soc_events", "noc_sources", "soc_meta", "org_members"].map((t) => [t, 0])));
  const done = await ap(w.tokPlat); assert.equal(done.status, 200, JSON.stringify(done.body)); assert.equal(done.body.deleted, true); assert.ok(done.body.rowsDeleted > 2500);
  // every table: nothing of org A remains; org B intact
  const mem: Map<string, Map<string, any>> = (w.s as any).t; let leftA = 0, bRows = 0;
  for (const [name, m] of mem) { if (["org_tombstones", "org_deletion_requests"].includes(name)) continue; for (const r of m.values()) { if (r.orgId === A || String(r.id ?? "").startsWith(A + ":")) leftA++; if (r.orgId === B || String(r.id ?? "").startsWith(B + ":")) bRows++; } }
  assert.equal(leftA, 0, "no row of the deleted organization remains in any table"); assert.equal((await w.s.select("organizations", { where: { id: A } })).length, 0); assert.equal((await w.s.select("organizations", { where: { id: B } })).length, 1);
  assert.equal(bRows, 1 + 1 + 1 + 2, "org B rows untouched (event, source, meta, 2 members)"); void bBefore;
  const [tomb] = await w.s.select<any>("org_tombstones", {}); assert.equal(tomb.orgId, A); assert.equal(tomb.nameSha256, createHash("sha256").update("Acme Corp").digest("hex")); assert.equal(tomb.finalAuditHash != null, true); assert.ok(tomb.rowCounts.soc_events === 2500); assert.ok(!JSON.stringify(tomb).includes("Acme"));
  assert.equal((await w.s.select<any>("org_deletion_requests", { where: { id } }))[0].status, "completed");
  assert.equal((await w.call("POST", `admin/deletions/${id}/approve`, w.tokPlat)).status, 409, "cannot run twice");
  assert.equal((await w.call("GET", "org/mine", w.tokOwner)).status, 200, "the person's own account is untouched");
});
test("deletion: the Default organization and failures are handled safely", async () => {
  const w = await world(); const D = "00000000-0000-0000-0000-000000000001"; await w.s.upsert("organizations", [{ id: D, name: "Default organization", slug: "default" }] as any); await w.s.upsert("org_members", [{ orgId: D, userId: w.u.ownerA, role: "owner" }] as any, "org_id,user_id");
  assert.equal((await w.call("POST", "org/deletion", w.tokOwner, { confirm: "Default organization" }, { "x-org-id": D })).status, 403);
  const q = await w.call("POST", "org/deletion", w.tokOwner, { confirm: "Acme Corp" }, { "x-org-id": A }); await past(w, q.body.request.id);
  (w.s as any).hardDeleteOrg = async () => { throw new Error("db exploded"); };
  const r = await w.call("POST", `admin/deletions/${q.body.request.id}/approve`, w.tokPlat); assert.equal(r.status, 500); assert.match(r.body.error, /nothing was removed/);
  assert.equal((await w.s.select<any>("org_deletion_requests", { where: { id: q.body.request.id } }))[0].status, "failed"); assert.equal((await w.s.select("organizations", { where: { id: A } })).length, 1);
});
test("completeness guard: every table in the migrations is either deleted/exported as organization data or explicitly marked as not organization data", () => {
  const dir = "supabase/migrations", found = new Set<string>();
  for (const f of readdirSync(dir).filter((x) => /^0\d{3}_.*\.sql$/.test(x))) { const sql = readFileSync(`${dir}/${f}`, "utf8");
    for (const m of sql.matchAll(/create table (?:if not exists )?public\.([a-z_]+)/g)) found.add(m[1]);
    for (const m of sql.matchAll(/foreach t in array array\[([^\]]+)\]/g)) for (const n of m[1].matchAll(/'([a-z_]+)'/g)) found.add(n[1]); }
  const known = new Set<string>([...OWNED_TABLES, ...NOT_ORG_DATA]), unknown = [...found].filter((t) => !known.has(t));
  assert.deepEqual(unknown, [], "new table(s) must be added to OWNED_TABLES (customer data: exported + deleted) or NOT_ORG_DATA: " + unknown.join(", "));
  for (const t of ORG_TABLES) assert.ok((OWNED_TABLES as readonly string[]).includes(t), t + " is an organization table and must be exported/deleted");
  assert.equal(new Set(OWNED_TABLES).size, OWNED_TABLES.length);
});
