import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "fs";
import { answer, detectLang, KB } from "../lib/support/kb";
import { parseTicket, memoryStore, ticketBlockReason } from "../lib/support/tickets";
import { createSupportHandlers } from "../lib/support/handlers";
const env: any = { SUPPORT_TICKETS_ENABLED: "on", SUPABASE_URL: "https://abcdefghijklmnopqrst.supabase.co", SUPABASE_SERVICE_ROLE_KEY: "x".repeat(40), APP_ENV: "staging", PRODUCTION_PROJECT_REF: "zzzzzzzzzzzzzzzzzzzz" };
const H = { host: "site.test", origin: "https://site.test", "content-type": "application/json" };
const rq = (path: string, b: unknown, h: Record<string, string> = H) => new Request("https://site.test" + path, { method: "POST", headers: h, body: JSON.stringify(b) });
const good = { name: "Sam", email: "sam@example.com", subject: "Cannot sign in", body: "I get an error when I sign in.", category: "account", lang: "en" };
test("language detection and bilingual answers", () => {
  assert.equal(detectLang("كم سعر الباقة؟"), "ar"); assert.equal(detectLang("how much is the plan"), "en");
  const a = answer("كم سعر الاشتراك؟"); assert.equal(a.lang, "ar"); assert.equal(a.topic, "pricing"); assert.match(a.answer, /49/);
  assert.equal(answer("What is your pricing?").topic, "pricing"); assert.equal(answer("zzz qqq").topic, null);
  for (const e of KB) { assert.ok(e.en && e.ar && /[؀-ۿ]/.test(e.ar), e.id); }
});
test("KB never claims payments are live or unvalidated features are ready", () => {
  const all = KB.map((e) => e.en + e.ar).join(" "); assert.match(all, /not enabled yet|not active yet/); assert.doesNotMatch(all, /checkout|buy now/i);
});
test("ticket validation, honeypot and sanitising", () => {
  assert.equal(parseTicket(good).ok, true);
  assert.equal(parseTicket({ ...good, email: "bad" }).ok, false); assert.equal(parseTicket({ ...good, body: "short" }).ok, false);
  assert.equal(parseTicket({ ...good, website: "http://spam" }).ok, false);
  const p: any = parseTicket({ ...good, category: "evil", lang: "fr", subject: "Hi\u0000 there" }); assert.equal(p.value.category, "general"); assert.equal(p.value.lang, "en"); assert.ok(!p.value.subject.includes("\u0000"));
});
test("storage is off by default and fail-closed", () => {
  assert.equal(ticketBlockReason({}), "storage not enabled"); assert.equal(ticketBlockReason(env), null); assert.match(ticketBlockReason({ ...env, SUPABASE_URL: "https://zzzzzzzzzzzzzzzzzzzz.supabase.co" })!, /isolation/);
  assert.match(ticketBlockReason({ ...env, APP_ENV: "", SUPABASE_URL: "https://zzzzzzzzzzzzzzzzzzzz.supabase.co" })!, /production/);
  assert.equal(ticketBlockReason({ ...env, SUPABASE_SERVICE_ROLE_KEY: "" }) !== null, true);
});
test("create, track, reply; token hashed; wrong token and unknown ref indistinguishable", async () => {
  const store = memoryStore(), h = createSupportHandlers({ env, store });
  const r = await h.create(rq("/api/support/tickets", good)); assert.equal(r.status, 201); const c: any = await r.json();
  assert.match(c.ref, /^AA-[0-9A-F]{8}$/); assert.match(c.token, /^[0-9a-f]{48}$/);
  const row = store.rows.get(c.ref); assert.notEqual(row.token_hash, c.token); assert.equal(row.token_hash.length, 64); assert.ok(!JSON.stringify(row).includes(c.token));
  let t: any = await (await h.track(rq("/api/support/track", { ref: c.ref, token: c.token }))).json(); assert.equal(t.ticket.status, "open"); assert.equal(t.messages.length, 1); assert.equal(t.ticket.token_hash, undefined); assert.equal(t.ticket.email, undefined);
  const bad = await h.track(rq("/api/support/track", { ref: c.ref, token: "0".repeat(48) })), unk = await h.track(rq("/api/support/track", { ref: "AA-00000000", token: c.token }));
  assert.equal(bad.status, 404); assert.equal(unk.status, 404); assert.equal(await bad.text(), await unk.text());
  t = await (await h.track(rq("/api/support/track", { ref: c.ref, token: c.token, reply: "Any update please?" }))).json(); assert.equal(t.messages.length, 2);
  row.status = "closed"; assert.equal((await h.track(rq("/api/support/track", { ref: c.ref, token: c.token, reply: "hello again" }))).status, 409);
});
test("cross-origin, content-type, size, disabled storage and rate limits", async () => {
  const h = createSupportHandlers({ env, store: memoryStore() });
  assert.equal((await h.create(rq("/api/support/tickets", good, { ...H, origin: "https://evil.test" }))).status, 403);
  assert.equal((await h.create(rq("/api/support/tickets", good, { host: "site.test", origin: "https://site.test", "content-type": "text/plain" }))).status, 415);
  assert.equal((await h.create(rq("/api/support/tickets", { ...good, body: "x".repeat(9000) }))).status, 413);
  assert.equal((await createSupportHandlers({ env: {}, store: memoryStore() }).create(rq("/api/support/tickets", good))).status, 503);
  const l = createSupportHandlers({ env, store: memoryStore() }); const codes: number[] = []; for (let i = 0; i < 7; i++) codes.push((await l.create(rq("/api/support/tickets", good, { ...H, "x-forwarded-for": "9.9.9.9" }))).status);
  assert.deepEqual(codes, [201, 201, 201, 201, 201, 429, 429]);
});
test("chat endpoint works without storage and reports ticket availability", async () => {
  const h = createSupportHandlers({ env: {} }); const j: any = await (await h.chat(rq("/api/support/chat", { message: "سعر", lang: "ar" }))).json();
  assert.equal(j.lang, "ar"); assert.equal(j.ticketsEnabled, false); assert.equal((await h.chat(rq("/api/support/chat", { message: "" }))).status, 400);
  assert.equal((await h.chat(rq("/api/support/chat", { message: "x".repeat(501) }))).status, 400);
});
test("widget is bilingual/RTL, uses no innerHTML, and demo blocks tickets", () => {
  const w = readFileSync("public/support-widget.js", "utf8"); assert.match(w, /rtl/); assert.match(w, /العربية/); assert.doesNotMatch(w, /innerHTML|eval\(/);
  const d = readFileSync("public/demo.js", "utf8"); assert.match(d, /api\/support\/chat/); assert.doesNotMatch(d, /api\/support\/tickets/);
});
test("migration 0116 is server-only (RLS, no grants) and additive", () => {
  const m = readFileSync("supabase/migrations/0116_support_tickets.sql", "utf8"); assert.match(m, /enable row level security/); assert.match(m, /revoke all on public\.support_tickets, public\.support_messages from public, anon, authenticated/); assert.doesNotMatch(m, /create policy|drop table|delete from public/i);
});
