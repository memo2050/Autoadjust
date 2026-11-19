// AI Sales Agent: qualification, plan recommendation, demo requests, follow-ups, CRM pipeline, dashboard, RBAC, isolation, audit, safety.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "fs";
import { qualify, recommend, parseLead, followupDrafts, canMove } from "../lib/sales/model";
import { extract, turn, cleanAnswers } from "../lib/sales/agent";
import { createSalesHandlers, salesRole, salesBlockReason } from "../lib/sales/handlers";
import { memoryStore, supabaseSalesStore } from "../lib/sales/store";

const H = "app.test", ADMIN = "11111111-1111-1111-1111-111111111111", REP = "22222222-2222-2222-2222-222222222222", REP2 = "33333333-3333-3333-3333-333333333333", VIEW = "44444444-4444-4444-4444-444444444444", CUST = "55555555-5555-5555-5555-555555555555";
const ENV = { SALES_ENABLED: "on", SUPABASE_URL: "https://abcdefghijklmnopqrst.supabase.co", SUPABASE_SERVICE_ROLE_KEY: "svc-placeholder", APP_ENV: "staging", PRODUCTION_PROJECT_REF: "zzzzzzzzzzzzzzzzzzzz", SALES_ADMIN_USER_IDS: ADMIN, SALES_REP_USER_IDS: REP + "," + REP2, SALES_VIEWER_USER_IDS: VIEW } as NodeJS.ProcessEnv;
let ipn = 0; const mk = (env: Record<string, string> = {}, ask?: any) => { const store = memoryStore(); const h = createSalesHandlers({ env: { ...ENV, ...env } as NodeJS.ProcessEnv, store, ask, user: async (r) => { const t = (r.headers.get("authorization") ?? "").replace("Bearer ", ""); return t ? { id: t, email: t + "@example.com" } : null; } }); return { h, store }; };
const R = (path: string, o: { method?: string; body?: unknown; as?: string; ip?: string; origin?: string } = {}) => new Request(`https://${H}/api/sales/${path}`, { method: o.method ?? "GET", headers: { host: H, ...(o.method && o.method !== "GET" ? { origin: o.origin ?? `https://${H}`, "content-type": "application/json" } : {}), "x-forwarded-for": o.ip ?? "9.9.9." + (++ipn % 250), ...(o.as ? { authorization: "Bearer " + o.as } : {}) }, body: o.body === undefined ? undefined : JSON.stringify(o.body) });
const J = async (r: Response | Promise<Response>) => { const x = await r; return { s: x.status, j: (await x.json()) as any }; };
const FORM = { name: "Dana Lee", email: "dana@acme-corp.com", company: "Acme Corp", job_title: "IT Director", country: "US", endpoints: 120, devices: 40, users: 8, retention_days: 30, needs: ["soc", "noc"], timeline: "1-3m", message: "Need monitoring", consent_contact: true };
const intake = async (h: any, over: any = {}) => J(h.intake(R("intake", { method: "POST", body: { ...FORM, ...over } })));
const con = (h: any, path: string, as: string, method = "GET", body?: unknown) => J(h.console(R(path, { method, as, body }), path.split("?")[0].split("/")));

test("1 lead qualification: scoring, grades, disqualification, missing fields", () => {
  const a = qualify({ ...FORM, needs: ["soc", "noc"] as any, timeline: "now", demo_requested: true } as any); assert.equal(a.grade, "A"); assert.ok(a.qualified);
  const free = qualify({ ...FORM, email: "dana@gmail.com", job_title: "", company: "", endpoints: 5, devices: null, needs: [], timeline: "unknown" } as any); assert.ok(free.score < 35 && free.grade === "D" && !free.qualified); assert.ok(free.missing.includes("job_title") && free.missing.includes("timeline"));
  assert.ok(a.score > qualify({ ...FORM, timeline: "later", job_title: "intern" } as any).score);
  assert.equal(qualify({ ...FORM, email: "x@mailinator.com" } as any).disqualified, true);
  const p = parseLead({ ...FORM, email: "x@mailinator.com" }); assert.equal(p.ok, false);
  assert.equal(parseLead({ ...FORM, consent_contact: false }).ok, false); assert.equal(parseLead({ ...FORM, website: "bot" }).ok, false); assert.equal(parseLead({ ...FORM, endpoints: -1 }).ok, false); assert.equal(parseLead({ ...FORM, endpoints: "abc" }).ok, false);
  const v: any = parseLead({ ...FORM, name: "<b>Dana</b>\u0000", needs: ["soc", "hack", "soc"], demo_slots: ["2026-12-01T10:00:00Z", "not a date"] }); assert.ok(v.ok); assert.doesNotMatch(v.value.name, /[<>\u0000]/); assert.deepEqual(v.value.needs, ["soc"]); assert.equal(v.value.demo_slots.length, 1);
});
test("2 plan recommendation: right tier, add-ons, honesty about soon/planned, enterprise, confidence", () => {
  assert.equal(recommend({ endpoints: 20, devices: 5, users: 2, retention_days: 7, needs: [] }).plan, "basic");
  const mid = recommend({ endpoints: 120, devices: 40, users: 8, retention_days: 30, needs: ["soc", "noc"] }); assert.equal(mid.plan, "professional"); assert.equal(mid.monthlyUsd, 199); assert.equal(mid.annualUsd, 2029.8);
  const ao = recommend({ endpoints: 30, devices: 10, users: 3, retention_days: 7, needs: [] }); assert.equal(ao.plan, "basic"); assert.equal(ao.monthlyUsd, 64); assert.equal(ao.addons[0].qty, 1);   // 25 included + 1 x 25 add-on is cheaper than Standard
  assert.equal(recommend({ endpoints: 5000, devices: 100, users: 10, retention_days: 30, needs: [] }).plan, "enterprise");
  const z = recommend({ endpoints: 30, devices: 10, users: 3, retention_days: 7, needs: ["zabbix"] }); assert.equal(z.plan, "professional"); assert.ok(z.caveats.some((c) => /Zabbix.*coming soon/i.test(c)));   // integration needs push the tier up, never claimed as available
  const sl = recommend({ endpoints: 30, devices: 10, users: 3, retention_days: 7, needs: ["syslog", "prtg"] }); assert.ok(sl.notAvailable.length === 2 && sl.notAvailable.every((x) => /planned and not built/.test(x)));
  assert.equal(recommend({ endpoints: 30, devices: null, users: null, retention_days: null, needs: [] }).confidence, "low"); assert.ok(mid.caveats.some((c) => /payment is not enabled/i.test(c)));
  assert.equal(recommend({ endpoints: 10, devices: 5, users: 12, retention_days: 7, needs: [] }).plan, "business");   // users cannot be topped up with add-ons
});
test("agent conversation extracts facts (EN and AR), asks next question, recommends, then asks consent", () => {
  const e = extract("We have 120 endpoints and 40 switches, 8 users, want SOC and NOC with Wazuh, ASAP", {}); assert.deepEqual([e.endpoints, e.devices, e.users, e.timeline], [120, 40, 8, "now"]); assert.ok(e.needs!.includes("soc") && e.needs!.includes("wazuh"));
  const ar = extract("لدينا ١٢٠ جهاز كمبيوتر و ٣٠ سويتش و ٥ مستخدمين نحتاج مراقبة الشبكة", {}); assert.deepEqual([ar.endpoints, ar.devices, ar.users], [120, 30, 5]); assert.ok(ar.needs!.includes("noc"));
  let t = turn("hi, I need a plan", {}, "en"); assert.equal(t.asked, "endpoints"); t = turn("about 60 laptops", t.answers, "en"); assert.equal(t.answers.endpoints, 60); assert.equal(t.asked, "needs");
  t = turn("security monitoring please", t.answers, "en"); t = turn("5", { ...t.answers, asked: "users" }, "en"); t = turn("within 3 months", t.answers, "en");
  assert.ok(t.recommendation && /Standard/.test(t.reply) && /not enabled/i.test(t.reply)); assert.equal(t.asked, "name");
  t = turn("Sam Cole", t.answers, "en"); t = turn("sam@bigco.io", t.answers, "en"); t = turn("BigCo", t.answers, "en"); t = turn("Security Manager", t.answers, "en"); assert.equal(t.asked, "consent"); assert.equal(t.readyToStore, false);
  const yes = turn("yes", t.answers, "en"); assert.equal(yes.readyToStore, true); const no = turn("no", t.answers, "en"); assert.equal(no.readyToStore, false); assert.ok(no.declined);
  assert.equal(turn("مرحبا", {}, "ar").asked, "endpoints"); { let k = turn("40 laptops, SOC and NOC", {}, "en"); assert.equal(k.asked, "devices"); k = turn("not sure", k.answers, "en"); assert.equal(k.asked, "users"); k = turn("don't know", k.answers, "en"); assert.equal(k.asked, "timeline"); k = turn("skip", k.answers, "en"); assert.ok(k.recommendation); assert.equal(k.asked, "name"); } assert.deepEqual(cleanAnswers({ endpoints: -5, needs: ["soc", "x"], email: "A@B.CO", consent: "yes" }), { endpoints: undefined, devices: undefined, users: undefined, retention_days: undefined, needs: ["soc"], timeline: undefined, name: undefined, email: "a@b.co", company: undefined, job_title: undefined, consent: undefined, asked: undefined, recShown: false, skip: undefined });
});
test("3 demo request collection: form creates a lead with demo status, dedupes, honours the off switch, validates, rate limits", async () => {
  const { h, store } = mk(); const r = await intake(h, { demo_slots: ["2026-12-03T15:00:00Z"] }); assert.equal(r.s, 200); assert.match(r.j.ref, /^AA-L[0-9A-F]{8}$/); assert.equal(r.j.demoRequested, true); assert.match(r.j.message, /No automatic email/);
  const l = [...store._leads.values()][0]; assert.equal(l.status, "demo_requested"); assert.equal(l.source, "form"); assert.ok(["A", "B"].includes(l.grade)); assert.equal(l.recommended_plan, "professional");
  const again = await intake(h, { demo_slots: ["2026-12-04T15:00:00Z"], endpoints: 130 }); assert.equal(again.j.created, false); assert.equal(store._leads.size, 1);
  assert.equal((await intake(h, { email: "bad" })).s, 400); assert.equal((await intake(h, { consent_contact: false })).s, 400); assert.equal((await J(h.intake(R("intake", { method: "POST", origin: "https://evil.example", body: FORM })))).s, 403);
  assert.equal((await J(h.intake(new Request(`https://${H}/api/sales/intake`, { method: "POST", headers: { host: H, origin: `https://${H}`, "content-type": "text/plain" }, body: "{}" })))).s, 415);
  const off = mk({ SALES_ENABLED: "" }); const o = await intake(off.h); assert.equal(o.s, 503); assert.equal(o.j.error, "not_enabled"); assert.ok(o.j.recommendation); assert.equal(off.store._leads.size, 0);   // disabled: recommendation only, nothing stored
  const lim = mk(); let last = 0; for (let i = 0; i < 6; i++) last = (await J(lim.h.intake(R("intake", { method: "POST", ip: "7.7.7.7", body: { ...FORM, email: `u${i}@acme-corp.com` } })))).s; assert.equal(last, 429);
  const prod = mk({ SUPABASE_URL: "https://zzzzzzzzzzzzzzzzzzzz.supabase.co" }); assert.equal((await intake(prod.h)).s, 503); assert.match(salesBlockReason({ ...ENV, SUPABASE_URL: "https://zzzzzzzzzzzzzzzzzzzz.supabase.co", APP_ENV: "" } as any)!, /production/);
});
test("agent endpoint: full conversation stores a lead only after consent; product questions go through the guarded assistant", async () => {
  const { h, store } = mk({}, async (m: string) => "ANSWER: Pro includes SOC views."); const post = (message: string, answers: any) => J(h.agent(R("agent", { method: "POST", ip: "3.3.3.3", body: { message, answers } })));
  let r = await post("We have 60 laptops, need SOC, 5 users, within 3 months", {}); assert.equal(r.s, 200); assert.ok(r.j.recommendation); assert.equal(store._leads.size, 0);
  r = await post("I'm Sam Cole, sam@bigco.io", r.j.answers); r = await post("BigCo", r.j.answers); r = await post("Security Manager", r.j.answers); assert.equal(r.j.asked, "consent"); assert.equal(store._leads.size, 0);
  r = await post("no", r.j.answers); assert.equal(store._leads.size, 0);
  let r2 = await post("yes", { ...r.j.answers, consent: undefined, asked: "consent" }); assert.equal(r2.j.stored, true); assert.equal(store._leads.size, 1); assert.equal([...store._leads.values()][0].source, "agent");
  const q = await post("What does the Pro plan include?", {}); assert.match(q.j.reply, /ANSWER: Pro includes/);
  assert.equal((await J(h.agent(R("agent", { method: "POST", body: { message: "x".repeat(501) } })))).s, 400);
});
test("4 follow-up: drafts bilingual sequence, nothing is sent, approval needed, dry-run only, stops on close/unsubscribe/anonymize", async () => {
  const d = followupDrafts({ name: "Dana Lee", company: "Acme", lang: "en", demo: true }, "Professional"); assert.deepEqual(d.map((x) => x.template), ["thanks", "demo", "recap", "checkin"]); assert.ok(d.every((x) => /unsubscribe/.test(x.body)));
  assert.match(followupDrafts({ name: "سارة", company: "", lang: "ar", demo: false }, "Standard")[0].body, /لا يتم خصم/);
  const { h, store } = mk({ SALES_EMAIL_MODE: "outbox" }); await intake(h); const lead = [...store._leads.values()][0], fus = await store.listFollowups({ leadId: lead.id }); assert.equal(fus.length, 3); assert.ok(fus.every((f) => f.status === "draft"));
  assert.equal((await con(h, "followups/run", ADMIN, "POST", {})).j.processed, 0);   // drafts are never processed
  assert.equal((await con(h, `followups/${fus[0].id}/approve`, REP, "POST", {})).s, 403); assert.equal((await con(h, `followups/${fus[0].id}/approve`, ADMIN, "POST", {})).s, 200); assert.equal((await con(h, `followups/${fus[0].id}/approve`, ADMIN, "POST", {})).s, 409);
  const run = await con(h, "followups/run", ADMIN, "POST", {}); assert.equal(run.j.processed, 1); assert.match(run.j.note, /No email left the system/); assert.equal((await store.getFollowup(fus[0].id))!.status, "dry_run");
  const off = mk(); await intake(off.h); const f2 = (await off.store.listFollowups({}))[0]; await con(off.h, `followups/${f2.id}/approve`, ADMIN, "POST", {}); const r2 = await con(off.h, "followups/run", ADMIN, "POST", {}); assert.equal(r2.j.mode, "off"); assert.equal(r2.j.processed, 0); assert.equal((await off.store.getFollowup(f2.id))!.status, "approved");   // email mode off: nothing happens
  const l2 = mk({ SALES_EMAIL_MODE: "outbox" }); await intake(l2.h); const id = [...l2.store._leads.values()][0].id, fl = await l2.store.listFollowups({}); await con(l2.h, `followups/${fl[0].id}/approve`, ADMIN, "POST", {});
  await con(l2.h, `leads/${id}/status`, ADMIN, "POST", { status: "lost", lost_reason: "no budget" }); assert.ok((await l2.store.listFollowups({})).every((f) => f.status === "cancelled")); assert.equal((await con(l2.h, `followups/${fl[1].id}/approve`, ADMIN, "POST", {})).s, 409);
  const u = mk(); await intake(u.h); const uid = [...u.store._leads.values()][0].id; await con(u.h, `leads/${uid}/unsubscribe`, REP, "POST", {}); assert.ok((await u.store.listFollowups({})).every((f) => f.status === "cancelled"));
  const edit = mk(); await intake(edit.h); const ef = (await edit.store.listFollowups({}))[0]; assert.equal((await con(edit.h, `followups/${ef.id}`, REP, "PATCH", { subject: "Hello", body: "Edited" })).s, 200); assert.equal((await con(edit.h, `followups/${ef.id}`, VIEW, "PATCH", { subject: "x", body: "y" })).s, 403);
});
test("5 CRM pipeline: list/filter/search, detail, status machine, notes, assignment, requalify, anonymize", async () => {
  const { h, store } = mk(); await intake(h); await intake(h, { name: "Omar K", email: "omar@globex.io", company: "Globex", endpoints: 10, devices: 2, users: 1, job_title: "", timeline: "later" }); const [a, b] = [...store._leads.values()];
  const list = await con(h, "leads?q=globex", REP); assert.equal(list.j.total, 1); assert.equal((await con(h, "leads?grade=" + a.grade, REP)).j.leads.every((l: any) => l.grade === a.grade), true);
  const det = await con(h, `leads/${a.id}`, VIEW); assert.equal(det.s, 200); assert.ok(det.j.activities.length >= 2 && det.j.followups.length === 3);
  assert.equal((await con(h, `leads/${a.id}/status`, REP, "POST", { status: "won" })).s, 409); assert.equal((await con(h, `leads/${a.id}/status`, REP, "POST", { status: "contacted" })).s, 200); assert.equal((await con(h, `leads/${a.id}/status`, REP, "POST", { status: "lost" })).s, 400);
  assert.equal((await con(h, `leads/${a.id}/status`, REP, "POST", { status: "qualified" })).j.lead.owner_user_id, REP);   // working a lead claims it
  assert.equal((await con(h, `leads/${a.id}/notes`, REP2, "POST", { body: "call back" })).s, 403);   // another rep cannot edit a lead owned by REP
  assert.equal((await con(h, `leads/${a.id}/notes`, REP, "POST", { body: "left voicemail" })).s, 200); assert.equal((await con(h, `leads/${a.id}/notes`, ADMIN, "POST", { body: "admin note" })).s, 200);
  assert.equal((await con(h, `leads/${a.id}/assign`, REP2, "POST", { owner: "me" })).s, 403); assert.equal((await con(h, `leads/${a.id}/assign`, ADMIN, "POST", { owner: REP2 })).j.lead.owner_user_id, REP2);
  assert.equal((await con(h, `leads/${b.id}/assign`, REP, "POST", { owner: REP2 })).s, 403);
  assert.equal((await con(h, `leads/${b.id}`, REP, "PATCH", { endpoints: 500, devices: 100, users: 20, job_title: "CTO" })).s, 200); const rq = await con(h, `leads/${b.id}/requalify`, REP, "POST", {}); assert.equal(rq.j.lead.recommended_plan, "business");
  await con(h, `leads/${b.id}/status`, REP, "POST", { status: "lost", lost_reason: "chose competitor" }); assert.equal((await con(h, `leads/${b.id}/status`, REP, "POST", { status: "contacted" })).s, 409); assert.equal((await con(h, `leads/${b.id}/status`, ADMIN, "POST", { status: "contacted" })).s, 200);
  const pipe = await con(h, "pipeline", VIEW); assert.equal(pipe.j.stages.length, 9); assert.equal(pipe.j.stages.reduce((x: number, s: any) => x + s.count, 0), 2);
  assert.equal((await con(h, `leads/${a.id}/anonymize`, REP, "POST", {})).s, 403); const an = await con(h, `leads/${a.id}/anonymize`, ADMIN, "POST", {}); assert.equal(an.j.lead.name, "Removed"); assert.equal(an.j.lead.anonymized, true); assert.doesNotMatch(JSON.stringify(an.j.lead), /dana|acme/i);
  assert.ok((await store.listFollowups({ leadId: a.id })).every((f) => f.status === "cancelled")); assert.equal((await intake(h)).j.created, true);   // email can be re-registered after erasure
  assert.equal((await con(h, `leads/not-a-uuid`, ADMIN)).s, 404); assert.equal((await con(h, `leads/${"0".repeat(8)}-0000-0000-0000-000000000000`, ADMIN)).s, 404);
  assert.ok(canMove("new", "contacted", false) && !canMove("won", "lost", true) && canMove("lost", "contacted", true) && !canMove("lost", "contacted", false));
  const manual = await con(h, "leads", REP, "POST", { name: "Lin", email: "lin@initech.com", company: "Initech", endpoints: 40 }); assert.equal(manual.s, 201); assert.equal((await con(h, "leads", VIEW, "POST", { name: "x", email: "x@y.com" })).s, 403);
});
test("6 dashboard and analytics: totals, funnel, rates, plan mix, weighted pipeline, series, follow-up counts", async () => {
  const { h, store } = mk(); await intake(h); await intake(h, { email: "b@globex.io", name: "B", endpoints: 10, devices: 2, users: 1 }); await intake(h, { email: "c@initech.com", name: "C", demo_slots: ["2026-12-03T15:00:00Z"], endpoints: 300, devices: 100, users: 20 });
  const [a, b] = [...store._leads.values()]; await con(h, `leads/${a.id}/status`, ADMIN, "POST", { status: "qualified" }); await con(h, `leads/${a.id}/status`, ADMIN, "POST", { status: "proposal" }); await con(h, `leads/${a.id}/status`, ADMIN, "POST", { status: "won" }); await con(h, `leads/${b.id}/status`, ADMIN, "POST", { status: "lost", lost_reason: "price" });
  const d = (await con(h, "dashboard?days=14", VIEW)).j; assert.equal(d.totals.leads, 3); assert.equal(d.totals.won, 1); assert.equal(d.totals.lost, 1); assert.equal(d.totals.open, 1); assert.equal(d.rates.winRate, 50); assert.equal(d.funnel.leads, 3); assert.equal(d.funnel.won, 1); assert.equal(d.byPlan.professional, 2); assert.equal(d.byPlan.business, 1); assert.equal(Object.keys(d.leadsPerDay).length, 14); assert.equal(Object.values(d.leadsPerDay).reduce((x: any, y: any) => x + y, 0), 3);
  assert.equal(d.pipeline.wonAnnualUsd, 2030); assert.ok(d.pipeline.openAnnualUsd > 0 && d.pipeline.weightedAnnualUsd < d.pipeline.openAnnualUsd); assert.ok(d.followups.draft > 0 || d.followups.cancelled > 0); assert.match(d.pipeline.note, /not invoices/);
});
test("RBAC: unauthenticated 401, customer/unlisted 403, viewer read-only, rep limits, admin-only actions, audit access", async () => {
  const { h } = mk(); await intake(h);
  assert.equal((await J(h.console(R("dashboard"), ["dashboard"]))).s, 401); assert.equal((await con(h, "dashboard", CUST)).s, 403); assert.equal((await con(h, "leads", CUST)).s, 403); assert.equal((await con(h, "pipeline", "forged-token-not-listed")).s, 403);
  assert.equal((await con(h, "me", VIEW)).j.role, "sales_viewer"); assert.equal((await con(h, "me", REP)).j.role, "sales_rep"); assert.equal((await con(h, "me", ADMIN)).j.role, "sales_admin");
  assert.equal((await con(h, "audit", REP)).s, 403); assert.equal((await con(h, "audit", VIEW)).s, 403); assert.equal((await con(h, "audit", ADMIN)).s, 200); assert.equal((await con(h, "followups/run", REP, "POST", {})).s, 403);
  assert.equal(salesRole({ PLATFORM_ADMIN_USER_IDS: CUST } as any, CUST), "sales_admin"); assert.equal(salesRole({} as any, ADMIN), null);
  assert.equal((await J(h.console(R("leads", { method: "POST", as: ADMIN, origin: "https://evil.example", body: FORM }), ["leads"]))).s, 403);   // cross-site writes refused
  const off = mk({ SALES_ENABLED: "" }); assert.equal((await con(off.h, "dashboard", ADMIN)).s, 503);
});
test("audit log: every mutation recorded with actor, no personal data in audit metadata", async () => {
  const { h, store } = mk(); await intake(h); const id = [...store._leads.values()][0].id; await con(h, `leads/${id}/status`, REP, "POST", { status: "contacted" }); await con(h, `leads/${id}/notes`, REP, "POST", { body: "secret note text" }); await con(h, `leads/${id}/anonymize`, ADMIN, "POST", {});
  const acts = store._audit.map((a) => a.action); for (const x of ["lead.create", "lead.status", "lead.note", "lead.anonymize"]) assert.ok(acts.includes(x), x); assert.ok(store._audit.every((a) => a.actor.length > 0));
  const txt = JSON.stringify(store._audit); assert.doesNotMatch(txt, /dana@acme|secret note text|Acme/i);
});
test("isolation and safety by construction: no tenant data access, no email sending code, no payments, no demo_requests coupling", () => {
  const src = readdirSync("lib/sales").map((f) => readFileSync("lib/sales/" + f, "utf8")).join("\n");
  assert.doesNotMatch(src, /scoped-store|ScopedStore|from "\.\.\/soc|from "\.\.\/noc|org_id|orgId|x-org-id/); assert.doesNotMatch(src, /nodemailer|sendgrid|mailgun|resend\.com|smtp|\/messages\/send|api\.postmarkapp|ses\.amazonaws/i); assert.doesNotMatch(src, /stripe|checkout/i);
  assert.doesNotMatch(readFileSync("lib/sales/handlers.ts", "utf8"), /process\.env/);   // all configuration is injected; nothing is read ambiently
  const mig = readFileSync("supabase/migrations/0118_sales_agent.sql", "utf8"); assert.match(mig, /enable row level security/); assert.match(mig, /revoke all on public\.sales_leads, public\.sales_activities, public\.sales_followups, public\.sales_audit from public, anon, authenticated/); assert.doesNotMatch(mig, /create policy/i); assert.match(mig, /append-only/);
  assert.match(readFileSync("lib/tenant/lifecycle.ts", "utf8"), /"sales_leads"/);
});
test("Supabase store sends the expected REST calls (service role, server side)", async () => {
  const calls: any[] = []; const f = (async (u: string, i: any) => { calls.push({ u, m: i.method ?? "GET", b: i.body }); return new Response(JSON.stringify([{ id: "x" }]), { status: 200 }); }) as any; const s = supabaseSalesStore({ SUPABASE_URL: "https://abc.supabase.co", SUPABASE_SERVICE_ROLE_KEY: "k" } as any, f);
  await s.findByEmail("A@B.co"); await s.updateLead("id1", { score: 5 }); await s.audit("a", "x", "t", { k: 1 }); await s.listFollowups({ status: "approved", leadId: "L" });
  assert.match(calls[0].u, /sales_leads\?email=eq\.a%40b\.co&anonymized=eq\.false/); assert.equal(calls[1].m, "PATCH"); assert.match(calls[2].u, /sales_audit$/); assert.match(calls[3].u, /status=eq\.approved/);
});
