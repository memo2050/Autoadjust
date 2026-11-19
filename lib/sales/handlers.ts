// AI Sales Agent HTTP handlers (framework-neutral). Public: recommend / intake / agent. Console (Bearer, role-checked): leads, pipeline, follow-ups, dashboard, audit.
import { clientIp, sameOrigin } from "../analyze/guard";
import { envViolations } from "../tenant/env-isolation";
import { createRateLimiters, type RateLimiterFactory } from "../ratelimit/shared";
import { OPEN, CLOSED, STATUSES, canMove, followupDrafts, parseLead, qualify, recommend, NEEDS, TIMELINES, type LeadInput, type Status } from "./model";
import { turn, cleanAnswers, type Answers } from "./agent";
import { supabaseSalesStore, type Lead, type SalesStore, type Followup } from "./store";

const json = (o: unknown, status = 200) => new Response(JSON.stringify(o), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
export type SalesRole = "sales_admin" | "sales_rep" | "sales_viewer";
const RANK: Record<SalesRole, number> = { sales_viewer: 1, sales_rep: 2, sales_admin: 3 };
const ids = (v: string | undefined) => (v ?? "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
/** Roles come ONLY from server env lists of Supabase user ids. A signed-in customer (tenant) user who is not listed gets 403 everywhere in the console. */
export function salesRole(env: NodeJS.ProcessEnv, userId: string): SalesRole | null {
  const u = userId.toLowerCase(); if (ids(env.SALES_ADMIN_USER_IDS).includes(u) || ids(env.PLATFORM_ADMIN_USER_IDS).includes(u)) return "sales_admin";
  if (ids(env.SALES_REP_USER_IDS).includes(u)) return "sales_rep"; if (ids(env.SALES_VIEWER_USER_IDS).includes(u)) return "sales_viewer"; return null;
}
/** Fail-closed storage gate: off by default; refuses on isolation violations and on writing to the production project from a non-production app. */
export function salesBlockReason(env: NodeJS.ProcessEnv): string | null {
  if ((env.SALES_ENABLED ?? "").toLowerCase() !== "on") return "not enabled";
  if (envViolations(env).length) return "environment isolation check failed";
  const ref = /^https:\/\/([a-z0-9]{15,30})\.supabase\.co/i.exec(env.SUPABASE_URL ?? "")?.[1]?.toLowerCase(), prod = (env.PRODUCTION_PROJECT_REF ?? "").toLowerCase();
  if (prod && ref === prod && (env.APP_ENV ?? "").toLowerCase() !== "production") return "refusing to write to the production project from a non-production app";
  if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY) return "not configured"; return null;
}
export const emailMode = (env: NodeJS.ProcessEnv): "off" | "outbox" => ((env.SALES_EMAIL_MODE ?? "").toLowerCase() === "outbox" ? "outbox" : "off");   // "live" does not exist: no real email can be sent by this code
const PROB: Record<Status, number> = { new: 0.05, contacted: 0.1, qualified: 0.25, demo_requested: 0.3, demo_scheduled: 0.45, proposal: 0.65, won: 1, lost: 0, disqualified: 0 };
export interface Deps { env: NodeJS.ProcessEnv; store?: SalesStore; user?: (req: Request) => Promise<{ id: string; email?: string } | null>; rl?: RateLimiterFactory; now?: () => number; ask?: (message: string, lang: "en" | "ar", key: string) => Promise<string | null> }

export function createSalesHandlers(d: Deps) {
  const now = d.now ?? Date.now, hops = Math.max(1, Number(d.env.TRUSTED_PROXY_HOPS) || 1), rl = d.rl ?? createRateLimiters({ env: d.env, now: d.now });
  const recLim = rl("sales-rec", 30, 2000, 3600_000), intakeLim = rl("sales-intake", 5, 200, 3600_000), agentLim = rl("sales-agent", 40, 2000, 3600_000), conLim = rl("sales-console", 300, 1e9, 60_000);
  let _store: SalesStore | undefined = d.store; const store = () => (_store ??= supabaseSalesStore(d.env));
  const gate = (req: Request) => (sameOrigin(req.headers) ? null : json({ error: "forbidden" }, 403));
  const body = async (req: Request, max = 16384) => { if (!(req.headers.get("content-type") ?? "").toLowerCase().startsWith("application/json")) return { err: json({ error: "unsupported_media_type" }, 415) }; let t = ""; try { t = await req.text(); } catch { return { err: json({ error: "invalid" }, 400) }; } if (t.length > max) return { err: json({ error: "too_large" }, 413) }; try { return { b: t ? JSON.parse(t) : {} }; } catch { return { err: json({ error: "invalid" }, 400) }; } };
  const iso = (ms: number) => new Date(ms).toISOString();

  /** Creates a lead, or merges into the existing one with the same email (no duplicates). Scores it, recommends a plan, drafts the follow-up sequence. */
  async function upsertLead(v: LeadInput, source: Lead["source"], actor: string): Promise<{ lead: Lead; created: boolean }> {
    const s = store(), demo = v.demo_slots.length > 0, ex = await s.findByEmail(v.email);
    const merged = ex ? { ...v, endpoints: v.endpoints ?? ex.endpoints, devices: v.devices ?? ex.devices, users: v.users ?? ex.users, retention_days: v.retention_days ?? ex.retention_days, company: v.company || ex.company, job_title: v.job_title || ex.job_title, country: v.country || ex.country, needs: [...new Set([...(ex.needs as any[]), ...v.needs])] as any, timeline: v.timeline === "unknown" ? (ex.timeline as any) : v.timeline, demo_slots: demo ? v.demo_slots : ex.demo_slots, message: v.message || ex.message } : v;
    const q = qualify({ ...merged, demo_requested: demo || ex?.status === "demo_requested" }), rec = recommend(merged);
    if (ex) {
      const status: Status = OPEN.includes(ex.status) && demo && ex.status !== "demo_scheduled" && ex.status !== "proposal" ? "demo_requested" : ex.status;
      const lead = (await s.updateLead(ex.id, { ...pick(merged), score: q.score, grade: q.grade, qualification: q as any, recommended_plan: rec.plan, recommendation: rec as any, status, consent_contact: true, unsubscribed: false }))!;
      await s.addActivity({ lead_id: ex.id, actor, kind: "resubmitted", body: `Resubmitted via ${source}; score ${q.score} (${q.grade}).` }); await s.audit(actor, "lead.resubmit", ex.id, { source }); return { lead, created: false };
    }
    const lead = await s.insertLead({ ...pick(merged), source, status: demo ? "demo_requested" : "new", score: q.score, grade: q.grade, qualification: q as any, recommended_plan: rec.plan, recommendation: rec as any, owner_user_id: null, lost_reason: null, anonymized: false, unsubscribed: false, consent_contact: true });
    await s.addActivity({ lead_id: lead.id, actor, kind: "created", body: `Lead created via ${source}.` }); await s.addActivity({ lead_id: lead.id, actor: "agent", kind: "qualification", body: `Score ${q.score} (${q.grade}); recommended ${rec.planName}. ${q.reasons.join("; ")}` });
    await s.insertFollowups(followupDrafts({ name: lead.name, company: lead.company, lang: lead.lang, demo }, rec.planName).map((x) => ({ lead_id: lead.id, step: x.step, template: x.template, subject: x.subject, body: x.body, lang: x.lang, status: "draft" as const, due_at: iso(now() + x.due_offset_days * 86400_000) })));
    await s.audit(actor, "lead.create", lead.id, { source, grade: q.grade }); return { lead, created: true };
  }
  const pick = (v: LeadInput) => ({ name: v.name, email: v.email, company: v.company, job_title: v.job_title, country: v.country, lang: v.lang, endpoints: v.endpoints, devices: v.devices, users: v.users, retention_days: v.retention_days, budget_monthly_usd: v.budget_monthly_usd, needs: v.needs as string[], timeline: v.timeline, message: v.message, demo_slots: v.demo_slots });
  async function cancelPending(s: SalesStore, leadId: string) { for (const f of await s.listFollowups({ leadId })) if (f.status === "draft" || f.status === "approved") await s.updateFollowup(f.id, { status: "cancelled" }); }
  const publicLead = (l: Lead) => l;   // console only: the full lead record is returned to authorized staff

  const out = {
    // ---------------- public ----------------
    /** Stateless plan recommendation: stores nothing, needs no database. */
    async recommend(req: Request) {
      const g = gate(req); if (g) return g; if (!(await recLim(clientIp(req.headers, hops)))) return json({ error: "rate_limited" }, 429);
      const r = await body(req, 4096); if (r.err) return r.err; const o = (r.b ?? {}) as any, n = (v: unknown, m: number) => (v === null || v === undefined || v === "" ? null : typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= m ? Math.round(v) : NaN);
      const f = { endpoints: n(o.endpoints, 100000), devices: n(o.devices, 100000), users: n(o.users, 10000), retention_days: n(o.retention_days, 3650) }; if (Object.values(f).some((x) => Number.isNaN(x))) return json({ error: "invalid" }, 400);
      const needs = (Array.isArray(o.needs) ? o.needs : []).filter((x: unknown) => (NEEDS as readonly string[]).includes(String(x))).slice(0, 13); return json({ recommendation: recommend({ ...(f as any), needs }) });
    },
    /** Public form: lead capture, qualification, plan recommendation, demo request. Stored only when SALES_ENABLED=on and isolation checks pass. */
    async intake(req: Request) {
      const g = gate(req); if (g) return g; if (!(await intakeLim(clientIp(req.headers, hops)))) return json({ error: "rate_limited" }, 429);
      const r = await body(req); if (r.err) return r.err; const p = parseLead(r.b); if (!p.ok) return json({ error: "invalid", message: p.error }, 400);
      const rec = recommend(p.value); if (salesBlockReason(d.env)) return json({ error: "not_enabled", recommendation: rec }, 503);   // recommendation is still useful, nothing is stored
      try { const { lead, created } = await upsertLead(p.value, "form", "public:form"); return json({ ok: true, ref: "AA-L" + lead.id.slice(0, 8).toUpperCase(), created, recommendation: rec, demoRequested: p.value.demo_slots.length > 0, message: p.value.lang === "ar" ? "شكرًا لك. سيتواصل معك فريقنا شخصيًا. لم يتم إرسال أي بريد تلقائي." : "Thank you. Our team will contact you personally. No automatic email has been sent." }); } catch { return json({ error: "store_failed" }, 502); }
    },
    /** Conversational qualification. State lives in the client; every turn is re-validated. Stores a lead only after explicit consent and only when storage is enabled. */
    async agent(req: Request) {
      const g = gate(req); if (g) return g; if (!(await agentLim(clientIp(req.headers, hops)))) return json({ error: "rate_limited" }, 429);
      const r = await body(req, 8192); if (r.err) return r.err; const o = (r.b ?? {}) as any, msg = typeof o.message === "string" ? o.message.trim() : ""; if (!msg || msg.length > 500) return json({ error: "invalid" }, 400);
      const lang = o.lang === "ar" || (o.lang !== "en" && /[؀-ۿ]/.test(msg)) ? "ar" : "en", prior = cleanAnswers(o.answers);
      let note: string | undefined; if (/\?|؟/.test(msg) && d.ask) { try { note = (await d.ask(msg, lang, clientIp(req.headers, hops))) ?? undefined; } catch { note = undefined; } }   // product questions go through the guarded support assistant
      const t = turn(msg, prior, lang, note); let ref: string | undefined, stored = false, storage: string | undefined;
      if (t.readyToStore) {
        if (salesBlockReason(d.env)) storage = "not_enabled";
        else try { const a = t.answers; const v = parseLead({ name: a.name, email: a.email, company: a.company, job_title: a.job_title, endpoints: a.endpoints, devices: a.devices, users: a.users, retention_days: a.retention_days, needs: a.needs, timeline: a.timeline, lang, consent_contact: true, message: "" }); if (v.ok) { const x = await upsertLead(v.value, "agent", "public:agent"); ref = "AA-L" + x.lead.id.slice(0, 8).toUpperCase(); stored = true; } } catch { storage = "store_failed"; }
      }
      return json({ reply: t.reply + (stored ? "\n\n" + (lang === "ar" ? "تم تسجيل طلبك. سيتواصل معك فريقنا شخصيًا؛ لم يتم إرسال أي بريد تلقائي." : "Your request is recorded. Our team will contact you personally; no automatic email was sent.") : storage === "not_enabled" && t.readyToStore ? "\n\n" + (lang === "ar" ? "ملاحظة: حفظ الطلبات غير مفعّل بعد في هذه البيئة." : "Note: saving requests is not enabled in this environment yet.") : ""), answers: t.answers, recommendation: t.recommendation ?? null, asked: t.asked, stored, ref: ref ?? null, storage: storage ?? null });
    },

    // ---------------- console ----------------
    async console(req: Request, path: string[]) {
      const g = req.method !== "GET" ? gate(req) : null; if (g) return g;
      const u = d.user ? await d.user(req).catch(() => null) : null; if (!u) return json({ error: "unauthorized" }, 401);
      const role = salesRole(d.env, u.id); if (!role) return json({ error: "forbidden" }, 403);   // signed in but not sales staff (e.g. a customer organization user)
      if (!(await conLim(u.id))) return json({ error: "rate_limited" }, 429);
      const br = salesBlockReason(d.env); if (br) return json({ error: "not_enabled", reason: br === "not enabled" ? "not_enabled" : "blocked" }, 503);
      const need = (min: SalesRole) => RANK[role] >= RANK[min], s = store(), actor = u.email ?? u.id, [a, b, c] = path, m = req.method;
      const forb = () => json({ error: "forbidden" }, 403), nf = () => json({ error: "not_found" }, 404);
      const mayEdit = (l: Lead) => need("sales_admin") || (need("sales_rep") && (!l.owner_user_id || l.owner_user_id === u.id));
      try {
        if (a === "me" && m === "GET") return json({ role, email: u.email ?? null, emailMode: emailMode(d.env), perms: { edit: need("sales_rep"), admin: need("sales_admin") } });
        if (a === "leads") {
          if (!b && m === "GET") {
            const url = new URL(req.url), st = url.searchParams.get("status"), gr = url.searchParams.get("grade"), qq = (url.searchParams.get("q") ?? "").toLowerCase().slice(0, 100), ow = url.searchParams.get("owner"), lim = Math.min(200, Math.max(1, Number(url.searchParams.get("limit")) || 50)), off = Math.max(0, Number(url.searchParams.get("offset")) || 0);
            const all = (await s.listLeads()).filter((l) => (!st || l.status === st) && (!gr || l.grade === gr) && (!ow || (ow === "me" ? l.owner_user_id === u.id : ow === "none" ? !l.owner_user_id : l.owner_user_id === ow)) && (!qq || (l.name + " " + l.email + " " + l.company).toLowerCase().includes(qq)));
            return json({ total: all.length, leads: all.slice(off, off + lim).map(publicLead) });
          }
          if (!b && m === "POST") { if (!need("sales_rep")) return forb(); const r = await body(req); if (r.err) return r.err; const o = { ...(r.b as any), consent_contact: true }; const p = parseLead(o); if (!p.ok) return json({ error: "invalid", message: p.error }, 400); const x = await upsertLead(p.value, "manual", actor); return json({ lead: x.lead, created: x.created }, x.created ? 201 : 200); }
          const lead = b ? await s.getLead(b) : null; if (b && !/^[0-9a-f-]{36}$/i.test(b)) return nf(); if (b && !lead) return nf();
          if (lead && !c && m === "GET") return json({ lead, activities: await s.listActivities(lead.id), followups: await s.listFollowups({ leadId: lead.id }) });
          if (lead && c) {
            if (m !== "POST" && !(m === "PATCH" && !c)) return json({ error: "method_not_allowed" }, 405);
            const r = await body(req); if (r.err) return r.err; const o = (r.b ?? {}) as any;
            if (c === "notes") { if (!need("sales_rep") || !mayEdit(lead)) return forb(); const t = typeof o.body === "string" ? o.body.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, " ").trim().slice(0, 4000) : ""; if (!t) return json({ error: "invalid" }, 400); await s.addActivity({ lead_id: lead.id, actor, kind: "note", body: t }); await s.audit(actor, "lead.note", lead.id); return json({ ok: true }); }
            if (c === "status") {
              if (!need("sales_rep") || !mayEdit(lead)) return forb(); const to = o.status as Status; if (!(STATUSES as readonly string[]).includes(to)) return json({ error: "invalid" }, 400);
              if (!canMove(lead.status, to, need("sales_admin"))) return json({ error: "invalid_transition", from: lead.status, to }, 409);
              const reason = typeof o.lost_reason === "string" ? o.lost_reason.slice(0, 300) : null; if (to === "lost" && !reason) return json({ error: "lost_reason_required" }, 400);
              const up = await s.updateLead(lead.id, { status: to, lost_reason: to === "lost" ? reason : lead.lost_reason, owner_user_id: lead.owner_user_id ?? (need("sales_rep") ? u.id : null) });
              if (CLOSED.includes(to)) await cancelPending(s, lead.id); await s.addActivity({ lead_id: lead.id, actor, kind: "status", body: `${lead.status} -> ${to}${reason ? " (" + reason + ")" : ""}` }); await s.audit(actor, "lead.status", lead.id, { from: lead.status, to }); return json({ lead: up });
            }
            if (c === "assign") {
              if (!need("sales_rep")) return forb(); const to = o.owner === "me" ? u.id : o.owner === null || o.owner === "none" ? null : typeof o.owner === "string" && /^[0-9a-f-]{36}$/i.test(o.owner) ? o.owner : undefined; if (to === undefined) return json({ error: "invalid" }, 400);
              if (!need("sales_admin") && !(to === u.id && (!lead.owner_user_id || lead.owner_user_id === u.id)) && !(to === null && lead.owner_user_id === u.id)) return forb();   // reps may only claim unassigned leads or release their own
              const up = await s.updateLead(lead.id, { owner_user_id: to }); await s.addActivity({ lead_id: lead.id, actor, kind: "assigned", body: to ? "assigned to " + to : "unassigned" }); await s.audit(actor, "lead.assign", lead.id, { to }); return json({ lead: up });
            }
            if (c === "requalify") { if (!need("sales_rep") || !mayEdit(lead)) return forb(); const q = qualify({ ...(lead as any), needs: lead.needs as any, timeline: lead.timeline as any, demo_requested: lead.status === "demo_requested" || lead.demo_slots.length > 0 }), rec = recommend(lead as any); const up = await s.updateLead(lead.id, { score: q.score, grade: q.grade, qualification: q as any, recommended_plan: rec.plan, recommendation: rec as any }); await s.addActivity({ lead_id: lead.id, actor, kind: "qualification", body: `Re-scored ${q.score} (${q.grade}); recommended ${rec.planName}.` }); await s.audit(actor, "lead.requalify", lead.id); return json({ lead: up }); }
            if (c === "unsubscribe") { if (!need("sales_rep") || !mayEdit(lead)) return forb(); const up = await s.updateLead(lead.id, { unsubscribed: true }); await cancelPending(s, lead.id); await s.addActivity({ lead_id: lead.id, actor, kind: "updated", body: "marked unsubscribed; pending follow-ups cancelled" }); await s.audit(actor, "lead.unsubscribe", lead.id); return json({ lead: up }); }
            if (c === "anonymize") { if (!need("sales_admin")) return forb(); await cancelPending(s, lead.id); const up = await s.updateLead(lead.id, { name: "Removed", email: `removed-${lead.id.slice(0, 8)}@invalid.local`, company: "", job_title: "", country: "", message: "", demo_slots: [], anonymized: true, status: "disqualified", consent_contact: false, unsubscribed: true, owner_user_id: null }); await s.addActivity({ lead_id: lead.id, actor, kind: "anonymized", body: "personal data removed on request" }); await s.audit(actor, "lead.anonymize", lead.id); return json({ lead: up }); }
            return nf();
          }
          if (lead && m === "PATCH") {
            if (!need("sales_rep") || !mayEdit(lead)) return forb(); const r = await body(req); if (r.err) return r.err; const o = (r.b ?? {}) as any, p = parseLead({ ...lead, ...o, consent_contact: true, website: "", demo_slots: o.demo_slots ?? lead.demo_slots }); if (!p.ok) return json({ error: "invalid", message: p.error }, 400);
            const allowed = ["name", "company", "job_title", "country", "endpoints", "devices", "users", "retention_days", "needs", "timeline", "message", "budget_monthly_usd"].filter((k) => k in o), patch: any = {}; for (const k of allowed) patch[k] = (p.value as any)[k];
            const up = await s.updateLead(lead.id, patch); await s.addActivity({ lead_id: lead.id, actor, kind: "updated", body: "fields: " + allowed.join(", ") }); await s.audit(actor, "lead.update", lead.id, { fields: allowed }); return json({ lead: up });
          }
          return nf();
        }
        if (a === "pipeline" && m === "GET") { const all = await s.listLeads(); return json({ stages: STATUSES.map((st) => { const ls = all.filter((l) => l.status === st); return { status: st, count: ls.length, valueAnnualUsd: Math.round(ls.reduce((x, l) => x + (l.recommendation?.annualUsd ?? 0), 0)), leads: ls.slice(0, 50).map((l) => ({ id: l.id, name: l.name, company: l.company, grade: l.grade, score: l.score, plan: l.recommended_plan, owner: l.owner_user_id, updated_at: l.updated_at })) }; }) }); }
        if (a === "followups") {
          if (!b && m === "GET") { const st = new URL(req.url).searchParams.get("status") as Followup["status"] | null; const fs = await s.listFollowups({ status: st ?? undefined }); return json({ followups: fs.slice(0, 500), emailMode: emailMode(d.env) }); }
          if (b === "run" && m === "POST") {
            if (!need("sales_admin")) return forb(); const mode = emailMode(d.env), due = (await s.listFollowups({ status: "approved" })).filter((f) => Date.parse(f.due_at) <= now()); if (mode === "off") return json({ mode, processed: 0, cancelled: 0, due: due.length, note: "Email mode is off: nothing is sent or recorded. Set SALES_EMAIL_MODE=outbox for a dry run; real sending is not implemented." });
            let processed = 0, cancelled = 0; for (const f of due) { const l = await s.getLead(f.lead_id); if (!l || l.anonymized || l.unsubscribed || !l.consent_contact || CLOSED.includes(l.status)) { await s.updateFollowup(f.id, { status: "cancelled" }); cancelled++; continue; } await s.updateFollowup(f.id, { status: "dry_run", processed_at: iso(now()) }); await s.addActivity({ lead_id: l.id, actor: "agent", kind: "followup", body: `dry run (not sent): ${f.template}` }); processed++; }
            await s.audit(actor, "followups.run", "", { mode, processed, cancelled }); return json({ mode, processed, cancelled, due: due.length, note: "Dry run only. No email left the system." });
          }
          const f = b ? await s.getFollowup(b) : null; if (b && !/^[0-9a-f-]{36}$/i.test(b)) return nf(); if (!f) return nf(); const lead = await s.getLead(f.lead_id);
          if (c === "approve" && m === "POST") { if (!need("sales_admin")) return forb(); if (f.status !== "draft") return json({ error: "invalid_state" }, 409); if (!lead || lead.anonymized || lead.unsubscribed || !lead.consent_contact || CLOSED.includes(lead.status)) return json({ error: "lead_not_contactable" }, 409); const up = await s.updateFollowup(f.id, { status: "approved", approved_by: actor, approved_at: iso(now()) }); await s.addActivity({ lead_id: f.lead_id, actor, kind: "followup", body: `approved ${f.template} (step ${f.step})` }); await s.audit(actor, "followup.approve", f.id); return json({ followup: up }); }
          if (c === "cancel" && m === "POST") { if (!need("sales_rep") || (lead && !mayEdit(lead))) return forb(); if (f.status !== "draft" && f.status !== "approved") return json({ error: "invalid_state" }, 409); const up = await s.updateFollowup(f.id, { status: "cancelled" }); await s.audit(actor, "followup.cancel", f.id); return json({ followup: up }); }
          if (!c && m === "PATCH") { if (!need("sales_rep") || (lead && !mayEdit(lead))) return forb(); if (f.status !== "draft") return json({ error: "invalid_state" }, 409); const r = await body(req); if (r.err) return r.err; const o = (r.b ?? {}) as any, sub = typeof o.subject === "string" ? o.subject.replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, 200) : f.subject, bd = typeof o.body === "string" ? o.body.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "").trim().slice(0, 6000) : f.body; if (!sub || !bd) return json({ error: "invalid" }, 400); const up = await s.updateFollowup(f.id, { subject: sub, body: bd }); await s.audit(actor, "followup.edit", f.id); return json({ followup: up }); }
          return nf();
        }
        if (a === "dashboard" && m === "GET") {
          const days = Math.min(180, Math.max(1, Number(new URL(req.url).searchParams.get("days")) || 30)), all = await s.listLeads(), fus = await s.listFollowups({}), since = now() - days * 86400_000, inWin = all.filter((l) => Date.parse(l.created_at) >= since);
          const cnt = <T>(xs: T[], f: (x: T) => string) => xs.reduce((o: Record<string, number>, x) => { const k = f(x) || "none"; o[k] = (o[k] ?? 0) + 1; return o; }, {});
          const open = all.filter((l) => OPEN.includes(l.status)), won = all.filter((l) => l.status === "won"), lost = all.filter((l) => l.status === "lost"), closed = won.length + lost.length;
          const series: Record<string, number> = {}; for (let i = days - 1; i >= 0; i--) series[new Date(now() - i * 86400_000).toISOString().slice(0, 10)] = 0; for (const l of inWin) { const k = l.created_at.slice(0, 10); if (k in series) series[k]++; }
          const reached = (xs: Status[]) => all.filter((l) => xs.includes(l.status)).length;
          return json({ windowDays: days, totals: { leads: all.length, newInWindow: inWin.length, open: open.length, won: won.length, lost: lost.length, disqualified: all.filter((l) => l.status === "disqualified").length, unassigned: open.filter((l) => !l.owner_user_id).length, avgScore: all.length ? Math.round(all.reduce((x, l) => x + l.score, 0) / all.length) : 0 },
            byStatus: cnt(all, (l) => l.status), byGrade: cnt(all, (l) => l.grade), bySource: cnt(all, (l) => l.source), byPlan: cnt(all, (l) => l.recommended_plan ?? ""), byTimeline: cnt(all, (l) => l.timeline),
            funnel: { leads: all.length, qualifiedOrBeyond: reached(["qualified", "demo_requested", "demo_scheduled", "proposal", "won"]), demo: reached(["demo_requested", "demo_scheduled", "proposal", "won"]), proposal: reached(["proposal", "won"]), won: won.length },
            rates: { winRate: closed ? Math.round((won.length / closed) * 100) : null, demoRate: all.length ? Math.round((reached(["demo_requested", "demo_scheduled", "proposal", "won"]) / all.length) * 100) : null },
            pipeline: { openAnnualUsd: Math.round(open.reduce((x, l) => x + (l.recommendation?.annualUsd ?? 0), 0)), weightedAnnualUsd: Math.round(open.reduce((x, l) => x + (l.recommendation?.annualUsd ?? 0) * PROB[l.status], 0)), wonAnnualUsd: Math.round(won.reduce((x, l) => x + (l.recommendation?.annualUsd ?? 0), 0)), note: "Values are list-price proposals from the plan recommendation, not invoices; payments are not enabled." },
            followups: cnt(fus, (f) => f.status), emailMode: emailMode(d.env), leadsPerDay: series });
        }
        if (a === "audit" && m === "GET") { if (!need("sales_admin")) return forb(); return json({ audit: await s.listAudit(Math.min(200, Number(new URL(req.url).searchParams.get("limit")) || 100)) }); }
        return nf();
      } catch { return json({ error: "store_failed" }, 502); }
    },
  };
  return out;
}
