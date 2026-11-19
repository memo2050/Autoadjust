import type { Status } from "./model";
export interface Lead { id: string; created_at: string; updated_at: string; name: string; email: string; company: string; job_title: string; country: string; lang: "en" | "ar"; source: "form" | "agent" | "manual"; endpoints: number | null; devices: number | null; users: number | null; retention_days: number | null; budget_monthly_usd: number | null; needs: string[]; timeline: string; message: string; demo_slots: string[]; consent_contact: boolean; unsubscribed: boolean; status: Status; score: number; grade: "A" | "B" | "C" | "D"; qualification: any; recommended_plan: string | null; recommendation: any; owner_user_id: string | null; lost_reason: string | null; anonymized: boolean }
export interface Activity { id: string; lead_id: string; at: string; actor: string; kind: string; body: string }
export interface Followup { id: string; lead_id: string; step: number; template: string; subject: string; body: string; lang: "en" | "ar"; status: "draft" | "approved" | "dry_run" | "sent" | "cancelled"; due_at: string; approved_by: string | null; approved_at: string | null; processed_at: string | null; created_at: string }
export interface AuditRow { id: number; at: string; actor: string; action: string; target: string; meta: Record<string, unknown> }
export interface SalesStore {
  insertLead(l: Omit<Lead, "id" | "created_at" | "updated_at">): Promise<Lead>;
  getLead(id: string): Promise<Lead | null>;
  findByEmail(email: string): Promise<Lead | null>;
  updateLead(id: string, patch: Partial<Lead>): Promise<Lead | null>;
  listLeads(): Promise<Lead[]>;                                   // bounded (<= 5000, newest first); filtering/paging happens in the API layer
  addActivity(a: Omit<Activity, "id" | "at">): Promise<void>;
  listActivities(leadId: string): Promise<Activity[]>;
  insertFollowups(f: Array<Omit<Followup, "id" | "created_at" | "approved_by" | "approved_at" | "processed_at">>): Promise<Followup[]>;
  listFollowups(q: { leadId?: string; status?: Followup["status"] }): Promise<Followup[]>;
  getFollowup(id: string): Promise<Followup | null>;
  updateFollowup(id: string, patch: Partial<Followup>): Promise<Followup | null>;
  audit(actor: string, action: string, target: string, meta?: Record<string, unknown>): Promise<void>;
  listAudit(limit: number): Promise<AuditRow[]>;
}
const uuid = () => crypto.randomUUID();
export function memoryStore(now: () => number = Date.now): SalesStore & { _leads: Map<string, Lead>; _audit: AuditRow[] } {
  const leads = new Map<string, Lead>(), acts: Activity[] = [], fus = new Map<string, Followup>(), aud: AuditRow[] = []; let seq = 0; const iso = () => new Date(now()).toISOString();
  return {
    _leads: leads, _audit: aud,
    async insertLead(l) { if ([...leads.values()].some((x) => !x.anonymized && x.email.toLowerCase() === l.email.toLowerCase())) throw new Error("duplicate"); const r: Lead = { ...l, id: uuid(), created_at: iso(), updated_at: iso() }; leads.set(r.id, r); return { ...r }; },
    async getLead(id) { const r = leads.get(id); return r ? { ...r } : null; },
    async findByEmail(e) { const r = [...leads.values()].find((x) => !x.anonymized && x.email.toLowerCase() === e.toLowerCase()); return r ? { ...r } : null; },
    async updateLead(id, p) { const r = leads.get(id); if (!r) return null; Object.assign(r, p, { updated_at: iso() }); return { ...r }; },
    async listLeads() { return [...leads.values()].sort((a, b) => (a.created_at < b.created_at ? 1 : -1)).slice(0, 5000).map((x) => ({ ...x })); },
    async addActivity(a) { acts.push({ ...a, id: uuid(), at: iso() }); },
    async listActivities(id) { return acts.filter((a) => a.lead_id === id).reverse(); },
    async insertFollowups(f) { return f.map((x) => { const r: Followup = { ...x, id: uuid(), created_at: iso(), approved_by: null, approved_at: null, processed_at: null }; fus.set(r.id, r); return { ...r }; }); },
    async listFollowups(q) { return [...fus.values()].filter((f) => (!q.leadId || f.lead_id === q.leadId) && (!q.status || f.status === q.status)).sort((a, b) => (a.due_at < b.due_at ? -1 : 1)).map((x) => ({ ...x })); },
    async getFollowup(id) { const r = fus.get(id); return r ? { ...r } : null; },
    async updateFollowup(id, p) { const r = fus.get(id); if (!r) return null; Object.assign(r, p); return { ...r }; },
    async audit(actor, action, target, meta = {}) { aud.push({ id: ++seq, at: iso(), actor, action, target, meta }); },
    async listAudit(n) { return aud.slice(-n).reverse(); },
  };
}
/** Supabase REST store (service role, server only). Tables: sales_leads, sales_activities, sales_followups, sales_audit (migration 0118). */
export function supabaseSalesStore(env: NodeJS.ProcessEnv, f: typeof fetch = fetch): SalesStore {
  const base = (env.SUPABASE_URL ?? "").replace(/\/$/, "") + "/rest/v1/", key = env.SUPABASE_SERVICE_ROLE_KEY ?? "";
  const h = { apikey: key, Authorization: "Bearer " + key, "Content-Type": "application/json" }, q = encodeURIComponent;
  const call = async (path: string, init: RequestInit = {}) => { const r = await f(base + path, { ...init, headers: { ...h, ...(init.headers as any) }, signal: AbortSignal.timeout(8000) }); if (!r.ok) throw new Error("store " + r.status); return r.status === 204 ? null : r.json(); };
  const one = async <T>(path: string, init?: RequestInit): Promise<T | null> => ((await call(path, init)) as T[] | null)?.[0] ?? null;
  const rep = { Prefer: "return=representation" };
  return {
    insertLead: async (l) => (await one<Lead>("sales_leads", { method: "POST", headers: rep, body: JSON.stringify(l) }))!,
    getLead: (id) => one<Lead>(`sales_leads?id=eq.${q(id)}&limit=1`),
    findByEmail: (e) => one<Lead>(`sales_leads?email=eq.${q(e.toLowerCase())}&anonymized=eq.false&limit=1`),
    updateLead: (id, p) => one<Lead>(`sales_leads?id=eq.${q(id)}`, { method: "PATCH", headers: rep, body: JSON.stringify({ ...p, updated_at: new Date().toISOString() }) }),
    listLeads: async () => ((await call("sales_leads?select=*&order=created_at.desc&limit=5000")) as Lead[]) ?? [],
    addActivity: async (a) => { await call("sales_activities", { method: "POST", body: JSON.stringify(a) }); },
    listActivities: async (id) => ((await call(`sales_activities?lead_id=eq.${q(id)}&order=at.desc&limit=500`)) as Activity[]) ?? [],
    insertFollowups: async (fs) => (((await call("sales_followups", { method: "POST", headers: rep, body: JSON.stringify(fs) })) as Followup[]) ?? []),
    listFollowups: async (x) => ((await call(`sales_followups?select=*&order=due_at.asc&limit=2000${x.leadId ? "&lead_id=eq." + q(x.leadId) : ""}${x.status ? "&status=eq." + q(x.status) : ""}`)) as Followup[]) ?? [],
    getFollowup: (id) => one<Followup>(`sales_followups?id=eq.${q(id)}&limit=1`),
    updateFollowup: (id, p) => one<Followup>(`sales_followups?id=eq.${q(id)}`, { method: "PATCH", headers: rep, body: JSON.stringify(p) }),
    audit: async (actor, action, target, meta = {}) => { await call("sales_audit", { method: "POST", body: JSON.stringify({ actor, action, target, meta }) }); },
    listAudit: async (n) => ((await call(`sales_audit?select=*&order=id.desc&limit=${Math.min(500, Math.max(1, n | 0))}`)) as AuditRow[]) ?? [],
  };
}
