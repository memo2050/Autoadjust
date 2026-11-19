import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { envViolations } from "../tenant/env-isolation";
export const CATEGORIES = ["general", "technical", "billing", "security", "account"] as const;
export const STATUSES = ["open", "in_progress", "waiting_customer", "resolved", "closed"] as const;
export type Category = (typeof CATEGORIES)[number]; export type Status = (typeof STATUSES)[number];
export interface TicketInput { name: string; email: string; subject: string; body: string; category: Category; lang: "en" | "ar" }
export interface Ticket { id: string; ref: string; status: Status; subject: string; category: Category; lang: string; created_at: string; updated_at: string }
export interface Message { author: "customer" | "support"; body: string; created_at: string }
const EMAIL = /^[^\s@<>]{1,64}@[^\s@<>]{1,190}\.[^\s@<>]{2,}$/;
const clean = (v: unknown, max: number) => (typeof v === "string" ? v.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, " ").trim().slice(0, max) : "");
export function parseTicket(b: unknown): { ok: true; value: TicketInput } | { ok: false; error: string } {
  if (!b || typeof b !== "object") return { ok: false, error: "invalid" }; const o = b as Record<string, unknown>;
  if (typeof o.website === "string" && o.website) return { ok: false, error: "invalid" };   // honeypot
  const name = clean(o.name, 120), email = clean(o.email, 200).toLowerCase(), subject = clean(o.subject, 160), body = clean(o.body, 4000);
  const category = (CATEGORIES as readonly string[]).includes(o.category as string) ? (o.category as Category) : "general";
  if (!name) return { ok: false, error: "name" }; if (!EMAIL.test(email)) return { ok: false, error: "email" };
  if (subject.length < 3) return { ok: false, error: "subject" }; if (body.length < 10) return { ok: false, error: "body" };
  return { ok: true, value: { name, email, subject, body, category, lang: o.lang === "ar" ? "ar" : "en" } };
}
export const newRef = () => "AA-" + randomBytes(4).toString("hex").toUpperCase();
export const newToken = () => randomBytes(24).toString("hex");
export const hashToken = (t: string) => createHash("sha256").update(t).digest("hex");
export const tokenMatches = (token: string, hash: string) => { const a = Buffer.from(hashToken(token)), b = Buffer.from(hash); return a.length === b.length && timingSafeEqual(a, b); };
export const validRef = (r: unknown): r is string => typeof r === "string" && /^AA-[0-9A-F]{8}$/.test(r);
export const validToken = (t: unknown): t is string => typeof t === "string" && /^[0-9a-f]{48}$/.test(t);

/** Fail-closed gate, same rules as demo requests: off until the owner approves migration 0116 and sets SUPPORT_TICKETS_ENABLED=on. */
export function ticketBlockReason(env: NodeJS.ProcessEnv): string | null {
  if ((env.SUPPORT_TICKETS_ENABLED ?? "").toLowerCase() !== "on") return "storage not enabled";
  if (envViolations(env).length) return "environment isolation check failed";
  const ref = /^https:\/\/([a-z0-9]{15,30})\.supabase\.co/i.exec(env.SUPABASE_URL ?? "")?.[1]?.toLowerCase(), prod = (env.PRODUCTION_PROJECT_REF ?? "").toLowerCase();
  if (prod && ref === prod && (env.APP_ENV ?? "").toLowerCase() !== "production") return "refusing to write to the production project from a non-production app";
  if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY) return "not configured";
  return null;
}
export interface TicketStore {
  create(t: TicketInput, ref: string, tokenHash: string, userId: string | null): Promise<void>;
  find(ref: string): Promise<(Ticket & { token_hash: string }) | null>;
  messages(ref: string): Promise<Message[]>;
  addMessage(ref: string, author: "customer", body: string): Promise<void>;
}
export function memoryStore(): TicketStore & { rows: Map<string, any> } {
  const rows = new Map<string, any>();
  return { rows,
    async create(t, ref, token_hash, user_id) { const now = new Date().toISOString(); rows.set(ref, { id: ref, ref, status: "open", subject: t.subject, category: t.category, lang: t.lang, created_at: now, updated_at: now, token_hash, user_id, email: t.email, name: t.name, msgs: [{ author: "customer", body: t.body, created_at: now }] }); },
    async find(ref) { return rows.get(ref) ?? null; },
    async messages(ref) { return rows.get(ref)?.msgs ?? []; },
    async addMessage(ref, author, body) { const r = rows.get(ref); r.msgs.push({ author, body, created_at: new Date().toISOString() }); r.status = "open"; } };
}
/** Supabase REST store (service role, server only). Tables: support_tickets, support_messages (migration 0116). */
export function supabaseStore(env: NodeJS.ProcessEnv, f: typeof fetch = fetch): TicketStore {
  const base = (env.SUPABASE_URL ?? "").replace(/\/$/, "") + "/rest/v1/", key = env.SUPABASE_SERVICE_ROLE_KEY ?? "";
  const h = { apikey: key, Authorization: "Bearer " + key, "Content-Type": "application/json" };
  const q = (s: string) => encodeURIComponent(s);
  return {
    async create(t, ref, token_hash, user_id) {
      const r = await f(base + "support_tickets?select=id", { method: "POST", headers: { ...h, Prefer: "return=representation" }, body: JSON.stringify({ ref, token_hash, user_id, name: t.name, email: t.email, subject: t.subject, category: t.category, lang: t.lang }) });
      if (!r.ok) throw new Error("create"); const id = (await r.json())?.[0]?.id; if (!id) throw new Error("create");
      const m = await f(base + "support_messages", { method: "POST", headers: { ...h, Prefer: "return=minimal" }, body: JSON.stringify({ ticket_id: id, author: "customer", body: t.body }) }); if (!m.ok) throw new Error("message");
    },
    async find(ref) { const r = await f(base + "support_tickets?ref=eq." + q(ref) + "&select=id,ref,status,subject,category,lang,created_at,updated_at,token_hash&limit=1", { headers: h }); if (!r.ok) throw new Error("find"); return (await r.json())?.[0] ?? null; },
    async messages(ref) { const t = await this.find(ref); if (!t) return []; const r = await f(base + "support_messages?ticket_id=eq." + q(t.id) + "&select=author,body,created_at&order=created_at.asc&limit=200", { headers: h }); if (!r.ok) throw new Error("messages"); return await r.json(); },
    async addMessage(ref, author, body) { const t = await this.find(ref); if (!t) throw new Error("none"); const r = await f(base + "support_messages", { method: "POST", headers: { ...h, Prefer: "return=minimal" }, body: JSON.stringify({ ticket_id: t.id, author, body }) }); if (!r.ok) throw new Error("add"); },
  };
}
