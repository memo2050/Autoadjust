// Storage layer: Supabase (Postgres via REST) in production, in-memory for tests and local dev.
// In-memory data is lost on restart and is NOT shared between serverless invocations; use Supabase for real use.

export interface Query {
  where?: Record<string, string | number | boolean>;
  gte?: [string, string];
  order?: [string, "asc" | "desc"];
  offset?: number;
  limit?: number;
}
export interface Store {
  kind: "memory" | "supabase";
  /** `conflict` names the unique key columns (snake_case, comma separated) for tables whose key is not `id`, e.g. org_members. */
  upsert<T extends { id?: string }>(table: string, rows: T[], conflict?: string): Promise<void>;
  select<T>(table: string, q?: Query): Promise<T[]>;
  get<T>(table: string, id: string): Promise<T | null>;
  remove(table: string, where: Record<string, string | number | boolean>): Promise<void>;
  /** Count one hit for `key` in the current window and return the new count. Shared across instances on the database store. */
  hit?(key: string, windowSec?: number): Promise<number>;
  /** Rows whose id starts with `prefix` (soc_meta rows are namespaced "<orgId>:" and cannot be found by an org_id column). */
  listPrefix?(table: string, prefix: string, limit?: number): Promise<any[]>;
  /** Permanently delete everything the organization owns, in one transaction, after an approved + held deletion request. Database store: the hard_delete_org() function. */
  hardDeleteOrg?(orgId: string, requestId: string, approver: string): Promise<{ counts: Record<string, number>; finalAuditSeq?: number | null }>;
}

export const T = {
  assets: "soc_assets", events: "soc_events", alerts: "soc_alerts", incidents: "soc_incidents",
  vulns: "soc_vulns", scans: "soc_scans", runs: "soc_agent_runs", actions: "soc_actions",
  audit: "soc_audit", kev: "soc_kev", meta: "soc_meta", tasks: "soc_tasks",
} as const;

const snake = (k: string) => k.replace(/[A-Z]/g, (c) => "_" + c.toLowerCase());
const camel = (k: string) => k.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
const mapKeys = (o: Record<string, unknown>, f: (k: string) => string) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined).map(([k, v]) => [f(k), v]));

export class MemoryStore implements Store {
  kind = "memory" as const;
  private t = new Map<string, Map<string, any>>();
  private tab(n: string) { let m = this.t.get(n); if (!m) { m = new Map(); this.t.set(n, m); } return m; }
  async upsert<R extends { id?: string }>(table: string, rows: R[], conflict = "id") {
    const m = this.tab(table), cols = conflict.split(",").map((c) => camel(c.trim()));
    for (const r of rows) { m.set(cols.map((c) => String((r as any)[c])).join("|"), structuredClone(r)); }
  }
  async select<R>(table: string, q: Query = {}): Promise<R[]> {
    let rows = Array.from(this.tab(table).values());
    if (q.where) rows = rows.filter((r) => Object.entries(q.where!).every(([k, v]) => r[k] === v));
    if (q.gte) rows = rows.filter((r) => String(r[q.gte![0]] ?? "") >= q.gte![1]);
    if (q.order) { const [c, d] = q.order; rows.sort((a, b) => (a[c] < b[c] ? -1 : a[c] > b[c] ? 1 : 0) * (d === "desc" ? -1 : 1)); }
    if (q.offset) rows = rows.slice(q.offset);
    if (q.limit) rows = rows.slice(0, q.limit);
    return structuredClone(rows) as R[];
  }
  async get<R>(table: string, id: string): Promise<R | null> { const r = this.tab(table).get(id); return r ? (structuredClone(r) as R) : null; }
  async listPrefix(table: string, prefix: string, limit = 1000) { return structuredClone(Array.from(this.tab(table).values()).filter((r) => String(r.id ?? "").startsWith(prefix)).slice(0, limit)); }
  async hardDeleteOrg(orgId: string, requestId: string, approver: string) {
    const req = this.tab("org_deletion_requests").get(requestId);
    if (!req || req.orgId !== orgId || req.status !== "approved") throw new Error("No approved deletion request for this organization");
    if (Date.parse(req.holdUntil) > Date.now()) throw new Error("The 14-day hold has not ended");
    if (orgId === "00000000-0000-0000-0000-000000000001") throw new Error("The Default organization cannot be deleted");
    const org = this.tab("organizations").get(orgId); if (!org) throw new Error("Organization not found");
    const audits = Array.from(this.tab("soc_audit").values()).filter((r) => r.orgId === orgId).sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0)), last = audits[audits.length - 1];
    const counts: Record<string, number> = {};
    for (const [name, m] of this.t) { if (name === "org_tombstones" || name === "org_deletion_requests" || name === "organizations") continue; for (const [k, r] of Array.from(m)) if (r.orgId === orgId || (name === "soc_meta" && String(r.id).startsWith(orgId + ":"))) { m.delete(k); counts[name] = (counts[name] ?? 0) + 1; } }
    this.tab("organizations").delete(orgId);
    const { createHash } = await import("node:crypto");
    this.tab("org_tombstones").set(orgId, { id: orgId, orgId, nameSha256: createHash("sha256").update(String(org.name)).digest("hex"), deletedAt: new Date().toISOString(), requestId, approvedBy: approver, rowCounts: counts, finalAuditSeq: last?.seq ?? null, finalAuditHash: last?.hash ?? null });
    req.status = "completed"; req.completedAt = new Date().toISOString();
    return { counts, finalAuditSeq: last?.seq ?? null };
  }
  private hits = new Map<string, number>();
  async hit(key: string, windowSec = 60) {
    const w = Math.floor(Date.now() / 1000 / windowSec), k = key + "|" + w;
    if (this.hits.size > 5000) for (const x of this.hits.keys()) if (!x.endsWith("|" + w)) this.hits.delete(x);
    const n = (this.hits.get(k) ?? 0) + 1; this.hits.set(k, n); return n;
  }
  async remove(table: string, where: Record<string, string | number | boolean>) {
    const m = this.tab(table);
    for (const [id, r] of Array.from(m)) if (Object.entries(where).every(([k, v]) => r[k] === v)) m.delete(id);
  }
}

export class SupabaseStore implements Store {
  kind = "supabase" as const;
  constructor(private url: string, private key: string, private f: typeof fetch = fetch) {}
  private h(extra: Record<string, string> = {}) { return { apikey: this.key, Authorization: `Bearer ${this.key}`, "Content-Type": "application/json", ...extra }; }
  private qs(q: Query = {}) {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(q.where ?? {})) p.set(snake(k), `eq.${v}`);
    if (q.gte) p.set(snake(q.gte[0]), `gte.${q.gte[1]}`);
    if (q.order) p.set("order", `${snake(q.order[0])}.${q.order[1]}`);
    if (q.limit) p.set("limit", String(q.limit));
    if (q.offset) p.set("offset", String(q.offset));
    return p.toString();
  }
  private async check(r: Response) { if (!r.ok) throw new Error(`Database error ${r.status}: ${(await r.text()).slice(0, 300)}`); return r; }
  async upsert<R extends { id?: string }>(table: string, rows: R[], conflict = "id") {
    for (let i = 0; i < rows.length; i += 500) {
      const part = rows.slice(i, i + 500);
      // Rows are always full snapshots: an optional field that is now undefined must become NULL, otherwise merge-upsert keeps the old value.
      const keys = new Set<string>(); for (const r of part) for (const k of Object.keys(r)) keys.add(k);
      const chunk = part.map((r) => Object.fromEntries([...keys].map((k) => [snake(k), (r as any)[k] === undefined ? null : (r as any)[k]])));
      await this.check(await this.f(`${this.url}/rest/v1/${table}?on_conflict=${encodeURIComponent(conflict)}`, { method: "POST", headers: this.h({ Prefer: "resolution=merge-duplicates,return=minimal" }), body: JSON.stringify(chunk) }));
    }
  }
  async select<R>(table: string, q: Query = {}): Promise<R[]> {
    const r = await this.check(await this.f(`${this.url}/rest/v1/${table}?select=*&${this.qs(q)}`, { headers: this.h() }));
    return ((await r.json()) as Record<string, unknown>[]).map((x) => mapKeys(x, camel)) as R[];
  }
  async get<R>(table: string, id: string): Promise<R | null> { return (await this.select<R>(table, { where: { id }, limit: 1 }))[0] ?? null; }
  async listPrefix(table: string, prefix: string, limit = 1000) {
    if (!/^[0-9a-f-]{36}:$/i.test(prefix)) throw new Error("listPrefix is only for organization id prefixes");
    const r = await this.check(await this.f(`${this.url}/rest/v1/${table}?select=*&id=like.${encodeURIComponent(prefix)}*&limit=${limit}`, { headers: this.h() }));
    return ((await r.json()) as Record<string, unknown>[]).map((x) => mapKeys(x, camel));
  }
  async hardDeleteOrg(orgId: string, requestId: string, approver: string) {
    const r = await this.check(await this.f(`${this.url}/rest/v1/rpc/hard_delete_org`, { method: "POST", headers: this.h(), body: JSON.stringify({ p_org: orgId, p_request: requestId, p_approver: approver }) }));
    const j: any = await r.json(); return { counts: j?.counts ?? {}, finalAuditSeq: j?.final_audit_seq ?? null };
  }
  async hit(key: string, windowSec = 60) {
    const r = await this.check(await this.f(`${this.url}/rest/v1/rpc/rate_limit_hit`, { method: "POST", headers: this.h(), body: JSON.stringify({ p_key: key, p_window: windowSec }) }));
    const n = Number(await r.json()); if (!Number.isFinite(n)) throw new Error("rate limiter returned no count"); return n;
  }
  async remove(table: string, where: Record<string, string | number | boolean>) {
    await this.check(await this.f(`${this.url}/rest/v1/${table}?${this.qs({ where })}`, { method: "DELETE", headers: this.h() }));
  }
}

let singleton: Store | null = null;
export function getStore(): Store {
  if (singleton) return singleton;
  const url = process.env.SUPABASE_URL, key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  singleton = url && key ? new SupabaseStore(url.replace(/\/$/, ""), key) : new MemoryStore();
  return singleton;
}
export function setStore(s: Store | null) { singleton = s; }
