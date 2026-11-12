// Storage layer: Supabase (Postgres via REST) in production, in-memory for tests and local dev.
// In-memory data is lost on restart and is NOT shared between serverless invocations; use Supabase for real use.

export interface Query {
  where?: Record<string, string | number | boolean>;
  gte?: [string, string];
  order?: [string, "asc" | "desc"];
  limit?: number;
}
export interface Store {
  kind: "memory" | "supabase";
  /** `conflict` names the unique key columns (snake_case, comma separated) for tables whose key is not `id`, e.g. org_members. */
  upsert<T extends { id?: string }>(table: string, rows: T[], conflict?: string): Promise<void>;
  select<T>(table: string, q?: Query): Promise<T[]>;
  get<T>(table: string, id: string): Promise<T | null>;
  remove(table: string, where: Record<string, string | number | boolean>): Promise<void>;
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
    if (q.limit) rows = rows.slice(0, q.limit);
    return structuredClone(rows) as R[];
  }
  async get<R>(table: string, id: string): Promise<R | null> { const r = this.tab(table).get(id); return r ? (structuredClone(r) as R) : null; }
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
