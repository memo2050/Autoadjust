// Organization-scoped view of a Store. EVERY read and write made by a request goes through one of these, so tenant isolation does not
// depend on each query remembering a filter. The server holds the Supabase service-role key (which bypasses row level security),
// therefore this wrapper is the isolation boundary for the application tier; RLS is the second lock for direct database access.
//
//  * Tables that have an org_id column (see supabase/migrations/0105): every select/remove is filtered by org_id and every written row is stamped.
//  * Primary keys in the legacy soc_*/noc_* tables are the bare `id` (e.g. a host name hashed to an id). Two organizations could therefore
//    collide on the same id and one would overwrite the other. The wrapper namespaces the `id` COLUMN as "<orgId>:<id>" on the way in and
//    strips it on the way out, so application code is unchanged and rows can never collide across organizations. No schema change is needed.
//  * soc_meta (integration state) has no org_id column: it is isolated purely by the namespaced id.
//  * soc_kev and the "kev" meta row are public CISA reference data shared by all organizations: readable by everyone, writable by platform admins only.
import type { Query, Store } from "../soc/store";

/** Tables that carry an org_id column. */
export const ORG_TABLES = new Set([
  "soc_assets", "soc_events", "soc_alerts", "soc_incidents", "soc_vulns", "soc_scans", "soc_agent_runs", "soc_actions", "soc_audit", "soc_tasks",
  "noc_devices", "noc_sources", "noc_interfaces", "noc_metrics", "noc_events", "noc_incidents", "noc_activities", "noc_workflows", "noc_approvals",
  "noc_executions", "noc_diag_jobs", "noc_executors", "noc_actions", "noc_scopes", "noc_scans", "noc_agents", "noc_links", "noc_maps", "noc_map_versions", "noc_changes", "noc_backups",
]);
const NAMESPACED_ONLY = new Set(["soc_meta"]);
const SHARED_TABLE = "soc_kev";
const SHARED_META_IDS = new Set(["kev"]);
export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const DEFAULT_ORG_ID = "00000000-0000-0000-0000-000000000001";
export class TenantError extends Error { status = 403; }
type Where = Record<string, string | number | boolean>;

export class ScopedStore implements Store {
  readonly kind: "memory" | "supabase";
  private pfx: string;
  constructor(private inner: Store, readonly orgId: string, private opts: { platformAdmin?: boolean } = {}) {
    if (!UUID_RE.test(orgId)) throw new TenantError("Invalid organization id");
    this.kind = inner.kind;
    // The Default organization keeps bare ids: it owns every row that existed before multi-tenancy (written with bare ids). Other organizations'
    // ids always contain "<uuid>:" so they can never equal a bare id.
    this.pfx = orgId === DEFAULT_ORG_ID ? "" : orgId + ":";
  }
  private tag(id: string) { return this.pfx + id; }
  private untag(id: unknown) { return typeof id === "string" && id.startsWith(this.pfx) ? id.slice(this.pfx.length) : id; }
  private isShared(table: string, id?: unknown) { return table === SHARED_TABLE || (table === "soc_meta" && typeof id === "string" && SHARED_META_IDS.has(id)); }
  private clean<R>(table: string, r: any): R {
    if (!r || this.isShared(table, r.id)) return r;
    const { orgId: _o, ...rest } = r; // eslint-disable-line @typescript-eslint/no-unused-vars
    return { ...rest, id: this.untag(rest.id) } as R;
  }
  private known(table: string) { if (!ORG_TABLES.has(table) && !NAMESPACED_ONLY.has(table) && table !== SHARED_TABLE) throw new TenantError(`Table ${table} is not available to organization-scoped requests`); }

  async upsert<R extends { id?: string }>(table: string, rows: R[]) {
    this.known(table);
    const out = rows.map((r) => {
      if (this.isShared(table, r.id)) { if (!this.opts.platformAdmin) throw new TenantError("Shared reference data can only be updated by platform administrators"); return r; }
      const given = (r as any).orgId;
      if (given !== undefined && given !== this.orgId) throw new TenantError("Row belongs to a different organization");
      return { ...r, id: this.tag(String(r.id)), ...(ORG_TABLES.has(table) ? { orgId: this.orgId } : {}) };
    });
    await this.inner.upsert(table, out as any);
  }
  async select<R>(table: string, q: Query = {}): Promise<R[]> {
    this.known(table);
    if (table === SHARED_TABLE) return this.inner.select<R>(table, q);
    if (NAMESPACED_ONLY.has(table)) {
      if (q.where?.id === undefined) throw new TenantError("soc_meta can only be read by id");
      const rows = await this.inner.select<any>(table, { ...q, where: { ...q.where, id: SHARED_META_IDS.has(String(q.where.id)) ? String(q.where.id) : this.tag(String(q.where.id)) } });
      return rows.map((r) => this.clean<R>(table, r));
    }
    const where: Where = { ...(q.where ?? {}) };
    if (where.id !== undefined) where.id = this.tag(String(where.id));
    where.orgId = this.orgId; // always last: a caller-supplied orgId can never widen the query
    return (await this.inner.select<any>(table, { ...q, where })).map((r) => this.clean<R>(table, r));
  }
  async get<R>(table: string, id: string): Promise<R | null> { return (await this.select<R>(table, { where: { id }, limit: 1 }))[0] ?? null; }
  async remove(table: string, where: Where) {
    this.known(table);
    if (table === SHARED_TABLE) { if (!this.opts.platformAdmin) throw new TenantError("Shared reference data can only be changed by platform administrators"); return this.inner.remove(table, where); }
    const w: Where = { ...where };
    if (w.id !== undefined) w.id = this.tag(String(w.id));
    if (NAMESPACED_ONLY.has(table)) { if (w.id === undefined) throw new TenantError("soc_meta rows can only be removed by id"); return this.inner.remove(table, w); }
    w.orgId = this.orgId;
    return this.inner.remove(table, w);
  }
}
