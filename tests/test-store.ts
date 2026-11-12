import { __setResolverForTests } from "../lib/tenant/ssrf";
import { MemoryStore } from "../lib/soc/store";
import { ORG_TABLES, DEFAULT_ORG_ID } from "../lib/tenant/scoped-store";
/** In-memory store that behaves like the database: rows written without an org_id get the column default (the Default organization, migration 0105). */
export class TestStore extends MemoryStore {
  async upsert<R extends { id?: string }>(table: string, rows: R[], conflict?: string) {
    return super.upsert(table, ORG_TABLES.has(table) ? rows.map((r) => ((r as any).orgId === undefined ? { ...r, orgId: DEFAULT_ORG_ID } : r)) : rows, conflict);
  }
}

// Existing NOC tests use made-up host names (zabbix.lan ...): resolve them to a public address and allow http for the fixture servers.
__setResolverForTests(async () => ["93.184.216.34"]); process.env.NOC_ALLOW_HTTP = "1"; process.env.WAZUH_ALLOW_HTTP = "1";
