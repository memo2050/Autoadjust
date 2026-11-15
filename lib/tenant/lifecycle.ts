// T9: customer data export and deletion.
//  * Export: owner-only ZIP of everything the organization owns (secrets redacted), via a short-lived signed, single-use link.
//  * Deletion: owner requests -> 14-day hold (cancellable) -> a DIFFERENT platform admin (with MFA) approves -> one-transaction hard delete + tombstone.
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { deflateRawSync } from "node:zlib";
import type { Store } from "../soc/store";
import { HttpError, audit } from "../soc/pipeline";
import type { Principal } from "./auth";
import { DEFAULT_ORG_ID, ScopedStore } from "./scoped-store";
type Actor = { name: string; role: string };
const aud = (raw: Store, orgId: string, actor: Actor, action: string, target: string, detail: Record<string, unknown>) => audit(new ScopedStore(raw, orgId), actor, action, target, detail);

/** Every table that has an org_id column (kept in step with the database by tests/data-lifecycle.test.ts and docs/DATA_LIFECYCLE.md). soc_meta rows are found by id prefix. */
export const OWNED_TABLES = [
  "agent_enrollment_tokens", "approvals", "assessment_reports", "assessments", "audit_log", "billing_events", "billing_invoices", "billing_payments",
  "net_device_interfaces", "net_device_services", "net_devices", "net_links", "net_segments", "network_agents",
  "noc_actions", "noc_activities", "noc_agents", "noc_approvals", "noc_backups", "noc_changes", "noc_devices", "noc_diag_jobs", "noc_events", "noc_executions", "noc_executors",
  "noc_incidents", "noc_interfaces", "noc_links", "noc_map_versions", "noc_maps", "noc_metrics", "noc_scans", "noc_scopes", "noc_sources", "noc_workflows",
  "org_api_keys", "org_billing", "org_invitations", "org_members", "scan_jobs", "scan_results", "scan_schedules", "scan_scopes",
  "soc_actions", "soc_agent_runs", "soc_alerts", "soc_assets", "soc_audit", "soc_events", "soc_incidents", "soc_scans", "soc_tasks", "soc_vulns",
  "topology_changes", "topology_snapshots", "vulnerability_findings",
] as const;
/** Tables that exist in the database but hold no per-organization customer data (reference/config/system/legacy website-builder data). A new table must be added to one list or the other: the test enforces it. */
export const NOT_ORG_DATA = ["organizations", "billing_plans", "billing_settings", "rate_limits", "org_deletion_requests", "org_tombstones", "soc_kev", "soc_meta", "app_records", "projects", "sites", "usage", "versions"] as const;
const ORDER_COL: Record<string, string> = { org_members: "userId", org_billing: "orgId" };
const SECRET_KEY = /^(secret|keyhash|tokenhash|password|enc|apikey|credentials?|privatekey)$/i;
const PAGE = 1000, MAX_ROWS_PER_TABLE = 100_000, MAX_ZIP_BYTES = 50 * 1024 * 1024, DAY = 86400000, HOLD_DAYS = 14, LINK_MINUTES = 10;

const redact = (v: unknown, found: Set<string>): unknown => {
  if (Array.isArray(v)) return v.map((x) => redact(x, found));
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => { if (SECRET_KEY.test(k)) { found.add(k); return [k, "[redacted]"]; } return [k, redact(x, found)]; }));
  return v;
};

// ---- minimal ZIP writer (deflate) -----------------------------------------------------------------------------------------------------------------------
const CRC = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
const crc32 = (b: Buffer) => { let c = 0xffffffff; for (let i = 0; i < b.length; i++) c = CRC[(c ^ b[i]) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
export function zip(files: { name: string; data: Buffer }[], when = new Date()): Buffer {
  const dt = ((when.getUTCFullYear() - 1980) << 9 | (when.getUTCMonth() + 1) << 5 | when.getUTCDate()) & 0xffff, tm = (when.getUTCHours() << 11 | when.getUTCMinutes() << 5 | (when.getUTCSeconds() >> 1)) & 0xffff;
  const parts: Buffer[] = [], central: Buffer[] = []; let off = 0;
  for (const f of files) {
    const name = Buffer.from(f.name), comp = deflateRawSync(f.data), crc = crc32(f.data), h = Buffer.alloc(30);
    h.writeUInt32LE(0x04034b50, 0); h.writeUInt16LE(20, 4); h.writeUInt16LE(0x0800, 6); h.writeUInt16LE(8, 8); h.writeUInt16LE(tm, 10); h.writeUInt16LE(dt, 12); h.writeUInt32LE(crc, 14); h.writeUInt32LE(comp.length, 18); h.writeUInt32LE(f.data.length, 22); h.writeUInt16LE(name.length, 26);
    parts.push(h, name, comp);
    const c = Buffer.alloc(46); c.writeUInt32LE(0x02014b50, 0); c.writeUInt16LE(20, 4); c.writeUInt16LE(20, 6); c.writeUInt16LE(0x0800, 8); c.writeUInt16LE(8, 10); c.writeUInt16LE(tm, 12); c.writeUInt16LE(dt, 14); c.writeUInt32LE(crc, 16); c.writeUInt32LE(comp.length, 20); c.writeUInt32LE(f.data.length, 24); c.writeUInt16LE(name.length, 28); c.writeUInt32LE(off, 42);
    central.push(c, name); off += 30 + name.length + comp.length;
  }
  const cd = Buffer.concat(central), end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat([...parts, cd, end]);
}

// ---- export ---------------------------------------------------------------------------------------------------------------------------------------------
async function readAll(raw: Store, table: string, orgId: string): Promise<{ rows: any[]; truncated: boolean }> {
  const rows: any[] = [], order = ORDER_COL[table] ?? "id";
  for (let off = 0; off < MAX_ROWS_PER_TABLE; off += PAGE) {
    let page: any[]; try { page = await raw.select<any>(table, { where: { orgId }, order: [order, "asc"], limit: PAGE, offset: off }); } catch (e) { if (/does not exist|42P01|PGRST205/.test(String((e as Error).message))) return { rows: [], truncated: false }; throw e; }
    rows.push(...page); if (page.length < PAGE) return { rows, truncated: false };
  }
  return { rows, truncated: true };
}
export async function buildExport(raw: Store, orgId: string, by: string, now = new Date()) {
  const redacted = new Set<string>(), files: { name: string; data: Buffer }[] = [], tables: Record<string, { rows: number; sha256: string; truncated?: boolean }> = {}, pfx = orgId === DEFAULT_ORG_ID ? "" : orgId + ":";
  const put = (name: string, v: unknown) => { const data = Buffer.from(JSON.stringify(redact(v, redacted), null, 1)); files.push({ name, data }); return createHash("sha256").update(data).digest("hex"); };
  const [org] = await raw.select<any>("organizations", { where: { id: orgId }, limit: 1 }); put("organization.json", org ?? { id: orgId });
  for (const t of OWNED_TABLES) {
    const { rows, truncated } = await readAll(raw, t, orgId); if (!rows.length) continue;
    const clean = rows.map((r) => { const { orgId: _o, ...rest } = r; return pfx && typeof rest.id === "string" && rest.id.startsWith(pfx) ? { ...rest, id: rest.id.slice(pfx.length) } : rest; });   // eslint-disable-line @typescript-eslint/no-unused-vars
    tables[t] = { rows: clean.length, sha256: put(`data/${t}.json`, clean), ...(truncated ? { truncated: true } : {}) };
  }
  if (raw.listPrefix) { const meta = (await raw.listPrefix("soc_meta", orgId + ":", 1000)).map((r) => ({ ...r, id: String(r.id).slice(orgId.length + 1) })); if (meta.length) tables.soc_meta = { rows: meta.length, sha256: put("data/soc_meta.json", meta) }; }
  const manifest = { format: "autoadjust-org-export/1", organizationId: orgId, createdAt: now.toISOString(), requestedBy: by, tables, redactedFields: [...redacted].sort(), notes: ["Credentials, key hashes and invitation token hashes are never exported.", "User sign-in accounts belong to the person, not the organization, and are not included.", "Tables not listed hold no rows for this organization."] };
  files.unshift({ name: "manifest.json", data: Buffer.from(JSON.stringify(manifest, null, 1)) });
  const out = zip(files, now); if (out.length > MAX_ZIP_BYTES) throw new HttpError(413, "This organization's export is larger than the on-demand limit. Contact support for a large-export job.");
  return { zip: out, manifest };
}

// ---- signed single-use download links ----------------------------------------------------------------------------------------------------------------------
const secretOf = (env: Record<string, string | undefined>) => env.EXPORT_SIGNING_SECRET || env.NOC_SECRET_KEY || "";
const sign = (secret: string, body: string) => createHmac("sha256", secret).update("aa-export:" + body).digest("base64url");
export function exportLink(env: Record<string, string | undefined>, orgId: string, userId: string, now = Date.now()) {
  const secret = secretOf(env); if (secret.length < 32) throw new HttpError(501, "Data export is not configured on this server (EXPORT_SIGNING_SECRET).");
  const exp = now + LINK_MINUTES * 60000, body = [exp, orgId, userId, randomBytes(9).toString("base64url")].join(".");
  return { token: body + "." + sign(secret, body), expiresAt: new Date(exp).toISOString() };
}
export function verifyExportLink(env: Record<string, string | undefined>, token: string, now = Date.now()) {
  const secret = secretOf(env), p = String(token ?? "").split("."); if (secret.length < 32 || p.length !== 5) return null;
  const body = p.slice(0, 4).join("."), want = Buffer.from(sign(secret, body)), got = Buffer.from(p[4]); if (want.length !== got.length || !timingSafeEqual(want, got)) return null;
  const [exp, orgId, userId, nonce] = p; if (!(Number(exp) > now)) return null; return { orgId, userId, nonce };
}
export async function requestExport(raw: Store, pr: Principal, env: Record<string, string | undefined>) {
  if (pr.kind !== "user" || pr.orgRole !== "owner") throw new HttpError(403, "Only an organization owner can export the organization's data.");
  const l = exportLink(env, pr.orgId, pr.userId!); await aud(raw, pr.orgId, { name: pr.name, role: "owner" }, "org.export_requested", pr.orgId, {}).catch(() => {});
  return { downloadUrl: "/api/soc/org/export/download?t=" + encodeURIComponent(l.token), expiresAt: l.expiresAt, singleUse: true };
}
export async function downloadExport(raw: Store, env: Record<string, string | undefined>, token: string) {
  const t = verifyExportLink(env, token); if (!t) throw new HttpError(403, "This download link is invalid or has expired. Request a new export.");
  const [m] = await raw.select<any>("org_members", { where: { orgId: t.orgId, userId: t.userId }, limit: 1 }); if (!m || m.role !== "owner") throw new HttpError(403, "Only an organization owner can download this export.");
  const used = `${t.orgId}:export-${t.nonce}`; if (await raw.get("soc_meta", used)) throw new HttpError(410, "This download link was already used. Request a new export.");
  await raw.upsert("soc_meta", [{ id: used, data: { usedAt: new Date().toISOString() } } as any]);
  const out = await buildExport(raw, t.orgId, t.userId);
  await aud(raw, t.orgId, { name: t.userId, role: "owner" }, "org.export_downloaded", t.orgId, { bytes: out.zip.length, tables: Object.keys(out.manifest.tables).length }).catch(() => {});
  return out;
}

// ---- deletion -------------------------------------------------------------------------------------------------------------------------------------------
export interface DeletionRequest { id: string; orgId: string; requestedBy?: string; requestedByEmail?: string; requestedAt: string; holdUntil: string; status: "requested" | "cancelled" | "approved" | "completed" | "failed"; approvedBy?: string; approvedAt?: string; completedAt?: string; cancelledAt?: string; error?: string }
const TD = "org_deletion_requests", uuid = () => ([1e7, 1e3, 4e3, 8e3, 1e11] as any as string).toString().replace(/[018]/g, (c: any) => (c ^ (randomBytes(1)[0] & (15 >> (c / 4)))).toString(16));
export const activeRequest = async (raw: Store, orgId: string) => (await raw.select<DeletionRequest>(TD, { where: { orgId } })).find((r) => r.status === "requested" || r.status === "approved") ?? null;
export async function deletionStatus(raw: Store, orgId: string) { const all = await raw.select<DeletionRequest>(TD, { where: { orgId } }).catch(() => []); const cur = all.find((r) => r.status === "requested" || r.status === "approved") ?? null; return { request: cur, holdDays: HOLD_DAYS }; }
export async function requestDeletion(raw: Store, pr: Principal, body: any, now = Date.now()) {
  if (pr.kind !== "user" || pr.orgRole !== "owner") throw new HttpError(403, "Only an organization owner can request deletion of the organization.");
  if (pr.orgId === DEFAULT_ORG_ID) throw new HttpError(403, "The Default organization cannot be deleted.");
  if (String(body?.confirm ?? "").trim() !== String(pr.orgName ?? "")) throw new HttpError(400, "Type the organization name exactly to confirm.", { code: "confirm_mismatch" });
  if (await activeRequest(raw, pr.orgId)) throw new HttpError(409, "A deletion request is already open for this organization.");
  const r: DeletionRequest = { id: uuid(), orgId: pr.orgId, requestedBy: pr.userId, requestedByEmail: pr.email, requestedAt: new Date(now).toISOString(), holdUntil: new Date(now + HOLD_DAYS * DAY).toISOString(), status: "requested" };
  await raw.upsert(TD, [r as any]); await aud(raw, pr.orgId, { name: pr.name, role: "owner" }, "org.deletion_requested", pr.orgId, { requestId: r.id, holdUntil: r.holdUntil }).catch(() => {});
  return { request: r, message: `Deletion is scheduled for review after ${HOLD_DAYS} days. Nothing is deleted before then; you can cancel any time. Export your data now if you need a copy.` };
}
export async function cancelDeletion(raw: Store, pr: Principal, now = Date.now()) {
  if (pr.kind !== "user" || pr.orgRole !== "owner") throw new HttpError(403, "Only an organization owner can cancel a deletion request.");
  const r = await activeRequest(raw, pr.orgId); if (!r || r.status !== "requested") throw new HttpError(409, "There is no open deletion request that can be cancelled.");
  await raw.upsert(TD, [{ ...r, status: "cancelled", cancelledAt: new Date(now).toISOString() } as any]); await aud(raw, pr.orgId, { name: pr.name, role: "owner" }, "org.deletion_cancelled", pr.orgId, { requestId: r.id }).catch(() => {});
  return { cancelled: true };
}
export const listDeletions = async (raw: Store) => (await raw.select<DeletionRequest>(TD, { order: ["requestedAt", "desc"], limit: 200 })).map((r) => ({ ...r }));
export async function approveDeletion(raw: Store, pr: Principal, id: string, now = Date.now()) {
  if (pr.kind !== "user" || !pr.platformAdmin) throw new HttpError(403, "Only a platform administrator can approve a deletion.");
  const r = await raw.get<DeletionRequest>(TD, id); if (!r) throw new HttpError(404, "Deletion request not found.");
  if (r.status !== "requested" && r.status !== "failed") throw new HttpError(409, `This request is ${r.status}.`);
  if (r.requestedBy && r.requestedBy === pr.userId) throw new HttpError(403, "A deletion must be approved by someone other than the person who requested it.");
  if (Date.parse(r.holdUntil) > now) throw new HttpError(409, `The ${HOLD_DAYS}-day hold ends ${r.holdUntil}.`, { code: "hold_active" });
  const [b] = await raw.select<any>("org_billing", { where: { orgId: r.orgId }, limit: 1 }).catch(() => []);
  if (b?.subscriptionId && ["active", "trialing", "past_due", "unpaid"].includes(String(b.status))) throw new HttpError(409, "The organization still has a live subscription. Cancel it in billing first so the customer is not charged after deletion.", { code: "subscription_active" });
  if (!raw.hardDeleteOrg) throw new HttpError(501, "This data store cannot perform a hard delete.");
  const approver = pr.email ?? pr.userId ?? pr.name;
  await raw.upsert(TD, [{ ...r, status: "approved", approvedBy: approver, approvedAt: new Date(now).toISOString() } as any]);
  await aud(raw, r.orgId, { name: pr.name, role: "platform_admin" }, "org.deletion_approved", r.orgId, { requestId: r.id }).catch(() => {});
  try { const res = await raw.hardDeleteOrg(r.orgId, r.id, approver); return { deleted: true, organizationId: r.orgId, rowsDeleted: Object.values(res.counts).reduce((a, b2) => a + Number(b2), 0), counts: res.counts }; }
  catch (e) { await raw.upsert(TD, [{ ...r, status: "failed", approvedBy: approver, error: String((e as Error).message).slice(0, 300) } as any]); throw new HttpError(500, "The deletion failed and nothing was removed (it runs in a single transaction). See the request for the reason."); }
}
