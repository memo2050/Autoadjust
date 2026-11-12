// Authentication + organization context for the SOC/NOC API.
//  1. Browser users sign in with Supabase Auth (email + password, managed by Supabase: hashing, rate limits, email confirmation, MFA are theirs).
//     The API receives the Supabase access token (a JWT) as a Bearer token. It is verified here (HS256 with SUPABASE_JWT_SECRET, otherwise by asking
//     Supabase Auth /auth/v1/user), then membership and role are read from public.org_members FROM THE DATABASE on every request: never from the token.
//  2. Collectors (Windows/Wazuh/Zabbix bridges) use per-organization API keys (aa_live_...), stored only as SHA-256 hashes in public.org_api_keys.
//  3. Legacy shared tokens (SOC_ADMIN_TOKEN etc.) still work ONLY for the Default organization, and can be switched off with SOC_LEGACY_TOKENS=off.
import { createHmac, timingSafeEqual } from "node:crypto";
import type { Store } from "../soc/store";
import { safeEqual, sha256 } from "../soc/util";
import { UUID_RE } from "./scoped-store";

export const DEFAULT_ORG = "00000000-0000-0000-0000-000000000001";
export type OrgRole = "owner" | "it_admin" | "noc_operator" | "security_analyst" | "executive_readonly";
export type ApiRole = "admin" | "analyst" | "viewer" | "collector";
export const ORG_ROLES: OrgRole[] = ["owner", "it_admin", "noc_operator", "security_analyst", "executive_readonly"];
/** Which API role (read/write/approve/ingest set) each organization role gets. */
export const ROLE_MAP: Record<OrgRole, ApiRole> = { owner: "admin", it_admin: "admin", noc_operator: "analyst", security_analyst: "analyst", executive_readonly: "viewer" };
/** Which product area a role may WRITE in. Everyone with read access reads both. */
export const DOMAIN: Record<OrgRole, Array<"soc" | "noc">> = { owner: ["soc", "noc"], it_admin: ["soc", "noc"], noc_operator: ["noc"], security_analyst: ["soc"], executive_readonly: [] };

export interface Principal {
  kind: "user" | "apikey" | "legacy" | "dev";
  name: string;               // shown in audit records
  userId?: string; email?: string;
  orgId: string; orgName?: string;
  orgRole?: OrgRole;          // users only
  keyId?: string; keyHash?: string;   // organization API keys only: which key this request used (executor binding + job signing)
  role: ApiRole;              // what the endpoints check
  platformAdmin: boolean;     // may update shared reference data (CISA KEV)
}
export class AuthError extends Error { constructor(public status: number, message: string, public extra?: Record<string, unknown>) { super(message); } }

const b64u = (s: string) => Buffer.from(s, "base64url");
/** Verify a Supabase HS256 JWT. Returns claims or null. */
export function verifyJwtHs256(token: string, secret: string, now = Date.now()): Record<string, any> | null {
  const p = token.split("."); if (p.length !== 3) return null;
  try {
    const head = JSON.parse(b64u(p[0]).toString());
    if (head.alg !== "HS256") return null;            // never accept "none" or another algorithm
    const want = createHmac("sha256", secret).update(p[0] + "." + p[1]).digest();
    const got = b64u(p[2]); if (got.length !== want.length || !timingSafeEqual(got, want)) return null;
    const c = JSON.parse(b64u(p[1]).toString());
    if (typeof c.exp !== "number" || c.exp * 1000 <= now) return null;
    if (c.aud !== undefined && c.aud !== "authenticated") return null;
    if (c.role !== "authenticated" || typeof c.sub !== "string" || !UUID_RE.test(c.sub)) return null;   // anon/service_role keys are not users
    return c;
  } catch { return null; }
}

async function userFromToken(token: string, f: typeof fetch): Promise<{ id: string; email?: string; activeOrg?: string } | null> {
  const secret = process.env.SUPABASE_JWT_SECRET;
  if (secret) { const c = verifyJwtHs256(token, secret); return c ? { id: c.sub, email: c.email, activeOrg: c.user_metadata?.active_org } : null; }
  const url = process.env.SUPABASE_URL, key = process.env.SUPABASE_ANON_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) return null;
  const r = await f(`${url.replace(/\/$/, "")}/auth/v1/user`, { headers: { apikey: key, Authorization: `Bearer ${token}` } }).catch(() => null);
  if (!r || !r.ok) return null;
  const u: any = await r.json().catch(() => null);
  return u && typeof u.id === "string" && UUID_RE.test(u.id) ? { id: u.id, email: u.email, activeOrg: u.user_metadata?.active_org } : null;
}

/** Signed-in user without choosing an organization (used to create/list organizations and accept invitations). */
export async function identifyUser(req: Request, d: AuthDeps): Promise<{ id: string; email?: string } | null> {
  const h = req.headers.get("authorization") ?? "", tok = h.startsWith("Bearer ") ? h.slice(7).trim() : "";
  if (tok.length < 16 || tok.length > 4096 || tok.split(".").length !== 3) return null;
  return userFromToken(tok, d.fetcher ?? fetch);
}
export const apiKeyHash = (key: string) => sha256("aa-key:" + key);
export const API_KEY_RE = /^aa_live_[A-Za-z0-9_-]{32,64}$/;

export interface Memberships { orgId: string; name: string; slug: string; role: OrgRole }
export async function membershipsOf(raw: Store, userId: string): Promise<Memberships[]> {
  const ms = await raw.select<{ orgId: string; role: OrgRole }>("org_members", { where: { userId } });
  const out: Memberships[] = [];
  for (const m of ms) {
    const [o] = await raw.select<{ id: string; name: string; slug: string; disabledAt?: string | null }>("organizations", { where: { id: m.orgId }, limit: 1 });
    if (o && !o.disabledAt && ORG_ROLES.includes(m.role)) out.push({ orgId: o.id, name: o.name, slug: o.slug, role: m.role });
  }
  return out;
}

export interface AuthDeps { raw: Store; fetcher?: typeof fetch; env?: NodeJS.ProcessEnv }
export async function authenticate(req: Request, d: AuthDeps): Promise<Principal | null> {
  const env = d.env ?? process.env;
  if (env.SOC_DEV_AUTH === "true" && env.NODE_ENV !== "production") return { kind: "dev", name: "dev-user", orgId: DEFAULT_ORG, role: "admin", platformAdmin: true };
  const h = req.headers.get("authorization") ?? "";
  const tok = h.startsWith("Bearer ") ? h.slice(7).trim() : "";
  if (tok.length < 16 || tok.length > 4096) return null;

  // 1. per-organization collector key
  if (tok.startsWith("aa_live_")) {
    if (!API_KEY_RE.test(tok)) return null;
    const [k] = await d.raw.select<{ id: string; orgId: string; name: string; revokedAt?: string | null; expiresAt?: string | null }>("org_api_keys", { where: { keyHash: apiKeyHash(tok) }, limit: 1 });
    if (!k || k.revokedAt || (k.expiresAt && Date.parse(k.expiresAt) <= Date.now())) return null;
    const [o] = await d.raw.select<{ id: string; name: string; disabledAt?: string | null }>("organizations", { where: { id: k.orgId }, limit: 1 });
    if (!o || o.disabledAt) return null;
    d.raw.upsert("org_api_keys", [{ ...k, lastUsedAt: new Date().toISOString() } as any]).catch(() => {});
    return { kind: "apikey", name: `key:${k.name}`, orgId: k.orgId, orgName: o.name, role: "collector", platformAdmin: false, keyId: k.id, keyHash: apiKeyHash(tok) };
  }

  // 2. signed-in user (Supabase JWT has three dot-separated parts)
  if (tok.split(".").length === 3) {
    const u = await userFromToken(tok, d.fetcher ?? fetch);
    if (!u) return null;
    const mem = await membershipsOf(d.raw, u.id);
    if (!mem.length) throw new AuthError(403, "Your account is not a member of any organization yet. Create one or accept an invitation.", { code: "no_organization", organizations: [] });
    // The header is explicit and strict. The account page stores a PREFERENCE (user_metadata.active_org) so the unchanged web UI, which sends no header, still works for
    // people in several organizations. A preference is only honoured if the database says the user is a member; otherwise it is ignored.
    const want = req.headers.get("x-org-id");
    let m: Memberships | undefined;
    const pref = typeof u.activeOrg === "string" ? mem.find((x) => x.orgId === u.activeOrg) : undefined;
    if (want) { if (!UUID_RE.test(want)) throw new AuthError(400, "x-org-id must be an organization id"); m = mem.find((x) => x.orgId === want); if (!m) throw new AuthError(403, "You are not a member of that organization."); }
    else if (mem.length === 1) m = mem[0];
    else if (pref) m = pref;
    else throw new AuthError(409, "You belong to several organizations: send the x-org-id header to choose one.", { code: "choose_organization", organizations: mem.map((x) => ({ id: x.orgId, name: x.name, role: x.role })) });
    const platform = (env.PLATFORM_ADMIN_USER_IDS ?? "").split(",").map((s) => s.trim()).filter(Boolean).includes(u.id);
    return { kind: "user", name: u.email ?? u.id, userId: u.id, email: u.email, orgId: m.orgId, orgName: m.name, orgRole: m.role, role: ROLE_MAP[m.role], platformAdmin: platform };
  }

  // 3. legacy shared tokens: Default organization only
  if ((env.SOC_LEGACY_TOKENS ?? "on").toLowerCase() !== "off") {
    const map: [string | undefined, ApiRole][] = [[env.SOC_ADMIN_TOKEN, "admin"], [env.SOC_ANALYST_TOKEN, "analyst"], [env.SOC_VIEWER_TOKEN, "viewer"], [env.SOC_INGEST_TOKEN, "collector"]];
    for (const [secret, role] of map) if (secret && secret.length >= 16 && safeEqual(tok, secret)) return { kind: "legacy", name: `${role}-token`, orgId: DEFAULT_ORG, role, platformAdmin: role === "admin" };
  }
  return null;
}

export const PERMS: Record<ApiRole, string[]> = {
  admin: ["read", "write", "ingest", "approve", "audit"],
  analyst: ["read", "write", "audit"],
  viewer: ["read"],
  collector: ["ingest"],
};
/** Can this principal perform permission `p` in product area `area`? Users are also limited to their domain for write/approve. */
export function allowed(pr: Principal, p: string, area: "soc" | "noc" | "org"): boolean {
  if (!PERMS[pr.role].includes(p)) return false;
  if (pr.kind === "user" && pr.orgRole && (p === "write" || p === "approve") && area !== "org" && !DOMAIN[pr.orgRole].includes(area)) return false;
  return true;
}
