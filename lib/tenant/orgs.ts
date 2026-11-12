// Organization management: create organization, members, invitations, collector API keys. All writes use the server (service role) store,
// every one is authorized by the caller's role IN THAT ORGANIZATION (read from the database), and every one is written to that organization's audit chain.
import { randomBytes } from "node:crypto";
import type { Store } from "../soc/store";
import { audit, HttpError } from "../soc/pipeline";
import { nowIso, sha256 } from "../soc/util";
import { ScopedStore, UUID_RE } from "./scoped-store";
import { API_KEY_RE, apiKeyHash, membershipsOf, ORG_ROLES, type OrgRole, type Principal } from "./auth";

const SLUG_RE = /^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$/;
const MAX_ORGS_PER_USER = 5, INVITE_DAYS = 7;
const uuid = () => { const b = randomBytes(16); b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80; const h = b.toString("hex"); return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`; };
const str = (v: unknown, min: number, max: number, what: string) => { const t = typeof v === "string" ? v.trim() : ""; if (t.length < min || t.length > max) throw new HttpError(400, `${what} must be ${min}-${max} characters`); return t; };

export async function createOrganization(raw: Store, user: { id: string; email?: string }, body: any) {
  const name = str(body?.name, 2, 120, "Organization name");
  const slug = str(body?.slug ?? name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, ""), 3, 50, "Slug").toLowerCase();
  if (!SLUG_RE.test(slug)) throw new HttpError(400, "Slug may contain lowercase letters, digits and hyphens (3-50 characters, not starting or ending with a hyphen)");
  const owned = await raw.select<{ id: string }>("organizations", { where: { createdBy: user.id } });
  if (owned.length >= MAX_ORGS_PER_USER) throw new HttpError(429, "Organization limit reached for this account");
  if ((await raw.select("organizations", { where: { slug }, limit: 1 })).length) throw new HttpError(409, "That organization address is taken");
  const id = uuid();
  await raw.upsert("organizations", [{ id, name, slug, plan: "free", createdBy: user.id }]);
  try { await raw.upsert("org_members", [{ orgId: id, userId: user.id, role: "owner" } as any], "org_id,user_id"); }
  catch (e) { await raw.remove("organizations", { id }).catch(() => {}); throw e; }   // only ever removes the organization this very call created
  await audit(new ScopedStore(raw, id), { name: user.email ?? user.id, role: "owner" }, "org.create", id, { name, slug });
  return { id, name, slug, role: "owner" as OrgRole };
}

export async function myOrganizations(raw: Store, userId: string) { return (await membershipsOf(raw, userId)).map((m) => ({ id: m.orgId, name: m.name, slug: m.slug, role: m.role })); }

export async function listMembers(raw: Store, p: Principal) {
  const ms = await raw.select<{ userId: string; role: OrgRole; createdAt: string }>("org_members", { where: { orgId: p.orgId } });
  return { members: ms.map((m) => ({ userId: m.userId, role: m.role, since: m.createdAt })), you: p.userId };
}

async function ownerCount(raw: Store, orgId: string) { return (await raw.select("org_members", { where: { orgId, role: "owner" } })).length; }
// Legacy/dev admin tokens (Default organization only) count as administrators; signed-in users are judged by their organization role.
const isOwner = (p: Principal) => (p.orgRole ? p.orgRole === "owner" : p.role === "admin");
const isAdmin = (p: Principal) => (p.orgRole ? p.orgRole === "owner" || p.orgRole === "it_admin" : p.role === "admin");
const needOwner = (p: Principal) => { if (!isOwner(p)) throw new HttpError(403, "Only an owner can do this."); };
const needAdmin = (p: Principal) => { if (!isAdmin(p)) throw new HttpError(403, "Only an owner or IT administrator can do this."); };

export async function changeRole(raw: Store, p: Principal, userId: string, body: any) {
  needOwner(p);
  if (!UUID_RE.test(userId)) throw new HttpError(400, "Invalid user id");
  const role = body?.role as OrgRole; if (!ORG_ROLES.includes(role)) throw new HttpError(400, `role must be one of ${ORG_ROLES.join(", ")}`);
  const [cur] = await raw.select<{ role: OrgRole }>("org_members", { where: { orgId: p.orgId, userId }, limit: 1 });
  if (!cur) throw new HttpError(404, "Not a member of this organization");
  if (cur.role === "owner" && role !== "owner" && (await ownerCount(raw, p.orgId)) <= 1) throw new HttpError(409, "An organization must keep at least one owner");
  await raw.upsert("org_members", [{ orgId: p.orgId, userId, role } as any], "org_id,user_id");
  await audit(new ScopedStore(raw, p.orgId), { name: p.name, role: p.orgRole ?? p.role }, "org.member.role", userId, { from: cur.role, to: role });
  return { userId, role };
}

export async function removeMember(raw: Store, p: Principal, userId: string) {
  if (!UUID_RE.test(userId)) throw new HttpError(400, "Invalid user id");
  if (userId !== p.userId) needOwner(p);
  const [cur] = await raw.select<{ role: OrgRole }>("org_members", { where: { orgId: p.orgId, userId }, limit: 1 });
  if (!cur) throw new HttpError(404, "Not a member of this organization");
  if (cur.role === "owner" && (await ownerCount(raw, p.orgId)) <= 1) throw new HttpError(409, "An organization must keep at least one owner");
  await raw.remove("org_members", { orgId: p.orgId, userId });
  await audit(new ScopedStore(raw, p.orgId), { name: p.name, role: p.orgRole ?? p.role }, userId === p.userId ? "org.member.leave" : "org.member.remove", userId, { role: cur.role });
  return { removed: userId };
}

export async function invite(raw: Store, p: Principal, body: any) {
  needAdmin(p);
  const email = str(body?.email, 5, 254, "Email").toLowerCase(); if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new HttpError(400, "Enter a valid email address");
  const role = body?.role as OrgRole; if (!ORG_ROLES.includes(role) || role === "owner") throw new HttpError(400, "role must be one of it_admin, noc_operator, security_analyst, executive_readonly");
  if (p.orgRole === "it_admin" && role === "it_admin") throw new HttpError(403, "Only an owner can invite another IT administrator.");
  const token = "inv_" + randomBytes(32).toString("base64url"), id = uuid(), expiresAt = new Date(Date.now() + INVITE_DAYS * 86400_000).toISOString();
  await raw.upsert("org_invitations", [{ id, orgId: p.orgId, email, role, tokenHash: sha256(token), invitedBy: p.userId ?? null, expiresAt }]);
  await audit(new ScopedStore(raw, p.orgId), { name: p.name, role: p.orgRole ?? p.role }, "org.invite", id, { email, role });
  return { id, email, role, expiresAt, token, note: "Share this token with the invitee over a secure channel. It is shown once and cannot be recovered. Email delivery is not configured." };
}
export async function listInvites(raw: Store, p: Principal) {
  needAdmin(p);
  const rows = await raw.select<any>("org_invitations", { where: { orgId: p.orgId } });
  return { invitations: rows.map((r) => ({ id: r.id, email: r.email, role: r.role, expiresAt: r.expiresAt, acceptedAt: r.acceptedAt ?? null })) };
}
export async function revokeInvite(raw: Store, p: Principal, id: string) {
  needAdmin(p);
  const [r] = await raw.select<any>("org_invitations", { where: { id, orgId: p.orgId }, limit: 1 });
  if (!r) throw new HttpError(404, "Invitation not found");
  await raw.remove("org_invitations", { id, orgId: p.orgId });
  await audit(new ScopedStore(raw, p.orgId), { name: p.name, role: p.orgRole ?? p.role }, "org.invite.revoke", id, { email: r.email });
  return { revoked: id };
}
/** The invited person (signed in with the invited email) joins. Works for users who are not yet in any organization. */
export async function acceptInvite(raw: Store, user: { id: string; email?: string }, body: any) {
  const token = str(body?.token, 20, 200, "Invitation token");
  const [inv] = await raw.select<any>("org_invitations", { where: { tokenHash: sha256(token) }, limit: 1 });
  const bad = () => new HttpError(400, "This invitation is invalid, expired or already used.");
  if (!inv || inv.acceptedAt || Date.parse(inv.expiresAt) <= Date.now()) throw bad();
  if (!user.email || user.email.toLowerCase() !== inv.email) throw new HttpError(403, "This invitation was sent to a different email address.");
  const [o] = await raw.select<any>("organizations", { where: { id: inv.orgId }, limit: 1 });
  if (!o || o.disabledAt) throw bad();
  const [ex] = await raw.select<any>("org_members", { where: { orgId: inv.orgId, userId: user.id }, limit: 1 });
  if (!ex) await raw.upsert("org_members", [{ orgId: inv.orgId, userId: user.id, role: inv.role, invitedBy: inv.invitedBy ?? null } as any], "org_id,user_id");
  await raw.upsert("org_invitations", [{ ...inv, acceptedAt: nowIso() }]);
  await audit(new ScopedStore(raw, inv.orgId), { name: user.email, role: inv.role }, "org.invite.accept", inv.id, { userId: user.id });
  return { organization: { id: o.id, name: o.name, slug: o.slug }, role: ex?.role ?? inv.role };
}

export async function createKey(raw: Store, p: Principal, body: any) {
  needAdmin(p);
  const name = str(body?.name, 2, 60, "Key name");
  { const { requireRoom } = await import("../billing/service"); await requireRoom(raw, p.orgId, "keys", (await raw.select<{ revokedAt?: string | null }>("org_api_keys", { where: { orgId: p.orgId }, limit: 1000 })).filter((k) => !k.revokedAt).length); }
  const key = "aa_live_" + randomBytes(32).toString("base64url"); if (!API_KEY_RE.test(key)) throw new HttpError(500, "Key generation failed");
  const id = uuid();
  await raw.upsert("org_api_keys", [{ id, orgId: p.orgId, name, keyPrefix: key.slice(0, 12), keyHash: apiKeyHash(key), createdBy: p.userId ?? null }]);
  await audit(new ScopedStore(raw, p.orgId), { name: p.name, role: p.orgRole ?? p.role }, "org.key.create", id, { name });
  return { id, name, key, note: "Copy this key now. It is shown once; only a hash is stored. It can send collector data for this organization only." };
}
export async function listKeys(raw: Store, p: Principal) {
  needAdmin(p);
  const rows = await raw.select<any>("org_api_keys", { where: { orgId: p.orgId } });
  return { keys: rows.map((k) => ({ id: k.id, name: k.name, prefix: k.keyPrefix, createdAt: k.createdAt, lastUsedAt: k.lastUsedAt ?? null, revokedAt: k.revokedAt ?? null })) };
}
export async function revokeKey(raw: Store, p: Principal, id: string) {
  needAdmin(p);
  const [k] = await raw.select<any>("org_api_keys", { where: { id, orgId: p.orgId }, limit: 1 });
  if (!k) throw new HttpError(404, "Key not found");
  if (!k.revokedAt) await raw.upsert("org_api_keys", [{ ...k, revokedAt: nowIso() }]);
  await audit(new ScopedStore(raw, p.orgId), { name: p.name, role: p.orgRole ?? p.role }, "org.key.revoke", id, { name: k.name });
  return { revoked: id };
}
