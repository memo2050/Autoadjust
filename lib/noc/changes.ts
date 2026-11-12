// Controlled configuration changes. Nothing is "applied" unless the executor reports success AND the running config afterwards contains the proposal.
import { HttpError, audit } from "../soc/pipeline";
import { NOC_TABLE, type NocDevice } from "../soc/noc";
import { rid, sha256 } from "../soc/util";
import { cryptoConfigured, decryptJson, encryptJson } from "./crypto";
import { NT } from "./types";
import type { Ctx } from "./ops";

// Everything after a secret-bearing keyword is replaced, so the value can never survive (e.g. "snmp-server community public RO" -> "snmp-server community <redacted>").
const SECRET = /^(\s*(?!description\b|remark\b)[^\n]*?\b(?:password|passwd|secret|community|pre-shared-key|psk|key-string|authentication-key|auth|priv|token|api-key|key)\b\s+)(\S[^\n]*)$/i;
export const redact = (t: string) => t.split("\n").map((l) => l.replace(SECRET, "$1<redacted>")).join("\n");
const norm = (t: string) => t.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("!") && !l.startsWith("#"));
export function lineDiff(a: string, b: string) {
  const A = norm(a), B = norm(b), sa = new Set(A), sb = new Set(B);
  return { removed: A.filter((l) => !sb.has(l)), added: B.filter((l) => !sa.has(l)), unchanged: A.filter((l) => sb.has(l)).length };
}
export interface Change { id: string; deviceId: string; deviceName: string; title: string; description: string; proposed: string; proposedRaw?: string; baseline?: string; diff: ReturnType<typeof lineDiff>; risk: "medium" | "high"; status: "proposed" | "rejected" | "queued" | "running" | "applied" | "unverified" | "failed" | "rollback_proposed"; rollbackOf?: string; backupId?: string; requestedBy: string; decidedBy?: string; decidedAt?: string; note?: string; result?: { ok: boolean; error?: string; verified?: boolean; detail: string; at: string }; createdAt: string; updatedAt: string }
export interface Backup { id: string; deviceId: string; at: string; by: string; config: string; raw?: string; sha: string; changeId?: string }

export async function addBackup(c: Ctx, deviceId: string, config: string, changeId?: string) {
  if (!config || config.length > 200_000) throw new HttpError(400, "config must be 1 to 200000 characters");
  const raw = cryptoConfigured() ? encryptJson({ c: config }) : undefined, b: Backup = { id: rid("bak"), deviceId, at: new Date().toISOString(), by: c.actor.name, config: redact(config), raw, sha: sha256(config), changeId };
  await c.store.upsert(NT.backups, [b]); await audit(c.store, c.actor, "noc.backup.add", b.id, { deviceId, bytes: config.length, rawStored: !!raw }); return { id: b.id, at: b.at, sha: b.sha, redacted: b.config !== config, rawStored: !!raw };
}
export async function listBackups(c: Ctx, deviceId: string) { return (await c.store.select<Backup>(NT.backups, { where: { deviceId }, order: ["at", "desc"], limit: 20 })).map(({ raw: _r, ...x }) => x); }
async function latestBackup(c: Ctx, deviceId: string) { return (await c.store.select<Backup>(NT.backups, { where: { deviceId }, order: ["at", "desc"], limit: 1 }))[0]; }
export async function proposeChange(c: Ctx, b: any) {
  const d = await c.store.get<NocDevice>(NOC_TABLE, String(b?.deviceId ?? "")); if (!d) throw new HttpError(404, "Device not found");
  const proposed = String(b?.proposed ?? ""); if (!proposed.trim() || proposed.length > 100_000) throw new HttpError(400, "proposed configuration is required (max 100000 characters)");
  const title = String(b?.title ?? "").trim().slice(0, 100); if (!title) throw new HttpError(400, "title is required");
  const base = await latestBackup(c, d.id), t = new Date().toISOString(), raw = cryptoConfigured() ? encryptJson({ c: proposed }) : undefined, baseline = base?.config;
  const ch: Change = { id: rid("chg"), deviceId: d.id, deviceName: d.name, title, description: String(b?.description ?? "").slice(0, 500), proposed: redact(proposed), proposedRaw: raw, baseline, diff: lineDiff(baseline ?? "", redact(proposed)), risk: "high", status: "proposed", requestedBy: c.actor.name, createdAt: t, updatedAt: t };
  await c.store.upsert(NT.changes, [ch]); await audit(c.store, c.actor, "noc.change.propose", ch.id, { device: d.name, title, comparedAgainst: base ? base.id : "none (no backup yet)" });
  return pub(ch, !base ? "No backup exists for this device, so the comparison shows every proposed line as added. Take a backup first for a real comparison." : undefined);
}
const pub = (ch: Change, warning?: string) => { const { proposedRaw: _r, ...x } = ch; return { ...x, warning }; };
export async function listChanges(c: Ctx) { return (await c.store.select<Change>(NT.changes, { order: ["createdAt", "desc"], limit: 100 })).map((x) => pub(x)); }
export async function decideChange(c: Ctx, id: string, what: "approve" | "reject", b: any) {
  const ch = await c.store.get<Change>(NT.changes, id); if (!ch) throw new HttpError(404, "Change not found"); if (ch.status !== "proposed" && ch.status !== "rollback_proposed") throw new HttpError(409, `Already ${ch.status}`);
  if (c.actor.name.startsWith("agent:")) throw new HttpError(403, "An AI agent cannot decide a change.");
  ch.decidedBy = c.actor.name; ch.decidedAt = new Date().toISOString(); ch.updatedAt = ch.decidedAt; ch.note = b?.note ? String(b.note).slice(0, 300) : undefined;
  if (what === "reject") { ch.status = "rejected"; await c.store.upsert(NT.changes, [ch]); await audit(c.store, c.actor, "noc.change.reject", id, {}); return pub(ch); }
  if (String(b?.confirm ?? "") !== ch.deviceName) throw new HttpError(400, `Type the device name exactly ("${ch.deviceName}") to confirm you are changing that device.`);
  if (!ch.proposedRaw) throw new HttpError(400, "The backend has no NOC_SECRET_KEY, so it cannot hold the configuration for an executor. Set it first.");
  ch.status = "queued"; await c.store.upsert(NT.changes, [ch]); await audit(c.store, c.actor, "noc.change.approve", id, { device: ch.deviceName }); return pub(ch);
}
/** Executor (an agent inside the network) claims approved changes. Gets the raw config over the authenticated channel. */
export async function claimChanges(c: Ctx) {
  const q = await c.store.select<Change>(NT.changes, { where: { status: "queued" }, limit: 5 }), out = [];
  for (const ch of q) { const d = await c.store.get<NocDevice>(NOC_TABLE, ch.deviceId); ch.status = "running"; ch.updatedAt = new Date().toISOString(); await c.store.upsert(NT.changes, [ch]); out.push({ id: ch.id, device: { id: ch.deviceId, name: ch.deviceName, ip: d?.ip, type: d?.type }, proposed: ch.proposedRaw ? decryptJson(ch.proposedRaw).c : "", steps: ["backup", "apply", "readback"] }); }
  return { changes: out };
}
export async function executorBackup(c: Ctx, id: string, b: any) { const ch = await c.store.get<Change>(NT.changes, id); if (!ch || ch.status !== "running") throw new HttpError(409, "Change is not running"); const r = await addBackup(c, ch.deviceId, String(b?.config ?? ""), id); ch.backupId = r.id; await c.store.upsert(NT.changes, [ch]); return r; }
export async function executorResult(c: Ctx, id: string, b: any) {
  const ch = await c.store.get<Change>(NT.changes, id); if (!ch) throw new HttpError(404, "Change not found"); if (ch.status !== "running") throw new HttpError(409, `Change is ${ch.status}`);
  const t = new Date().toISOString(); ch.updatedAt = t;
  if (b?.ok !== true) { ch.status = "failed"; ch.result = { ok: false, error: String(b?.error ?? "Executor reported failure").slice(0, 400), detail: "The executor reported the change did not apply. The device should be unchanged; check it.", at: t }; }
  else if (typeof b?.runningConfig !== "string" || !b.runningConfig.trim()) { ch.status = "unverified"; ch.result = { ok: true, verified: false, detail: "The executor says it applied the change but sent no running configuration, so Spark cannot confirm it. Treat as UNVERIFIED.", at: t }; }
  else { const raw = ch.proposedRaw ? decryptJson(ch.proposedRaw).c : "", have = new Set(norm(b.runningConfig)), missing = norm(raw).filter((l) => !have.has(l)); ch.result = missing.length ? { ok: true, verified: false, detail: `${missing.length} proposed line(s) are not in the running configuration after the change.`, at: t } : { ok: true, verified: true, detail: "Every proposed line was found in the running configuration read back after the change.", at: t }; ch.status = missing.length ? "unverified" : "applied"; if (!missing.length || true) await addBackup(c, ch.deviceId, b.runningConfig, id); }
  await c.store.upsert(NT.changes, [ch]); await audit(c.store, c.actor, "noc.change." + ch.status, id, { device: ch.deviceName }); return pub(ch);
}
export async function proposeRollback(c: Ctx, id: string) {
  const ch = await c.store.get<Change>(NT.changes, id); if (!ch) throw new HttpError(404, "Change not found"); if (!ch.backupId) throw new HttpError(409, "No pre-change backup was recorded for this change, so a rollback is not possible.");
  const bk = await c.store.get<Backup>(NT.backups, ch.backupId); if (!bk?.raw) throw new HttpError(409, "The backup has no stored raw copy (needs NOC_SECRET_KEY when it was taken).");
  const t = new Date().toISOString(), cfg = decryptJson(bk.raw).c as string, rb: Change = { id: rid("chg"), deviceId: ch.deviceId, deviceName: ch.deviceName, title: "Rollback: " + ch.title, description: `Restore the configuration saved before ${ch.id}.`, proposed: redact(cfg), proposedRaw: bk.raw.replace(/^/, ""), diff: lineDiff(ch.proposed, redact(cfg)), risk: "high", status: "rollback_proposed", rollbackOf: id, requestedBy: c.actor.name, createdAt: t, updatedAt: t };
  rb.proposedRaw = encryptJson({ c: cfg }); await c.store.upsert(NT.changes, [rb]); await audit(c.store, c.actor, "noc.change.rollback_propose", rb.id, { of: id }); return pub(rb);
}
