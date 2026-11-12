// Controlled diagnostic execution – SERVER side. The server never runs anything and holds no host credentials: it validates a request, records it,
// and (only when a human has allowed it and the organization has switched execution on) hands a SIGNED job to the organization's own executor,
// which re-validates against its host-local policy and reports back. Read-only (tier R0) in v1.
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { Store } from "../../soc/store";
import { T as ST } from "../../soc/store";
import { HttpError, audit } from "../../soc/pipeline";
import { rid, sha256 } from "../../soc/util";
import type { Actor } from "../../soc/pipeline";
import type { Principal } from "../../tenant/auth";
import { NT, type NocIncident } from "../types";
import { NOC_TABLE, type NocDevice } from "../../soc/noc";
import { CATALOG, byId, buildArgv, forbiddenTarget, preview, validateParams, ParamError, HARD_MAX_BYTES, type Template } from "./catalog";
import { redact, redactDeep } from "./redact";

export const XT = { jobs: "noc_diag_jobs", executors: "noc_executors" } as const;
export type JobStatus = "proposed" | "rejected_by_policy" | "dry_run_done" | "awaiting_approval" | "queued" | "leased" | "succeeded" | "failed" | "timed_out" | "unsupported" | "expired" | "cancelled";
export const TERMINAL: JobStatus[] = ["rejected_by_policy", "dry_run_done", "succeeded", "failed", "timed_out", "unsupported", "expired", "cancelled"];
export interface Job {
  id: string; hostId: string; executorId?: string; os: "linux" | "windows"; template: string; tier: "R0" | "R1"; params: Record<string, string>; status: JobStatus; dryRun: boolean;
  requestedBy: string; requestedByKind: "user" | "agent"; requestedAt: string; reason?: string; incidentId?: string; evidenceIds?: string[];
  approvedBy?: string; approvedAt?: string; queuedAt?: string; expiresAt?: string; nonce: string; leaseId?: string; leasedAt?: string; leaseUntil?: string;
  startedAt?: string; endedAt?: string; exitCode?: number; timedOut?: boolean; output?: string; outputSha?: string; truncated?: boolean; error?: string; argvPreview: string; policy: string[]; note: string;
}
export interface Executor { id: string; hostId: string; keyId: string; name: string; os: "linux" | "windows"; enabled: boolean; registeredBy: string; createdAt: string; lastPollAt?: string; lastResultAt?: string }
export interface ExecCtx { store: Store; actor: Actor; orgId: string; pr?: Principal; now?: () => number; catalog?: Template[]; /** tests only: org-key lookup */ rawKeys?: Store }
const NOW = (c: ExecCtx) => (c.now ? c.now() : Date.now());
const iso = (c: ExecCtx) => new Date(NOW(c)).toISOString();
export const LIMITS = { liveJobsPerHour: 30, pendingPerHost: 5, queueTtlMs: 10 * 60_000, proposalTtlMs: 30 * 60_000, clockSkewMs: 60_000, maxResultBytes: HARD_MAX_BYTES };
const NOTE = "Raw output returned by the host. A completed command is not proof that a problem is fixed; incidents are resolved only by fresh monitoring data.";
const isAgent = (name: string) => name.startsWith("agent:");

/* ---------------- organization switch (owner only) ---------------- */
export async function getSettings(c: ExecCtx) { const r = (await c.store.get<any>(ST.meta, "exec-settings"))?.data; return { enabled: r?.enabled === true, changedBy: r?.changedBy ?? null, changedAt: r?.changedAt ?? null, tier: "R0 read-only diagnostics" }; }
export async function setSettings(c: ExecCtx, enabled: unknown) {
  if (c.pr?.orgRole !== "owner") throw new HttpError(403, "Only an organization owner can turn command execution on or off.");
  if (typeof enabled !== "boolean") throw new HttpError(400, "enabled must be true or false");
  await c.store.upsert(ST.meta, [{ id: "exec-settings", data: { enabled, changedBy: c.actor.name, changedAt: iso(c) } }]);
  await audit(c.store, c.actor, enabled ? "noc.exec.enabled" : "noc.exec.disabled", "exec-settings", {});
  return getSettings(c);
}

/* ---------------- executors (one per host, bound to one organization key) ---------------- */
export async function registerExecutor(c: ExecCtx, b: any, rawKeys: Store) {
  const hostId = String(b?.hostId ?? "").toLowerCase(); if (!/^[a-z0-9][a-z0-9._-]{0,79}$/.test(hostId)) throw new HttpError(400, "hostId must be the device id (letters, digits, . _ -)");
  const os = b?.os === "windows" ? "windows" : b?.os === "linux" ? "linux" : null; if (!os) throw new HttpError(400, "os must be linux or windows");
  const keyId = String(b?.keyId ?? ""); const [k] = await rawKeys.select<{ id: string; orgId: string; revokedAt?: string | null }>("org_api_keys", { where: { id: keyId, orgId: c.orgId }, limit: 1 });
  if (!k || k.revokedAt) throw new HttpError(404, "That API key does not exist in this organization (or is revoked).");
  { const { requireRoom } = await import("../../billing/service"); await requireRoom(rawKeys, c.orgId, "executors", (await c.store.select<Executor>(XT.executors, { where: { enabled: true }, limit: 1000 })).length); }
  const existing = (await c.store.select<Executor>(XT.executors, { where: { hostId }, limit: 5 })).find((e) => e.enabled); if (existing) throw new HttpError(409, "This host already has an enabled executor. Disable it first.");
  const e: Executor = { id: rid("nxe"), hostId, keyId, name: String(b?.name ?? hostId).slice(0, 80), os, enabled: true, registeredBy: c.actor.name, createdAt: iso(c) };
  await c.store.upsert(XT.executors, [e]); await audit(c.store, c.actor, "noc.executor.register", e.id, { hostId, os, keyId }); return e;
}
export async function setExecutorEnabled(c: ExecCtx, id: string, enabled: boolean) { const e = await c.store.get<Executor>(XT.executors, id); if (!e) throw new HttpError(404, "Executor not found"); e.enabled = enabled; await c.store.upsert(XT.executors, [e]); await audit(c.store, c.actor, enabled ? "noc.executor.enable" : "noc.executor.disable", id, { hostId: e.hostId }); return e; }
export const listExecutors = (c: ExecCtx) => c.store.select<Executor>(XT.executors, { limit: 500 });

/* ---------------- policy engine ---------------- */
async function knownTargets(c: ExecCtx): Promise<Set<string>> {
  const devs = await c.store.select<NocDevice>(NOC_TABLE, { limit: 1000 }); const s = new Set<string>();
  for (const d of devs) { s.add(d.id.toLowerCase()); s.add(d.name.toLowerCase()); if (d.ip) s.add(d.ip.toLowerCase()); }
  return s;
}
export async function evaluate(c: ExecCtx, b: any): Promise<{ t: Template; ex: Executor; params: Record<string, string>; os: "linux" | "windows"; rules: string[] }> {
  const cat = c.catalog ?? CATALOG, t = byId(String(b?.template ?? ""), cat); if (!t) throw new HttpError(400, "Unknown command template. Only catalogued diagnostics can be requested.");
  const hostId = String(b?.hostId ?? "").toLowerCase(); if (!hostId) throw new HttpError(400, "hostId is required");
  const ex = (await c.store.select<Executor>(XT.executors, { where: { hostId }, limit: 5 })).find((e) => e.enabled);
  if (!ex) throw new HttpError(404, "No enabled executor is registered for that host in this organization.");
  const rules = [`template ${t.id} is in the catalog (tier ${t.tier})`, `host ${hostId} has an enabled executor (${ex.os})`];
  let params: Record<string, string>; try { params = validateParams(t, ex.os, b?.params); } catch (e) { if (e instanceof ParamError) throw new HttpError(400, e.message); throw e; }
  rules.push("parameters match their strict patterns");
  if (!t[ex.os]) throw new HttpError(400, `${t.id} is not available on ${ex.os}`);
  for (const k of t.targetCheck ?? []) {
    const v = params[k], bad = forbiddenTarget(v); if (bad) throw new HttpError(400, `Target ${v} is not allowed (${bad}).`);
    if (!(await knownTargets(c)).has(v.toLowerCase())) throw new HttpError(400, `Target ${v} is not a registered device of this organization. Diagnostics may only point at the organization's own devices (no scanning).`);
    rules.push(`target ${v} is a registered device of this organization`);
  }
  return { t, ex, params, os: ex.os, rules };
}
async function counts(c: ExecCtx, hostId: string) {
  const all = await c.store.select<Job>(XT.jobs, { order: ["requestedAt", "desc"], limit: 1000 }), hourAgo = new Date(NOW(c) - 3600_000).toISOString();
  return { live: all.filter((j) => !j.dryRun && j.status !== "rejected_by_policy" && j.requestedAt >= hourAgo).length, pending: all.filter((j) => j.hostId === hostId && ["proposed", "awaiting_approval", "queued", "leased"].includes(j.status)).length };
}

/* ---------------- request / dry-run ---------------- */
export async function requestDiag(c: ExecCtx, b: any): Promise<Job> {
  const dry = b?.dryRun === true, agent = isAgent(c.actor.name), at = iso(c);
  let ev; try { ev = await evaluate(c, b); } catch (e) { if (e instanceof HttpError && e.status === 400) await audit(c.store, c.actor, "noc.diag.rejected_by_policy", String(b?.template ?? "?").slice(0, 60), { host: String(b?.hostId ?? "").slice(0, 80), reason: e.message }); throw e; }
  const { t, ex, params, os, rules } = ev;
  if (b?.incidentId && !(await c.store.get<NocIncident>(NT.incidents, String(b.incidentId)))) throw new HttpError(404, "Incident not found in this organization.");
  const job: Job = { id: rid("njb"), hostId: ex.hostId, executorId: ex.id, os, template: t.id, tier: t.tier, params, status: "dry_run_done", dryRun: dry, requestedBy: c.actor.name, requestedByKind: agent ? "agent" : "user", requestedAt: at,
    reason: b?.reason ? redact(String(b.reason)).slice(0, 300) : undefined, incidentId: b?.incidentId ? String(b.incidentId) : undefined, evidenceIds: Array.isArray(b?.evidenceIds) ? b.evidenceIds.map(String).slice(0, 20) : undefined,
    nonce: randomBytes(12).toString("hex"), argvPreview: preview(t, os, params), policy: rules, note: NOTE };
  if (dry) { await c.store.upsert(XT.jobs, [job]); await audit(c.store, c.actor, "noc.diag.dry_run", job.id, { template: t.id, host: ex.hostId, params }); return job; }
  if (!(await getSettings(c)).enabled) throw new HttpError(409, "Command execution is switched off for this organization. An owner must enable it (dry-run still works).");
  const n = await counts(c, ex.hostId);
  if (n.live >= LIMITS.liveJobsPerHour) throw new HttpError(429, `Limit reached: ${LIMITS.liveJobsPerHour} diagnostics per hour for this organization.`);
  if (n.pending >= LIMITS.pendingPerHost) throw new HttpError(429, `This host already has ${n.pending} pending diagnostics.`);
  if (agent) job.status = "proposed";                 // an AI agent can only PROPOSE; a human must confirm
  else if (t.tier === "R1") job.status = "awaiting_approval";
  else { job.status = "queued"; job.queuedAt = at; job.expiresAt = new Date(NOW(c) + LIMITS.queueTtlMs).toISOString(); }
  await c.store.upsert(XT.jobs, [job]);
  await audit(c.store, c.actor, "noc.diag.request", job.id, { template: t.id, host: ex.hostId, params, status: job.status, by: job.requestedByKind });
  return job;
}

/** A human confirms an AI-proposed job (R0) or approves a change-tier job (R1: requester != approver, AI never). */
export async function confirmJob(c: ExecCtx, id: string, what: "approve" | "reject", note?: string): Promise<Job> {
  const j = await getJob(c, id); if (isAgent(c.actor.name)) throw new HttpError(403, "An AI agent can never approve or confirm execution.");
  if (j.status !== "proposed" && j.status !== "awaiting_approval") throw new HttpError(409, `Job is ${j.status}; nothing to decide.`);
  if (NOW(c) - Date.parse(j.requestedAt) > LIMITS.proposalTtlMs) { j.status = "expired"; j.endedAt = iso(c); await c.store.upsert(XT.jobs, [j]); await audit(c.store, c.actor, "noc.diag.expired", id, { stage: "approval" }); throw new HttpError(409, "This request expired before it was decided."); }
  if (what === "reject") { j.status = "cancelled"; j.endedAt = iso(c); j.error = note ? redact(note).slice(0, 300) : "Rejected"; await c.store.upsert(XT.jobs, [j]); await audit(c.store, c.actor, "noc.diag.reject", id, { note: j.error }); return j; }
  if (j.tier === "R1" && j.requestedByKind === "user" && j.requestedBy === c.actor.name) throw new HttpError(403, "Two-person rule: the requester cannot approve their own change-type request.");
  if (!(await getSettings(c)).enabled) throw new HttpError(409, "Command execution is switched off for this organization.");
  const at = iso(c); j.status = "queued"; j.approvedBy = c.actor.name; j.approvedAt = at; j.queuedAt = at; j.expiresAt = new Date(NOW(c) + LIMITS.queueTtlMs).toISOString();
  await c.store.upsert(XT.jobs, [j]); await audit(c.store, c.actor, "noc.diag.approve", id, { template: j.template, host: j.hostId, requestedBy: j.requestedBy }); return j;
}
export async function cancelJob(c: ExecCtx, id: string) {
  const j = await getJob(c, id); if (!["proposed", "awaiting_approval", "queued"].includes(j.status)) throw new HttpError(409, `Job is ${j.status} and can no longer be cancelled.`);
  j.status = "cancelled"; j.endedAt = iso(c); await c.store.upsert(XT.jobs, [j]); await audit(c.store, c.actor, "noc.diag.cancel", id, {}); return j;
}
export async function getJob(c: ExecCtx, id: string) { const j = await c.store.get<Job>(XT.jobs, id); if (!j) throw new HttpError(404, "Job not found"); return j; }
export async function listJobs(c: ExecCtx, q: { status?: string; incident?: string; host?: string; limit?: number } = {}) {
  const where: Record<string, string> = {}; if (q.status) where.status = q.status; if (q.incident) where.incidentId = q.incident; if (q.host) where.hostId = q.host.toLowerCase();
  return c.store.select<Job>(XT.jobs, { where, order: ["requestedAt", "desc"], limit: Math.min(q.limit ?? 100, 500) });
}

/* ---------------- signing (key material = sha256 of the org key, known to the server as the stored hash and to the executor by hashing its own key) ---------------- */
const canonParams = (p: Record<string, string>) => Object.keys(p).sort().map((k) => `${k}=${p[k]}`).join("&");
export const jobCanonical = (j: Pick<Job, "id" | "hostId" | "template" | "params" | "expiresAt" | "nonce">, orgId: string, leaseId: string) => ["v1", j.id, orgId, j.hostId, j.template, canonParams(j.params), j.expiresAt, j.nonce, leaseId].join("|");
export const hmacHex = (keyHash: string, s: string) => createHmac("sha256", keyHash).update(s).digest("hex");
export const resultCanonical = (id: string, leaseId: string, exit: number, timedOut: boolean, outSha: string) => ["v1result", id, leaseId, exit, timedOut ? 1 : 0, outSha].join("|");
const eq = (a: string, b: string) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

/* ---------------- executor side of the API (org key with ingest role) ---------------- */
async function bound(c: ExecCtx, hostId: string): Promise<Executor> {
  if (c.pr?.kind !== "apikey" || !c.pr.keyId || !c.pr.keyHash) throw new HttpError(403, "Executors authenticate with an organization API key.");
  const ex = (await c.store.select<Executor>(XT.executors, { where: { hostId: hostId.toLowerCase() }, limit: 5 })).find((e) => e.enabled && e.keyId === c.pr!.keyId);
  if (!ex) throw new HttpError(403, "This key is not bound to an enabled executor for that host.");
  return ex;
}
export async function expireStale(c: ExecCtx) {
  const now = NOW(c);
  for (const j of await c.store.select<Job>(XT.jobs, { limit: 1000 })) {
    let why = "";
    if (j.status === "queued" && j.expiresAt && Date.parse(j.expiresAt) < now) why = "queue";
    else if (j.status === "leased" && j.leaseUntil && Date.parse(j.leaseUntil) < now) why = "lease";
    else if ((j.status === "proposed" || j.status === "awaiting_approval") && now - Date.parse(j.requestedAt) > LIMITS.proposalTtlMs) why = "approval";
    if (why) { j.status = "expired"; j.endedAt = iso(c); j.error = why === "lease" ? "The executor took the job but never reported a result." : "Expired before it ran."; await c.store.upsert(XT.jobs, [j]); await audit(c.store, { name: "system", role: "system" }, "noc.diag.expired", j.id, { stage: why }); }
  }
}
export async function pollJobs(c: ExecCtx, hostId: string) {
  const ex = await bound(c, hostId); ex.lastPollAt = iso(c); await c.store.upsert(XT.executors, [ex]);
  if (!(await getSettings(c)).enabled) return { jobs: [], executionEnabled: false };
  await expireStale(c);
  const mine = (await c.store.select<Job>(XT.jobs, { where: { hostId: ex.hostId }, limit: 200 }));
  if (mine.some((j) => j.status === "leased")) return { jobs: [], executionEnabled: true };         // one job per host at a time
  const next = mine.filter((j) => j.status === "queued" && !j.dryRun && j.expiresAt && Date.parse(j.expiresAt) > NOW(c)).sort((a, b) => (a.queuedAt! < b.queuedAt! ? -1 : 1))[0];
  if (!next) return { jobs: [], executionEnabled: true };
  const t = byId(next.template, c.catalog ?? CATALOG); if (!t) return { jobs: [], executionEnabled: true };
  const leaseId = randomBytes(12).toString("hex"); next.status = "leased"; next.leaseId = leaseId; next.leasedAt = iso(c); next.leaseUntil = new Date(NOW(c) + (t.timeoutSec * 2 + 30) * 1000).toISOString();
  await c.store.upsert(XT.jobs, [next]);
  const again = await c.store.get<Job>(XT.jobs, next.id); if (!again || again.leaseId !== leaseId) return { jobs: [], executionEnabled: true };   // lost a race with another poller: do not run it twice
  await audit(c.store, c.actor, "noc.diag.lease", next.id, { host: ex.hostId });
  return { executionEnabled: true, jobs: [{ id: next.id, orgId: c.orgId, hostId: next.hostId, template: next.template, params: next.params, expiresAt: next.expiresAt, nonce: next.nonce, leaseId, sig: hmacHex(c.pr!.keyHash!, jobCanonical(next as any, c.orgId, leaseId)) }] };
}
export async function acceptResult(c: ExecCtx, id: string, b: any) {
  const j = await getJob(c, id), ex = await bound(c, j.hostId);
  const bad = async (status: number, msg: string, why: string) => { await audit(c.store, c.actor, "noc.diag.result_rejected", id, { why }); throw new HttpError(status, msg); };
  if (j.status !== "leased") return bad(409, `Job is ${j.status}; a result is accepted once, while the job is leased.`, "not_leased_or_duplicate");
  if (typeof b?.leaseId !== "string" || b.leaseId !== j.leaseId) return bad(403, "Lease mismatch.", "lease_mismatch");
  if (!Number.isInteger(b?.exitCode) || typeof b?.output !== "string" || typeof b?.sig !== "string") return bad(400, "exitCode (integer), output (string) and sig are required.", "malformed");
  const timedOut = b.timedOut === true, outSha = sha256(b.output);
  if (!eq(hmacHex(c.pr!.keyHash!, resultCanonical(id, j.leaseId!, b.exitCode, timedOut, outSha)), b.sig)) return bad(403, "Result signature is invalid.", "bad_signature");
  const raw = b.output.slice(0, LIMITS.maxResultBytes * 2), t = byId(j.template, c.catalog ?? CATALOG);
  let out = redact(raw), truncated = raw.length < b.output.length || !!b.truncated; const cap = Math.min(t?.maxBytes ?? HARD_MAX_BYTES, HARD_MAX_BYTES), lines = out.split("\n");
  if (t && lines.length > t.maxLines) { out = lines.slice(0, t.maxLines).join("\n"); truncated = true; } if (Buffer.byteLength(out) > cap) { out = Buffer.from(out).subarray(0, cap).toString("utf8"); truncated = true; }
  j.endedAt = iso(c); j.startedAt = typeof b.startedAt === "string" ? b.startedAt.slice(0, 40) : j.leasedAt; j.exitCode = b.exitCode; j.timedOut = timedOut; j.output = out; j.outputSha = outSha; j.truncated = truncated;
  const unsupported = !timedOut && b.exitCode === 127 && /^UNSUPPORTED:/.test(out);   // the executor itself says the needed tool is missing; nothing was run
  j.status = timedOut ? "timed_out" : unsupported ? "unsupported" : b.exitCode === 0 ? "succeeded" : "failed"; if (j.status !== "succeeded") j.error = timedOut ? "The command exceeded its time limit and was stopped." : unsupported ? "Not supported on this host: a required tool is not installed. Nothing was run. This is NOT a success." : `The command exited with code ${b.exitCode}.`;
  await c.store.upsert(XT.jobs, [j]); ex.lastResultAt = j.endedAt; await c.store.upsert(XT.executors, [ex]);
  await audit(c.store, c.actor, "noc.diag.result", id, { status: j.status, exitCode: j.exitCode, bytes: out.length, truncated, requestedBy: j.requestedBy, approvedBy: j.approvedBy ?? null });
  return { ok: true, status: j.status };
}

/* ---------------- dashboard data ---------------- */
export async function execStats(c: ExecCtx) {
  await expireStale(c);
  const jobs = await c.store.select<Job>(XT.jobs, { order: ["requestedAt", "desc"], limit: 1000 }), execs = await listExecutors(c), now = NOW(c);
  const rate = (days: number) => { const since = new Date(now - days * 86400_000).toISOString(), done = jobs.filter((j) => !j.dryRun && j.endedAt && j.endedAt >= since && ["succeeded", "failed", "timed_out", "unsupported"].includes(j.status)); const ok = done.filter((j) => j.status === "succeeded").length;
    return { days, finished: done.length, succeeded: ok, failed: done.filter((j) => j.status === "failed").length, timedOut: done.filter((j) => j.status === "timed_out").length, unsupported: done.filter((j) => j.status === "unsupported").length, successRatePct: done.length ? Math.round((ok / done.length) * 1000) / 10 : null }; };
  return { settings: await getSettings(c), executors: execs.map((e) => ({ id: e.id, hostId: e.hostId, os: e.os, enabled: e.enabled, lastPollAt: e.lastPollAt ?? null, lastResultAt: e.lastResultAt ?? null, online: !!e.lastPollAt && now - Date.parse(e.lastPollAt) < 120_000 })),
    active: jobs.filter((j) => ["queued", "leased"].includes(j.status)).map(slim), pendingApprovals: jobs.filter((j) => ["proposed", "awaiting_approval"].includes(j.status)).map(slim),
    history: jobs.filter((j) => !["proposed", "awaiting_approval", "queued", "leased"].includes(j.status)).slice(0, 50).map(slim), rates: [rate(7), rate(30)], note: "Rates count finished live runs only; with no runs the rate is null (not 0% or 100%)." };
}
const slim = (j: Job) => ({ id: j.id, template: j.template, hostId: j.hostId, params: j.params, status: j.status, dryRun: j.dryRun, requestedBy: j.requestedBy, requestedByKind: j.requestedByKind, approvedBy: j.approvedBy ?? null, requestedAt: j.requestedAt, endedAt: j.endedAt ?? null, exitCode: j.exitCode ?? null, incidentId: j.incidentId ?? null, error: j.error ?? null });
export { redactDeep };
