import * as BILL from "../billing/service";
import { pruneMetrics as prune } from "../noc/limits";
import { getStore, T, type Store } from "./store";
import type { Alert, Asset, AuditEntry, DataSource, Incident, IncidentStatus, ScanImport, SocAction, SocEvent, Role, TimelineEntry, Vuln, AgentRun } from "./types";
import { AGENT_IDS, sevRank } from "./types";
import type { AgentId } from "./types";
import { huntEvents, validateManualAction } from "./roles";
import { decideAction, runAnalyst, defaultModel, type AnalystTask, type ModelFn } from "./agents";
import { audit, HttpError, importKev, importScan, ingestWindows, setIncidentStatus, verifyAuditChain, verifyIncident, type Actor } from "./pipeline";
import { displayStatus, enrichActions } from "./approvals";
import { RULES_META } from "./rules";
import { assetRisk } from "./risk";
import { hid, ms, nowIso, safeEqual } from "./util";
import { ingestTelemetry, listDevices, NOC_TABLE, type NocDevice } from "./noc";
import * as N from "../noc/ops";
import { overview as nocOverview, pushSnapshot, runAgent as nocRun } from "../noc/agents";
import * as TP from "../noc/topo";
import * as RT from "../noc/realtime";
import * as XJ from "../noc/exec/jobs";
import { analyzeSoc } from "./ai-analyst";
import { analyzeNoc } from "../noc/ai-analyst";
import { CATALOG, preview as xPreview } from "../noc/exec/catalog";
import * as WZ from "./wazuh";
import * as WC from "./wazuh-config";
import * as CH from "../noc/changes";
import { authenticate, allowed, AuthError, identifyUser } from "../tenant/auth";
import { ScopedStore, TenantError } from "../tenant/scoped-store";
import * as ORG from "../tenant/orgs";
import { advanceTask, cancelTask, createTask, publicTask, retryTask, type TaskRun } from "./tasks";

// ---------- Auth: see lib/tenant/auth.ts (Supabase sign-in, per-organization collector keys, legacy tokens for the Default organization only) ----------
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
const MAX_BODY = 8_000_000, MAX_EVENTS = 5000;

async function readJson(req: Request): Promise<any> {
  const t = await req.text();
  if (t.length > MAX_BODY) throw new HttpError(413, "Request too large");
  try { return t ? JSON.parse(t) : {}; } catch { throw new HttpError(400, "Body must be valid JSON"); }
}
const lim = (u: URL, d = 200, max = 1000) => Math.max(1, Math.min(max, Number(u.searchParams.get("limit")) || d));
const srcOk = (u: URL, s: DataSource) => { const f = u.searchParams.get("source"); return !f || f === s; };

export interface Deps { store?: Store; model?: ModelFn | null; fetcher?: any }
/** Does THIS organization have a Wazuh connection (its own, or the server environment for the Default organization)? */
const wzConfigured = async (store: Store) => !!(await WC.resolveWazuhCfg(store).catch(() => ({}))); 
const hits = new Map<string, number[]>();
function rate(key: string, perMin: number) { const now = Date.now(), a = (hits.get(key) ?? []).filter((t) => now - t < 60000); if (a.length >= perMin) throw new HttpError(429, "Too many requests. Slow down and retry in a minute."); a.push(now); hits.set(key, a); }

export async function handleSoc(req: Request, path: string[], deps: Deps = {}): Promise<Response> {
  try {
    const raw = deps.store ?? getStore();
    const u = new URL(req.url), m = req.method.toUpperCase(), [a, b, c] = path;
    if (a === "org" && ((b === "create" && m === "POST") || (b === "mine" && m === "GET") || (b === "invitations" && c === "accept" && m === "POST"))) {
      const user = await identifyUser(req, { raw, fetcher: (deps as any).fetcher });
      if (!user) return json({ error: "Sign in first." }, 401);
      rate(user.id + ":org", 20);
      if (b === "mine") return json({ organizations: await ORG.myOrganizations(raw, user.id) });
      if (b === "create") return json(await ORG.createOrganization(raw, user, await readJson(req)), 201);
      return json(await ORG.acceptInvite(raw, user, await readJson(req)));
    }
    if (a === "billing" && b === "webhook" && m === "POST") {                       // public endpoint: authenticated ONLY by the Stripe signature over the raw body
      rate("billing-webhook", 300); const body = await req.text(); if (body.length > 512_000) throw new HttpError(413, "Payload too large.");
      return json(await BILL.handleWebhook(raw, body, req.headers.get("stripe-signature"), (deps as any).env ?? process.env));
    }
    const pr = await authenticate(req, { raw, fetcher: (deps as any).fetcher });
    if (!pr) {
      // A signed-in user who has no organization yet may only create one, list theirs, or accept an invitation.
      return json({ error: "Not authorized. Sign in, or provide an organization API key." }, 401);
    }
    const store = new ScopedStore(raw, pr.orgId, { platformAdmin: pr.platformAdmin });
    const actor: Actor = { name: pr.name, role: pr.orgRole ?? pr.role }, role = pr.role;
    const area = a === "noc" ? "noc" : a === "org" ? "org" : "soc";
    const need = (p: string) => { if (!allowed(pr, p, area)) throw new HttpError(403, `Your role (${pr.orgRole ?? role}) cannot do this.`); };

    if (a === "billing") {
      const env = (deps as any).env ?? process.env;
      if (b === "status" && m === "GET") { need("read"); return json(await BILL.status(raw, pr.orgId, env)); }
      if (b === "usage" && m === "GET") { need("read"); return json(await BILL.usage(raw, pr.orgId, env)); }
      if (b === "invoices" && m === "GET") return json(await BILL.listInvoices(raw, pr));
      if (b === "payments" && m === "GET") return json(await BILL.listPayments(raw, pr));
      if (b === "checkout" && m === "POST") { rate((pr.userId ?? pr.orgId) + ":bill", 10); return json(await BILL.createCheckout(raw, pr, await readJson(req), env)); }
      if (b === "portal" && m === "POST") { rate((pr.userId ?? pr.orgId) + ":bill", 10); return json(await BILL.createPortal(raw, pr, env)); }
      if (b === "change" && m === "POST") { rate((pr.userId ?? pr.orgId) + ":bill", 10); return json(await BILL.changePlan(raw, pr, await readJson(req), env)); }
      if (b === "cancel" && m === "POST") { rate((pr.userId ?? pr.orgId) + ":bill", 10); return json(await BILL.setCancel(raw, pr, true, env)); }
      if (b === "resume" && m === "POST") { rate((pr.userId ?? pr.orgId) + ":bill", 10); return json(await BILL.setCancel(raw, pr, false, env)); }
      if (b === "admin") {                                                       // platform administrators only (checked again inside every function)
        rate((pr.userId ?? pr.name) + ":badmin", 60); const o = path[3];
        if (c === "plans" && !o && m === "GET") return json(await BILL.adminPlans(raw, pr));
        if (c === "plans" && o && m === "PUT") return json(await BILL.adminUpdatePlan(raw, pr, o, await readJson(req)));
        if (c === "settings" && m === "PUT") return json(await BILL.adminSettings(raw, pr, await readJson(req)));
        if (c === "preview" && m === "GET") return json(await BILL.adminPreview(raw, pr, env));
        if (c === "stats" && m === "GET") return json(await BILL.adminStats(raw, pr));
        if (c === "coupons" && m === "POST") return json(await BILL.adminCreateCoupon(raw, pr, await readJson(req), env));
        if (c === "orgs" && !o && m === "GET") return json(await BILL.adminOrgs(raw, pr, env));
        if (c === "orgs" && o && path[4] === "overrides" && m === "PUT") return json(await BILL.adminSetOverrides(raw, pr, o, await readJson(req)));
        if (c === "orgs" && o && path[4] === "trial" && m === "POST") return json(await BILL.adminGrantTrial(raw, pr, o, await readJson(req)));
        if (c === "orgs" && o && path[4] === "discount" && m === "POST") return json(await BILL.adminApplyDiscount(raw, pr, o, await readJson(req), env));
        if (c === "orgs" && o && path[4] === "refund" && m === "POST") return json(await BILL.adminRefund(raw, pr, o, await readJson(req), env));
      }
      return json({ error: "Not found" }, 404);
    }
    if (a === "org") {
      const user = pr.userId ? { id: pr.userId, email: pr.email } : null;
      const needUser = () => { if (!user) throw new HttpError(403, "Organization management needs a signed-in user account."); return user; };
      if (b === "current" && m === "GET") return json({ id: pr.orgId, name: pr.orgName ?? null, role: pr.orgRole ?? role, kind: pr.kind });
      if (b === "members" && !c && m === "GET") { need("read"); return json(await ORG.listMembers(raw, pr)); }
      if (b === "members" && c && m === "PATCH") return json(await ORG.changeRole(raw, pr, c, await readJson(req)));
      if (b === "members" && c && m === "DELETE") return json(await ORG.removeMember(raw, pr, c));
      if (b === "invitations" && !c && m === "GET") return json(await ORG.listInvites(raw, pr));
      if (b === "invitations" && !c && m === "POST") { rate(pr.name + ":invite", 30); return json(await ORG.invite(raw, pr, await readJson(req)), 201); }
      if (b === "invitations" && c && m === "DELETE") return json(await ORG.revokeInvite(raw, pr, c));
      if (b === "keys" && !c && m === "GET") return json(await ORG.listKeys(raw, pr));
      if (b === "keys" && !c && m === "POST") { rate(pr.name + ":keys", 10); return json(await ORG.createKey(raw, pr, await readJson(req)), 201); }
      if (b === "keys" && c && m === "DELETE") return json(await ORG.revokeKey(raw, pr, c));
      if (b === "audit" && m === "GET") { need("audit"); return json(await store.select(T.audit, { order: ["seq", "desc"], limit: lim(u, 100, 500) })); }
      needUser();
      throw new HttpError(404, "Unknown organization endpoint");
    }

    if (a === "me" && m === "GET") return json({ actor: actor.name, role, orgRole: pr.orgRole ?? null, organization: { id: pr.orgId, name: pr.orgName ?? null }, auth: pr.kind, dev: pr.kind === "dev", store: store.kind, aiConfigured: !!(deps.model !== undefined ? deps.model : defaultModel()) });

    if (a === "noc" && b === "telemetry" && m === "POST") { need("ingest"); rate(actor.name + ":telemetry", 240); const res = await RT.ingestAndEvaluate({ store, actor, deviceMax: await BILL.deviceLimit(raw, pr.orgId, (deps as any).env ?? process.env), model: deps.model !== undefined ? deps.model : defaultModel(), fetcher: (deps as any).fetcher, resolver: (deps as any).resolver }, await readJson(req)); await audit(store, actor, "noc.telemetry", "noc", { devices: res.received }); return json(res); }
    const xc: XJ.ExecCtx = { store, actor, orgId: pr.orgId, pr };
    if (a === "noc" && b === "executor" && c === "jobs" && !path[3] && m === "GET") { need("ingest"); rate(actor.name + ":xpoll", 120); return json(await XJ.pollJobs(xc, String(u.searchParams.get("host") ?? ""))); }
    if (a === "noc" && b === "executor" && c === "jobs" && path[3] && path[4] === "result" && m === "POST") { need("ingest"); rate(actor.name + ":xres", 120); return json(await XJ.acceptResult(xc, path[3], await readJson(req))); }
    if (a === "noc" && ["alerts", "push", "executions", "scans", "changes"].includes(b ?? "") && !(["executions", "scans", "changes"].includes(b ?? "") && m === "GET" && c !== "pending") && !(["scans", "changes"].includes(b ?? "") && m === "POST" && !path[3] ) && !(b === "changes" && c && ["approve", "reject", "rollback"].includes(path[3] ?? ""))) {
      const nc: N.Ctx = { store, actor, deviceMax: await BILL.deviceLimit(raw, pr.orgId, (deps as any).env ?? process.env), model: deps.model !== undefined ? deps.model : defaultModel(), fetcher: (deps as any).fetcher, resolver: (deps as any).resolver };
      if (b === "scans" && c === "pending" && m === "GET") { need("ingest"); return json(await TP.claimScan(nc, String(u.searchParams.get("agent") ?? actor.name))); }
      if (b === "scans" && c && path[3] === "progress" && m === "POST") { need("ingest"); rate(actor.name + ":scanp", 240); return json(await TP.reportScan(nc, c, await readJson(req))); }
      if (b === "scans" && c && path[3] === "complete" && m === "POST") { need("ingest"); return json(await TP.finishScan(nc, c, await readJson(req))); }
      if (b === "changes" && c === "pending" && m === "GET") { need("ingest"); return json(await CH.claimChanges(nc)); }
      if (b === "changes" && c && path[3] === "backup" && m === "POST") { need("ingest"); return json(await CH.executorBackup(nc, c, await readJson(req))); }
      if (b === "changes" && c && path[3] === "result" && m === "POST") { need("ingest"); return json(await CH.executorResult(nc, c, await readJson(req))); }
      if (b === "alerts" && m === "POST") { need("ingest"); rate(actor.name + ":alerts", 120); const al = N.normalizeAlerts(await readJson(req)); return json({ results: await N.receiveAlerts(nc, al, u.searchParams.get("source") ?? undefined) }); }
      if (b === "push" && m === "POST") { need("ingest"); rate(actor.name + ":push", 60); return json(await pushSnapshot(nc, await readJson(req))); }
      if (b === "executions" && c === "pending" && m === "GET") { need("ingest"); return json({ executions: await N.pendingExecutions(nc) }); }
      if (b === "executions" && c && path[3] === "result" && m === "POST") { need("ingest"); return json(await N.reportExecution(nc, c, await readJson(req))); }
    }
    if (a === "ingest" && b === "windows" && m === "POST") {
      need("ingest");
      const body = await readJson(req);
      const events = Array.isArray(body) ? body : body.events;
      if (!Array.isArray(events)) throw new HttpError(400, "Body must be an array of events or { host, events: [...] }");
      if (events.length > MAX_EVENTS) throw new HttpError(413, `Send at most ${MAX_EVENTS} events per request`);
      const res = await ingestWindows(store, { host: body.host, ips: body.ips, os: body.os, collector: body.collector, version: typeof body.version === "string" ? body.version.slice(0, 40) : undefined, events }, "live", actor);
      return json(res);
    }

    // Wazuh bridge endpoints (ingest role only, before the read gate)
    if (a === "ingest" && b === "wazuh" && m === "POST") { need("ingest"); rate(actor.name + ":wazuh", 60); const body = await readJson(req); try { return json(await WZ.ingestWazuh(store, body, { source: "live", mode: "bridge", actor })); } catch (e: any) { await WZ.recordWazuhError(store, e.message, "bridge", actor).catch(() => {}); throw e; } }
    if (a === "wazuh" && b === "cursor" && m === "GET") { need("ingest"); const st = await WZ.wazuhStatus(store); return json({ cursor: st.cursor }); }
    if (a === "wazuh" && b === "bridge-error" && m === "POST") { need("ingest"); await WZ.recordWazuhError(store, String((await readJson(req)).error ?? "unknown"), "bridge", actor); return json({ ok: true }); }
    if (a === "wazuh" && b === "bridge-test" && m === "POST") { need("ingest"); const t = (await readJson(req)) as WZ.WazuhTest; const st = (await store.get<any>(T.meta, "wazuh")) ?? { id: "wazuh", data: { alertsReceived: 0 } }; st.data.lastTest = { at: new Date().toISOString(), by: actor.name, mode: "bridge", ok: !!t.ok, steps: (t.steps ?? []).slice(0, 20).map((x) => ({ name: String(x.name).slice(0, 80), ok: !!x.ok, detail: String(x.detail).slice(0, 300) })) }; await store.upsert(T.meta, [st]); await audit(store, actor, "wazuh.test.bridge", "wazuh", { ok: !!t.ok }); return json({ ok: true }); }
    need("read");
    if (a === "overview" && m === "GET") return json(await overview(store));
    if (a === "ai" && b === "analyze" && m === "POST") {
      rate(actor.name + ":aisoc", 20); const body = await readJson(req).catch(() => ({})); const canP = allowed(pr, "write", "soc") || allowed(pr, "write", "noc"); if (body?.proposeDiagnostics === true && !canP) throw new HttpError(403, "Not allowed to propose diagnostics.");
      const prop = async (list: any[]) => { const out: any[] = []; for (const d of list.slice(0, 5)) { try { const jb = await XJ.requestDiag({ ...xc, actor: { name: "agent:soc-analyst", role: "agent" } }, { hostId: d.hostId, template: d.template, params: d.params, reason: d.why }); out.push({ ...d, status: "proposed_awaiting_human", jobId: jb.id }); } catch (e: any) { out.push({ ...d, why: `${d.why} (not proposed: ${String(e?.message ?? e).slice(0, 120)})` }); } } return out.concat(list.slice(5)); };
      return json(await analyzeSoc(store, { incidentId: body?.incidentId, proposeDiagnostics: body?.proposeDiagnostics === true ? prop : undefined }, actor, deps.model !== undefined ? deps.model : defaultModel()));
    }
    if (a === "noc") {
      const nc: N.Ctx = { store, actor, deviceMax: await BILL.deviceLimit(raw, pr.orgId, (deps as any).env ?? process.env), model: deps.model !== undefined ? deps.model : defaultModel(), fetcher: (deps as any).fetcher, resolver: (deps as any).resolver };
      const canDiag = allowed(pr, "write", "noc") || allowed(pr, "write", "soc");

      const proposer = (agent: string, incidentId?: string) => async (list: any[]) => { const out: any[] = []; for (const d of list.slice(0, 5)) { try { const j = await XJ.requestDiag({ ...xc, actor: { name: agent, role: "agent" } }, { hostId: d.hostId, template: d.template, params: d.params, reason: d.why, incidentId }); out.push({ ...d, status: "proposed_awaiting_human", jobId: j.id }); } catch (e: any) { out.push({ ...d, why: `${d.why} (not proposed: ${String(e?.message ?? e).slice(0, 120)})` }); } } return out.concat(list.slice(5)); };
      if (b === "ai" && c === "analyze" && m === "POST") { rate(actor.name + ":ainoc", 20); const body = await readJson(req).catch(() => ({})); if (body?.proposeDiagnostics === true && !canDiag) throw new HttpError(403, "Not allowed to propose diagnostics."); return json(await analyzeNoc(nc, { deviceId: body?.deviceId, incidentId: body?.incidentId, hours: Number(body?.hours) || undefined, proposeDiagnostics: body?.proposeDiagnostics === true ? proposer("agent:noc-analyst", body?.incidentId) : undefined }, nc.model ?? null)); }
      if (b === "exec" && c === "stats" && m === "GET") return json(await XJ.execStats(xc));
      if (b === "exec" && c === "settings" && m === "GET") return json(await XJ.getSettings(xc));
      if (b === "exec" && c === "settings" && m === "PUT") { rate(actor.name + ":xset", 10); return json(await XJ.setSettings(xc, (await readJson(req))?.enabled)); }
      if (b === "exec" && c === "templates" && m === "GET") return json(CATALOG.map((t) => ({ id: t.id, title: t.title, tier: t.tier, params: t.params, timeoutSec: t.timeoutSec, maxLines: t.maxLines, maxBytes: t.maxBytes, linux: t.linux ? xPreview(t, "linux", Object.fromEntries(Object.keys(t.params).map((k) => [k, `<${k}>`]))) : null, windows: t.windows ? xPreview(t, "windows", Object.fromEntries(Object.keys(t.params).map((k) => [k, `<${k}>`]))) : null })));
      if (b === "exec" && c === "executors" && !path[3] && m === "GET") return json(await XJ.listExecutors(xc));
      if (b === "exec" && c === "executors" && !path[3] && m === "POST") { need("approve"); rate(actor.name + ":xreg", 20); return json(await XJ.registerExecutor(xc, await readJson(req), raw), 201); }
      if (b === "exec" && c === "executors" && path[3] && (path[4] === "enable" || path[4] === "disable") && m === "POST") { need("approve"); return json(await XJ.setExecutorEnabled(xc, path[3], path[4] === "enable")); }
      if (b === "diag" && !c && m === "POST") { const body = await readJson(req); if (body?.dryRun === true) need("read"); else if (pr.kind !== "user") throw new HttpError(403, "Real diagnostics must be requested by a signed-in person, not by an API key.");
          else if (!canDiag) throw new HttpError(403, `Your role (${pr.orgRole ?? role}) cannot run diagnostics.`); rate(actor.name + ":diag", 60); return json(await XJ.requestDiag(xc, body), 201); }
      if (b === "diag" && !c && m === "GET") return json(await XJ.listJobs(xc, { status: u.searchParams.get("status") ?? undefined, incident: u.searchParams.get("incident") ?? undefined, host: u.searchParams.get("host") ?? undefined, limit: lim(u, 100, 500) }));
      if (b === "diag" && c && !path[3] && m === "GET") return json(await XJ.getJob(xc, c));
      if (b === "diag" && c && (path[3] === "approve" || path[3] === "reject") && m === "POST") { const j = await XJ.getJob(xc, c); if (j.tier === "R1") need("approve"); else if (!canDiag) throw new HttpError(403, `Your role (${pr.orgRole ?? role}) cannot decide diagnostics.`); rate(actor.name + ":diagdec", 60); return json(await XJ.confirmJob(xc, c, path[3], (await readJson(req).catch(() => ({})))?.note)); }
      if (b === "diag" && c && path[3] === "cancel" && m === "POST") { if (!canDiag) throw new HttpError(403, "Not allowed."); return json(await XJ.cancelJob(xc, c)); }
      if (b === "availability" && m === "GET") return json(await RT.availability(nc, Math.max(1, Math.min(720, Number(u.searchParams.get("hours")) || 24)), u.searchParams.get("device") ?? undefined));
      if (b === "history" && m === "GET") return json(await RT.history(nc, String(u.searchParams.get("device") ?? ""), String(u.searchParams.get("key") ?? "cpu"), Math.max(1, Math.min(720, Number(u.searchParams.get("hours")) || 24)), lim(u, 1000, 5000)));
      if (b === "overview" && m === "GET") { rate(actor.name + ":ov", 240); await N.sweepSources(nc); await RT.sweepDevices(nc); return json(await nocOverview(nc)); }
      if (b === "sources" && !c && m === "POST") { need("approve"); rate(actor.name + ":cfg", 30); return json(await N.createSource(nc, await readJson(req)), 201); }
      if (b === "sources" && c && path[3] === "test" && m === "POST") { need("approve"); rate(actor.name + ":cfg", 30); return json(await N.testSource(nc, c)); }
      if (b === "retention" && m === "POST") {                       // dry run by default; deletes only when apply:true AND billing enforcement is on; only old noc_metrics samples
        need("approve"); rate(actor.name + ":retention", 6); const body: any = await readJson(req), env2 = (deps as any).env ?? process.env, e = await BILL.getEntitlements(raw, pr.orgId, Date.now(), env2);
        if (body?.apply === true && !e.enforced) throw new HttpError(409, "Plan limits are not enforced on this server, so nothing is pruned. Run without apply for a report.");
        const r = await prune(store, e.retentionDays, { apply: body?.apply === true });
        if (r.applied) await audit(store, actor, "noc.retention.prune", pr.orgId, { retentionDays: r.retentionDays, deleted: r.deleted }); return json({ plan: e.plan, enforced: e.enforced, ...r });
      }
      if (b === "sources" && c && path[3] === "sync" && m === "POST") { need("approve"); rate(actor.name + ":cfg", 30); return json(await N.syncSource(nc, c)); }
      if (b === "sources" && c && !path[3] && m === "DELETE") { need("approve"); return json(await N.deleteSource(nc, c)); }
      if (b === "actions" && !c && m === "POST") { need("approve"); return json(await N.createAction(nc, await readJson(req)), 201); }
      if (b === "approvals" && c && (path[3] === "approve" || path[3] === "reject") && m === "POST") { need("approve"); rate(actor.name + ":appr", 30); const bd = await readJson(req); return json(await N.decideApproval(nc, c, path[3] as any, bd?.note)); }
      if (b === "incidents" && c && path[3] === "verify" && m === "POST") { need("write"); return json({ incident: await N.verifyIncident(nc, c) }); }
      if (b === "topology" && m === "GET") return json(await TP.topology(nc, u.searchParams.get("map") ?? undefined));
      if (b === "discovery" && m === "GET") return json(await TP.discoveryView(nc));
      if (b === "scopes" && !c && m === "POST") { need("approve"); rate(actor.name + ":scope", 20); return json(await TP.createScope(nc, await readJson(req)), 201); }
      if (b === "scopes" && c && m === "DELETE") { need("approve"); return json(await TP.deleteScope(nc, c)); }
      if (b === "scans" && !c && m === "POST") { need("approve"); rate(actor.name + ":scan", 10); return json(await TP.startScan(nc, await readJson(req)), 201); }
      if (b === "scans" && c && path[3] === "cancel" && m === "POST") { need("approve"); return json(await TP.cancelScan(nc, c)); }
      if (b === "devices" && c && path[3] === "adopt" && m === "POST") { need("approve"); return json(await TP.adopt(nc, c)); }
      if (b === "maps" && !c && m === "GET") return json(await TP.listMaps(nc));
      if (b === "maps" && !c && m === "POST") { need("write"); return json(await TP.createMap(nc, await readJson(req)), 201); }
      if (b === "maps" && c && path[3] === "save" && m === "POST") { need("write"); rate(actor.name + ":mapsave", 60); return json(await TP.saveMap(nc, c, await readJson(req))); }
      if (b === "maps" && c && path[3] === "versions" && m === "GET") return json(await TP.mapVersions(nc, c));
      if (b === "maps" && c && path[3] === "restore" && m === "POST") { need("write"); return json(await TP.restoreVersion(nc, c, Number((await readJson(req)).version))); }
      if (b === "backups" && c && m === "GET") { need("write"); return json(await CH.listBackups(nc, c)); }
      if (b === "backups" && c && m === "POST") { need("write"); return json(await CH.addBackup(nc, c, String((await readJson(req)).config ?? ""))); }
      if (b === "changes" && !c && m === "GET") return json(await CH.listChanges(nc));
      if (b === "changes" && !c && m === "POST") { need("write"); rate(actor.name + ":chg", 30); return json(await CH.proposeChange(nc, await readJson(req)), 201); }
      if (b === "changes" && c && (path[3] === "approve" || path[3] === "reject") && m === "POST") { need("approve"); return json(await CH.decideChange(nc, c, path[3] as any, await readJson(req))); }
      if (b === "changes" && c && path[3] === "rollback" && m === "POST") { need("approve"); return json(await CH.proposeRollback(nc, c)); }
      if (b === "agents" && c && path[3] === "run" && m === "POST") { need("write"); rate(actor.name + ":agent", 30); return json({ activity: await nocRun(nc, c, await readJson(req)) }); }
    }
    if (a === "noc" && b === "devices" && m === "GET") { need("read"); return json(await listDevices(store)); }
    // ---- Wazuh (read-only integration) ----
    if (a === "wazuh" && b === "status" && m === "GET") { need("read"); return json(await WZ.wazuhStatus(store, Date.now(), await wzConfigured(store))); }
    if (a === "wazuh" && b === "sync" && m === "POST") { need("ingest"); rate(actor.name + ":wzsync", 20); return json(await WZ.syncWazuh(store, actor, (deps as any).fetcher ?? fetch, (deps as any).wazuhCfg !== undefined ? (deps as any).wazuhCfg : await WC.resolveWazuhCfg(store, process.env, (deps as any).resolver))); }
    if (a === "wazuh" && b === "test" && c === "connection" && m === "POST") { need("approve"); rate(actor.name + ":wztest", 10); return json(await WZ.testWazuhConnection(store, actor, (deps as any).fetcher ?? fetch, (deps as any).wazuhCfg !== undefined ? (deps as any).wazuhCfg : await WC.resolveWazuhCfg(store, process.env, (deps as any).resolver).catch((e) => { throw e; }))); }
    if (a === "wazuh" && b === "config" && m === "GET") { need("approve"); return json(await WC.getWazuhConfigPublic(store)); }
    if (a === "wazuh" && b === "config" && m === "PUT") { need("approve"); rate(actor.name + ":wzcfg", 20); return json(await WC.saveWazuhConfig(store, actor, await readJson(req), process.env, (deps as any).resolver)); }
    if (a === "wazuh" && b === "config" && m === "DELETE") { need("approve"); return json(await WC.deleteWazuhConfig(store, actor)); }
    if (a === "wazuh" && b === "enrollment" && m === "GET") {
      need("read"); const cfg = await WC.getWazuhConfigPublic(store) as any, st = await WZ.wazuhStatus(store);
      return json(WC.enrollment(u.searchParams.get("os") ?? "", String(cfg.agentManager ?? ""), u.searchParams.get("version") ?? String(st.manager ?? "").replace(/^v/i, "").match(/^\d+\.\d+\.\d+/)?.[0] ?? "", u.searchParams.get("name") ?? undefined));
    }
    if (a === "wazuh" && b === "test" && c === "event" && m === "POST") { need("approve"); rate(actor.name + ":wztest", 10); return json(await WZ.wazuhSelfTest(store, actor)); }
    if (a === "wazuh" && b === "test" && c === "cleanup" && m === "POST") { need("approve"); return json(await WZ.wazuhSelfTestCleanup(store, actor)); }
    if (a === "collectors" && m === "GET") return json(await collectors(store));
    if (a === "integrations" && m === "GET") return json({ integrations: await integrations(store, deps) });
    if (a === "rules" && m === "GET") return json(RULES_META);

    if (a === "events" && m === "GET") {
      const where: Record<string, string | number> = {};
      if (u.searchParams.get("asset")) where.assetId = u.searchParams.get("asset")!;
      if (u.searchParams.get("eventId")) where.eventId = Number(u.searchParams.get("eventId"));
      const since = u.searchParams.get("since"); // live view: only events ingested after this timestamp
      if (since) { const rows = (await store.select<SocEvent>(T.events, { where, gte: ["ingestedAt", since], order: ["ingestedAt", "asc"], limit: lim(u, 500, 1000) })).filter((e) => e.ingestedAt > since && srcOk(u, e.source)); return json(rows); }
      const q = (u.searchParams.get("q") ?? "").toLowerCase();
      let rows = await store.select<SocEvent>(T.events, { where, order: ["time", "desc"], limit: q ? 5000 : lim(u) });
      rows = rows.filter((e) => srcOk(u, e.source));
      if (q) rows = rows.filter((e) => `${e.summary} ${e.user ?? ""} ${e.srcIp ?? ""} ${e.process ?? ""} ${e.commandLine ?? ""} ${e.host}`.toLowerCase().includes(q));
      return json(rows.slice(0, lim(u)));
    }
    if (a === "hunt" && m === "GET") {
      const g = (k: string) => u.searchParams.get(k) ?? undefined;
      const ids = (g("eventIds") ?? "").split(",").map((x) => Number(x)).filter((x) => Number.isInteger(x) && x > 0).slice(0, 20);
      const all = (await store.select<SocEvent>(T.events, { order: ["time", "desc"], limit: 5000 })).filter((e) => srcOk(u, e.source));
      const r = huntEvents(all, { q: g("q"), host: g("host"), user: g("user"), ip: g("ip"), channel: g("channel"), from: g("from"), to: g("to"), eventIds: ids }, lim(u, 200, 1000));
      return json({ searched: all.length, total: r.total, rows: r.rows });
    }
    if (a === "alerts" && m === "GET") {
      const rows = (await store.select<Alert>(T.alerts, { order: ["lastSeen", "desc"], limit: 1000 })).filter((x) => srcOk(u, x.source));
      return json(rows.sort((x, y) => sevRank(y.severity) - sevRank(x.severity) || (x.lastSeen < y.lastSeen ? 1 : -1)).slice(0, lim(u)));
    }
    if (a === "incidents" && m === "GET" && !b) {
      const rows = (await store.select<Incident>(T.incidents, { order: ["lastSeen", "desc"], limit: 500 })).filter((x) => srcOk(u, x.source));
      const open = await store.select<SocAction>(T.actions, { where: { status: "proposed" } }), tasks = await store.select<TaskRun>(T.tasks, { order: ["createdAt", "desc"], limit: 200 });
      return json(rows.sort((x, y) => sevRank(y.severity) - sevRank(x.severity) || (x.lastSeen < y.lastSeen ? 1 : -1)).map((i) => withMgmt(i, open, tasks)));
    }
    if (a === "incidents" && b && m === "GET" && !c) { const d = await incidentDetail(store, b); const tasks = await store.select<TaskRun>(T.tasks, { order: ["createdAt", "desc"], limit: 200 }); return json({ ...d, incident: withMgmt(d.incident, d.actions, tasks) }); }
    if (a === "incidents" && b && !c && m === "PATCH") {
      need("write"); const body = await readJson(req);
      if (body.owner !== undefined) {
        const inc = await store.get<Incident>(T.incidents, b); if (!inc) throw new HttpError(404, "Incident not found");
        const owner = String(body.owner ?? "").trim().slice(0, 60); inc.owner = owner || undefined; inc.updatedAt = nowIso(); await store.upsert(T.incidents, [inc]); await audit(store, actor, "incident.assign", b, { owner: owner || null });
        if (!body.status) return json(inc);
      }
      return json(await setIncidentStatus(store, b, body.status as IncidentStatus, actor, body.note, body.force === true));
    }
    if (a === "incidents" && b && c === "status" && m === "POST") {
      need("write"); const body = await readJson(req);
      return json(await setIncidentStatus(store, b, body.status as IncidentStatus, actor, body.note, body.force === true));
    }
    if (a === "incidents" && b && c === "verify" && m === "POST") { need("write"); return json(await verifyIncident(store, b, actor)); }

    if (a === "vulns" && m === "GET") {
      const sev = u.searchParams.get("severity"), asset = u.searchParams.get("asset");
      const rows = (await store.select<Vuln>(T.vulns, { limit: 20000 })).filter((v) => srcOk(u, v.source) && (!sev || v.severity === sev) && (!asset || v.assetId === asset) && (u.searchParams.get("all") === "1" || v.status !== "fixed_verified"));
      return json(rows.sort((x, y) => y.priority - x.priority).slice(0, lim(u, 300, 2000)));
    }
    if (a === "vulns" && b && m === "PATCH") {
      need("write"); const body = await readJson(req); const v = await store.get<Vuln>(T.vulns, b);
      if (!v) throw new HttpError(404, "Not found");
      if (body.status) { if (!["open", "in_remediation", "accepted_risk"].includes(body.status)) throw new HttpError(400, "Status can be set to open, in_remediation or accepted_risk. fixed_verified is only set by a later scan."); v.status = body.status; }
      if (typeof body.note === "string") v.note = body.note.slice(0, 1000);
      v.updatedAt = nowIso(); await store.upsert(T.vulns, [v]); await audit(store, actor, "vuln.update", b, { status: v.status });
      return json(v);
    }
    if (a === "assets" && m === "GET" && !b) {
      const [assets, vulns, incs] = await Promise.all([store.select<Asset>(T.assets, { limit: 500 }), store.select<Vuln>(T.vulns, { limit: 20000 }), store.select<Incident>(T.incidents, { limit: 1000 })]);
      return json(assets.filter((x) => srcOk(u, x.source)).map((x) => ({ ...x, risk: assetRisk(vulns.filter((v) => v.assetId === x.id), incs.filter((i) => i.assetId === x.id)), openVulns: vulns.filter((v) => v.assetId === x.id && v.status !== "fixed_verified").length })));
    }
    if (a === "assets" && b && m === "PATCH") {
      need("write"); const body = await readJson(req); const x = await store.get<Asset>(T.assets, b);
      if (!x) throw new HttpError(404, "Not found");
      if (Number.isInteger(body.criticality) && body.criticality >= 1 && body.criticality <= 5) x.criticality = body.criticality;
      if (body.authorized === true) { if (body.attest !== true) throw new HttpError(400, "Set attest=true to confirm you own or are authorized to test this asset."); x.authorized = true; x.authorizedBy = actor.name; x.authorizedAt = nowIso(); x.authorizationNote = String(body.note ?? "").slice(0, 300); }
      if (body.authorized === false) { x.authorized = false; }
      await store.upsert(T.assets, [x]); await audit(store, actor, "asset.update", b, { criticality: x.criticality, authorized: x.authorized });
      return json(x);
    }

    if (a === "import" && b === "greenbone" && m === "POST") {
      need("write");
      const ct = req.headers.get("content-type") ?? "";
      let content: string, format: "xml" | "csv" | undefined, filename: string | undefined, attest = u.searchParams.get("attest") === "true", note: string | undefined;
      if (ct.includes("application/json")) { const body = await readJson(req); content = String(body.content ?? ""); format = body.format; filename = body.filename; attest = body.attest === true; note = body.note; }
      else { const t = await req.text(); if (t.length > 25_000_000) throw new HttpError(413, "Report too large (25 MB limit)"); content = t; format = ct.includes("csv") ? "csv" : ct.includes("xml") ? "xml" : undefined; filename = u.searchParams.get("filename") ?? undefined; }
      if (!content) throw new HttpError(400, "Empty report");
      return json({ scan: await importScan(store, content, { format, filename, attest, attestNote: note, source: "imported" }, actor) });
    }
    if (a === "import" && b === "kev" && m === "POST") { need("write"); return json(await importKev(store, await readJson(req), actor)); }

    if (a === "agents" && b === "run" && m === "POST") {
      need("write"); const body = await readJson(req);
      const agent = (AGENT_IDS as string[]).includes(body?.agent) ? (body.agent as AgentId) : "soc_analyst";
      const task = await taskFromAgentRequest(store, body);
      return json({ run: await runAnalyst(store, task, actor, deps.model !== undefined ? deps.model : defaultModel(), agent) });
    }
    if (a === "analyst" && m === "POST") {
      need("write"); const body = await readJson(req);
      const task = parseTask(body);
      return json(await runAnalyst(store, task, actor, deps.model !== undefined ? deps.model : defaultModel()));
    }
    if (a === "agent-runs" && m === "GET") return json((await store.select<AgentRun>(T.runs, { order: ["createdAt", "desc"], limit: lim(u, 50, 200) })));
    if (a === "tasks" && !b && m === "POST") { need("write"); return json(publicTask(await createTask(store, await readJson(req), actor)), 201); }
    if (a === "tasks" && !b && m === "GET") { const role = u.searchParams.get("role"), rows = await store.select<TaskRun>(T.tasks, { order: ["createdAt", "desc"], limit: 200 }); return json(rows.filter((r) => !role || r.role === role).slice(0, lim(u, 50, 200)).map(publicTask)); }
    if (a === "tasks" && b && !c && m === "GET") { const r = await store.get<TaskRun>(T.tasks, b); if (!r) throw new HttpError(404, "Task not found"); return json(publicTask(r)); }
    if (a === "tasks" && b && c === "next" && m === "POST") { need("write"); return json(publicTask(await advanceTask(store, b, actor, { overview: () => overview(store), incident: (id) => incidentDetail(store, id), collectors: () => collectors(store) }))); }
    if (a === "tasks" && b && c === "cancel" && m === "POST") { need("write"); return json(publicTask(await cancelTask(store, b, actor))); }
    if (a === "tasks" && b && c === "retry" && m === "POST") { need("write"); return json(publicTask(await retryTask(store, b, actor))); }
    if (a === "actions" && m === "GET") return json(await store.select<SocAction>(T.actions, { order: ["createdAt", "desc"], limit: 300 }));
    if (a === "actions" && !b && m === "POST") {
      need("write"); const body = await readJson(req); const v = validateManualAction(body);
      if (!v.ok) throw new HttpError(400, v.error);
      let source: DataSource = "live";
      if (body.incidentId) { const inc = await store.get<Incident>(T.incidents, String(body.incidentId)); if (!inc) throw new HttpError(404, "Incident not found"); source = inc.source; }
      const act: SocAction = { id: hid("act", `${actor.name}|${Date.now()}|${v.type}|${v.target}|${v.description}`), source, incidentId: body.incidentId ? String(body.incidentId) : undefined, type: v.type, target: v.target, description: v.description, rationale: v.rationale, proposedBy: `user:${actor.name}`, status: "proposed", requiresApproval: true, createdAt: nowIso() };
      await store.upsert(T.actions, [act]); await audit(store, actor, "action.propose", act.id, { type: act.type, target: act.target });
      return json(act, 201);
    }
    if (a === "actions" && b && c && m === "POST") {
      need("approve"); const body = await readJson(req);
      if (!["approve", "reject", "done"].includes(c)) throw new HttpError(404, "Unknown action");
      return json(await decideAction(store, b, c === "approve" ? "approved" : c === "reject" ? "rejected" : "done", actor, body.note));
    }
    if (a === "approvals" && m === "GET") {
      const all = await store.select<SocAction>(T.actions, { order: ["createdAt", "desc"], limit: 300 }), rich = await enrichActions(store, all);
      return json({ pending: rich.filter((x) => x.status === "proposed"), history: rich.filter((x) => x.status !== "proposed"), executor: { configured: false, detail: "No response connector (EDR, firewall, identity provider) is configured. Approving records the decision; a human carries the action out and marks it done." } });
    }
    if (a === "audit" && b === "verify" && m === "GET") { need("audit"); return json(await verifyAuditChain(store)); }
    if (a === "audit" && m === "GET") { need("audit"); return json(await store.select<AuditEntry>(T.audit, { order: ["time", "desc"], limit: lim(u, 200, 1000) })); }
    return json({ error: "Not found" }, 404);
  } catch (e) {
    if (e instanceof AuthError) return json({ error: e.message, ...(e.extra ?? {}) }, e.status);
    if (e instanceof TenantError) return json({ error: e.message }, e.status);
    if (e instanceof HttpError) return json({ error: e.message, ...(e.extra ?? {}) }, e.status);
    console.error("soc api error", e);
    return json({ error: "Server error. Check the server logs." }, 500);
  }
}

/** Maps the workspace buttons (agent + target + optional question) to an analyst task. */
async function taskFromAgentRequest(store: Store, b: any): Promise<AnalystTask> {
  const target = String(b?.target ?? ""), focus = String(b?.question ?? "").slice(0, 1000) || undefined;
  if (b?.agent === "security_advisor") return { kind: "report", focus };
  if (target.startsWith("alt_")) return { kind: "investigate_alert", alertId: target, focus };
  if (target.startsWith("evt_")) return { kind: "analyze_event", eventId: target, focus };
  if (target.startsWith("inc_")) {
    const inc = await store.get<Incident>(T.incidents, target);
    if (!inc) throw new HttpError(404, "Incident not found");
    const alerts = ((await Promise.all(inc.alertIds.map((x) => store.get<Alert>(T.alerts, x)))).filter(Boolean) as Alert[]).sort((x, y) => sevRank(y.severity) - sevRank(x.severity));
    if (!alerts.length) throw new HttpError(409, "This incident has no alerts to investigate.");
    return { kind: "investigate_alert", alertId: alerts[0].id, focus };
  }
  if (focus) return { kind: "ask", question: focus };
  throw new HttpError(400, "Provide a target (alert, event or incident id) or a question.");
}

function parseTask(b: any): AnalystTask {
  switch (b?.kind) {
    case "investigate_alert": if (typeof b.alertId === "string") return { kind: "investigate_alert", alertId: b.alertId }; break;
    case "analyze_event": if (typeof b.eventId === "string") return { kind: "analyze_event", eventId: b.eventId }; break;
    case "report": return { kind: "report" };
    case "ask": if (typeof b.question === "string" && b.question.trim()) return { kind: "ask", question: b.question.slice(0, 2000) }; break;
  }
  throw new HttpError(400, "Body must be {kind:'investigate_alert',alertId} | {kind:'analyze_event',eventId} | {kind:'report'} | {kind:'ask',question}");
}

export async function overview(store: Store) {
  const [alerts, incs, vulns, assets, evs, scans] = await Promise.all([
    store.select<Alert>(T.alerts, { order: ["lastSeen", "desc"], limit: 5000 }), store.select<Incident>(T.incidents, { limit: 2000 }), store.select<Vuln>(T.vulns, { limit: 20000 }),
    store.select<Asset>(T.assets, { limit: 500 }), store.select<SocEvent>(T.events, { order: ["time", "desc"], limit: 1000 }), store.select<ScanImport>(T.scans, { order: ["importedAt", "desc"], limit: 1 }),
  ]);
  const openV = vulns.filter((v) => v.status !== "fixed_verified");
  const n = <X extends { source: DataSource }>(xs: X[], s: DataSource) => xs.filter((x) => x.source === s).length;
  const vulnCounts = { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>;
  for (const v of openV) if (v.severity in vulnCounts) vulnCounts[v.severity]++;
  const rank = (x: { severity: Incident["severity"]; lastSeen: string }, y: typeof x) => sevRank(y.severity) - sevRank(x.severity) || (x.lastSeen < y.lastSeen ? 1 : -1);
  const scored = assets.map((x) => ({ id: x.id, hostname: x.hostname, criticality: x.criticality, authorized: x.authorized, lastEventAt: x.lastEventAt, source: x.source, score: assetRisk(vulns.filter((v) => v.assetId === x.id), incs.filter((i) => i.assetId === x.id)) }));
  const dayAgo = new Date(Date.now() - 86400_000).toISOString();
  return {
    generatedAt: nowIso(), hasData: !!(alerts.length || evs.length || vulns.length || assets.length),
    present: { live: { events: n(evs, "live"), alerts: n(alerts, "live") }, imported: { vulns: n(vulns, "imported") }, demo: { events: n(evs, "demo"), vulns: n(vulns, "demo"), alerts: n(alerts, "demo") } },
    posture: scored.length ? Math.max(0, Math.round(100 - scored.reduce((s, x) => s + x.score, 0) / scored.length)) : null,
    vulnCounts, activeIncidents: incs.filter((i) => i.status !== "closed").sort(rank).slice(0, 25),
    recentAlerts: [...alerts].sort((x, y) => (x.lastSeen < y.lastSeen ? 1 : -1)).slice(0, 30), recentEvents: evs.slice(0, 40),
    topVulns: [...openV].sort((x, y) => y.priority - x.priority).slice(0, 15), assets: scored,
    events24h: evs.filter((e) => e.time >= dayAgo).length, kevVulns: openV.filter((v) => v.kev).length, lastScanImport: scans[0] ?? null,
  };
}

/** Incident-center fields derived from stored data: display status, owner, and which agents have worked on it. */
function withMgmt(i: Incident, actions: { incidentId?: string; status: string; proposedBy?: string }[], tasks: TaskRun[]) {
  const mine = actions.filter((x) => x.incidentId === i.id), pending = mine.filter((x) => x.status === "proposed").length;
  const agents = [...new Set([...tasks.filter((t) => t.result?.incidentId === i.id).map((t) => t.role), ...mine.map((x) => x.proposedBy ?? "").filter((p) => p.startsWith("agent:")).map((p) => p.slice(6))])];
  return { ...i, displayStatus: displayStatus(i, pending), pendingApprovals: pending, assignedAgents: agents };
}
export type CollectorStatus = "connected" | "stale" | "offline";
/** One row per host that has ever reported. Status comes only from the last real contact time. */
export async function collectors(store: Store, now = Date.now()) {
  const assets = await store.select<Asset>(T.assets, { limit: 500 });
  return assets.filter((x) => x.source !== "imported" || x.lastEventAt || x.lastContactAt).map((x) => {
    const last = x.lastContactAt ?? x.lastEventAt ?? null, age = last ? now - ms(last) : Infinity;
    let status: CollectorStatus = age <= 5 * 60_000 ? "connected" : age <= 60 * 60_000 ? "stale" : "offline";
    if (x.agentStatus) status = x.agentStatus === "active" ? (now - ms(x.agentSyncedAt ?? "") <= 15 * 60_000 ? "connected" : "stale") : "offline"; // Wazuh decides if its agent is active; staleness is our last sync
    return { agentStatus: x.agentStatus ?? null, agentVersion: x.agentVersion ?? null, host: x.hostname, assetId: x.id, source: x.source, status, lastContactAt: last, lastEventAt: x.lastEventAt ?? null, lastBatch: x.lastBatch ?? null, collector: x.collector ?? null, version: x.collectorVersion ?? null, ips: x.ips, os: x.os ?? null };
  }).filter((x) => x.lastContactAt || x.agentStatus).sort((a, b) => ((a.lastContactAt ?? "") < (b.lastContactAt ?? "") ? 1 : -1));
}

async function integrations(store: Store, deps: Deps) {
  const [assets, scans, meta] = await Promise.all([store.select<Asset>(T.assets, { limit: 500 }), store.select<ScanImport>(T.scans, { order: ["importedAt", "desc"], limit: 1 }), store.get<{ importedAt: string; count: number }>(T.meta, "kev")]);
  const noc = await store.select<NocDevice>(NOC_TABLE, { limit: 1000 });
  const stale = 15 * 60_000;
  const win = assets.filter((x) => x.lastEventAt || x.lastContactAt);
  const latest = win.reduce<string | null>((m, x) => { const t = x.lastContactAt ?? x.lastEventAt!; return !m || t > m ? t : m; }, null);
  return [
    { id: "windows", name: "Windows Event Logs (collector)", status: !win.length ? "not_connected" : win.some((x) => Date.now() - ms((x.lastContactAt ?? x.lastEventAt)!) < stale) ? "healthy" : "stale", lastSuccess: latest, detail: win.length ? `${win.length} host(s) sending events` : "No events received yet. Install the collector on an authorized Windows computer.", hosts: win.map((x) => ({ host: x.hostname, lastEventAt: x.lastEventAt })) },
    { id: "greenbone", name: "Greenbone / OpenVAS (report import)", status: scans[0] ? "imported" : "not_connected", lastSuccess: scans[0]?.importedAt ?? null, detail: scans[0] ? `Last import: ${scans[0].findings} findings from ${scans[0].hosts.length} host(s). Reports are imported by file; the platform does not start scans.` : "No report imported yet." },
    { id: "kev", name: "CISA KEV file (optional)", status: meta ? "imported" : "not_connected", lastSuccess: meta?.importedAt ?? null, detail: meta ? `${meta.count} known-exploited CVEs imported from a file you provided.` : "Not imported. Import known_exploited_vulnerabilities.json to flag known-exploited CVEs." },
    { id: "ai", name: "AI SOC Analyst (Anthropic API)", status: (deps.model !== undefined ? deps.model : defaultModel()) ? "configured" : "not_configured", lastSuccess: null, detail: "Needs ANTHROPIC_API_KEY on the server." },
    { id: "db", name: "Database", status: store.kind === "supabase" ? "configured" : "volatile", lastSuccess: null, detail: store.kind === "supabase" ? "Supabase (Postgres)." : "In-memory only: data is lost on restart. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY." },
    { id: "noc_telemetry", name: "NOC telemetry API (POST /api/soc/noc/telemetry)", status: noc.length ? (Date.now() - Math.max(...noc.map((x) => ms(x.receivedAt))) < stale ? "healthy" : "stale") : "not_connected", lastSuccess: noc.length ? new Date(Math.max(...noc.map((x) => ms(x.receivedAt)))).toISOString() : null, detail: noc.length ? `${noc.length} device(s) reporting. SNMP, syslog, Zabbix, PRTG, Nagios, Prometheus, Grafana and cloud monitoring adapters are not built; send their data to this API.` : "No telemetry received. Nothing on the NOC page is real until a monitoring source posts here." },
    { id: "wazuh", name: "Wazuh (alerts and endpoint agents, read-only)", ...(await (async () => { const w = await WZ.wazuhStatus(store, Date.now(), await wzConfigured(store)); return { status: w.status, lastSuccess: w.lastSuccessAt, detail: w.detail + (w.agents ? ` Agents: ${w.agents.active} active, ${w.agents.disconnected} disconnected of ${w.agents.total}.` : "") }; })()) },
    { id: "siem", name: "Other SIEM / firewall / EDR APIs", status: "not_implemented", lastSuccess: null, detail: "Not built. Splunk, Sentinel and firewall APIs are not connected." },
  ];
}

export async function incidentDetail(store: Store, id: string) {
  const inc = await store.get<Incident>(T.incidents, id);
  if (!inc) throw new HttpError(404, "Incident not found");
  const alerts = ((await Promise.all(inc.alertIds.map((x) => store.get<Alert>(T.alerts, x)))).filter(Boolean) as Alert[]);
  const evIds = [...new Set(alerts.flatMap((x) => x.eventIds))].slice(0, 300);
  const events = ((await Promise.all(evIds.map((x) => store.get<SocEvent>(T.events, x)))).filter(Boolean) as SocEvent[]).sort((x, y) => (x.time < y.time ? -1 : 1));
  const [runs, actions, audits, vulns, asset] = await Promise.all([
    store.select<AgentRun>(T.runs, { order: ["createdAt", "desc"], limit: 200 }), store.select<SocAction>(T.actions, { where: { incidentId: id } }),
    store.select<AuditEntry>(T.audit, { where: { target: id }, order: ["time", "asc"], limit: 200 }), store.select<Vuln>(T.vulns, { where: { assetId: inc.assetId } }), store.get<Asset>(T.assets, inc.assetId),
  ]);
  const myRuns = runs.filter((r) => alerts.some((a) => a.id === r.target) || r.target === id);
  const tl: TimelineEntry[] = [
    ...events.map((e): TimelineEntry => ({ time: e.time, kind: "event", title: `${e.eventId} ${e.summary}`, detail: [e.user && `user ${e.user}`, e.srcIp && `from ${e.srcIp}`, e.process].filter(Boolean).join(" · "), ref: e.id, source: e.source })),
    ...alerts.map((x): TimelineEntry => ({ time: x.firstSeen, kind: "alert", title: `Alert ${x.ruleId}: ${x.title}`, detail: x.reasoning, ref: x.id, source: x.source })),
    ...myRuns.map((r): TimelineEntry => ({ time: r.createdAt, kind: "agent", title: `AI SOC Analyst (${r.status})`, detail: r.summary, ref: r.id, source: r.source })),
    ...actions.map((x): TimelineEntry => ({ time: x.createdAt, kind: "action", title: `Proposed action: ${x.description}`, detail: `${x.status}${x.decidedBy ? ` by ${x.decidedBy}` : ""}`, ref: x.id })),
    ...audits.filter((x) => x.action.startsWith("incident.")).map((x): TimelineEntry => ({ time: x.time, kind: x.action === "incident.verify" ? "verification" : "status", title: x.action === "incident.verify" ? `Remediation check: ${(x.detail as any).status}` : `Status → ${(x.detail as any).to}`, detail: String((x.detail as any).note ?? "") || undefined })),
  ].sort((x, y) => (x.time < y.time ? -1 : 1));
  return { incident: inc, asset, alerts, events, vulnerabilities: vulns.filter((v) => v.status !== "fixed_verified").sort((x, y) => y.priority - x.priority).slice(0, 20), agentRuns: myRuns, actions, timeline: tl };
}
