// Pending-approval view: for each proposed action, the risk, who and what it affects, and the evidence behind it.
import { T, type Store } from "./store";
import type { Alert, Asset, Incident, Severity, SocAction, SocEvent } from "./types";
import { sevRank } from "./types";
import { isPrivateIp } from "./util";

export interface EnrichedAction extends SocAction {
  risk: { level: "high" | "medium" | "low"; reasons: string[]; ifApproved: string; ifIgnored: string };
  affected: { host?: string; user?: string; ip?: string; incident?: { id: string; title: string; severity: Severity; status: string } };
  evidence: { alerts: { id: string; ruleId: string; title: string; severity: Severity; reasoning: string; eventCount: number }[]; events: { id: string; time: string; summary: string; user?: string; srcIp?: string }[] };
  ageMinutes: number; byAgent: boolean;
}
const BASE: Record<string, { level: "high" | "medium" | "low"; why: string; ifApproved: string }> = {
  isolate_host: { level: "high", why: "Takes the computer off the network; users and services on it lose connectivity.", ifApproved: "A human must isolate the host (Spark does not). Users on it will be cut off." },
  disable_account: { level: "high", why: "Locks a user out; may stop services that run under the account.", ifApproved: "A human must disable the account. Check that no service depends on it." },
  block_ip: { level: "medium", why: "Blocks traffic from an address; a wrong or shared address can cut off legitimate users.", ifApproved: "A human must add the firewall rule (Spark does not)." },
  reset_password: { level: "medium", why: "Forces the user to re-authenticate; may break saved sessions and service logons.", ifApproved: "A human must reset the password." },
  patch: { level: "medium", why: "Changes software on a production system; may need a reboot or cause regressions.", ifApproved: "A human must schedule and apply the patch." },
  request_scan: { level: "low", why: "Active scanning generates traffic against the target; low risk if the asset is authorized.", ifApproved: "A human must run the scan." },
  investigate: { level: "low", why: "Read-only investigation.", ifApproved: "No system change." }, other: { level: "medium", why: "Unclassified change; read the description carefully.", ifApproved: "A human must perform the change." },
};
export async function enrichActions(store: Store, actions: SocAction[], now = Date.now()): Promise<EnrichedAction[]> {
  const [incs, assets] = await Promise.all([store.select<Incident>(T.incidents, { limit: 2000 }), store.select<Asset>(T.assets, { limit: 500 })]);
  const out: EnrichedAction[] = [];
  for (const a of actions) {
    const b = BASE[a.type] ?? BASE.other, inc = a.incidentId ? incs.find((i) => i.id === a.incidentId) : undefined;
    const host = a.type === "isolate_host" || a.type === "patch" || a.type === "request_scan" ? a.target : inc?.host;
    const asset = assets.find((x) => x.id === (host ?? "").toLowerCase() || x.hostname.toLowerCase() === (host ?? "").toLowerCase() || x.id === inc?.assetId);
    let level = b.level; const reasons = [b.why];
    if (asset && asset.criticality >= 4 && level !== "high") { level = "high"; reasons.push(`The affected asset ${asset.hostname} is rated criticality ${asset.criticality}/5.`); }
    if (a.type === "block_ip" && a.target && isPrivateIp(a.target)) { level = "high"; reasons.push("The address is PRIVATE (internal). Blocking an internal address can cut off your own users or servers."); }
    if (inc) reasons.push(`Linked to a ${inc.severity} incident (${inc.status}).`);
    const alerts = inc ? ((await Promise.all(inc.alertIds.slice(0, 6).map((x) => store.get<Alert>(T.alerts, x)))).filter(Boolean) as Alert[]).sort((x, y) => sevRank(y.severity) - sevRank(x.severity)) : [];
    const evIds = [...new Set(alerts.flatMap((x) => x.eventIds))].slice(0, 5), events = ((await Promise.all(evIds.map((x) => store.get<SocEvent>(T.events, x)))).filter(Boolean) as SocEvent[]);
    out.push({ ...a, risk: { level, reasons, ifApproved: b.ifApproved, ifIgnored: inc ? `The ${inc.severity} incident stays ${inc.status}; the activity may continue.` : "The proposed concern stays open." },
      affected: { host: host || undefined, user: a.type === "disable_account" || a.type === "reset_password" ? a.target : undefined, ip: a.type === "block_ip" ? a.target : undefined, incident: inc ? { id: inc.id, title: inc.title, severity: inc.severity, status: inc.status } : undefined },
      evidence: { alerts: alerts.map((x) => ({ id: x.id, ruleId: x.ruleId, title: x.title, severity: x.severity, reasoning: x.reasoning, eventCount: x.eventIds.length })), events: events.map((e) => ({ id: e.id, time: e.time, summary: e.summary, user: e.user, srcIp: e.srcIp })) },
      ageMinutes: Math.max(0, Math.round((now - Date.parse(a.createdAt)) / 60000)), byAgent: a.proposedBy.startsWith("agent:") });
  }
  return out;
}
/** Display status for the incident center. The stored status is unchanged; "pending_approval" is derived from open proposals. */
export const DISPLAY: Record<string, string> = { open: "New", investigating: "Investigating", contained: "Contained", remediated: "Resolved", closed: "Closed" };
export const displayStatus = (inc: Incident, proposed: number) => (proposed > 0 && inc.status !== "closed" ? "Pending Approval" : DISPLAY[inc.status] ?? inc.status);
