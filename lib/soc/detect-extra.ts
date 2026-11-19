// Additional detections that plug into the existing rules engine: UEBA (per-user behaviour baselines) and NDR (network behaviour from Sysmon network events).
// Pure functions over SocEvent[]; no I/O. Every alert is a HYPOTHESIS with a confidence set here (not by AI) and cites its evidence event ids.
import type { Alert, MitreRef, Severity, SocEvent } from "./types";
import { isPrivateIp, ms, uniq } from "./util";
import type { AlertDraft, RuleMeta } from "./rules";

const T = {
  valid: { id: "T1078", name: "Valid Accounts", tactic: "Initial Access" } as MitreRef,
  c2: { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control" } as MitreRef,
  scan: { id: "T1046", name: "Network Service Discovery", tactic: "Discovery" } as MitreRef,
};
export const UEBA_CFG = { baselineMinLogons: 20, recentWindowMs: 24 * 3600_000, hourPad: 1, privateNewSourceMin: 20 };
export const NDR_CFG = { beaconMin: 8, beaconCv: 0.2, beaconMinGapMs: 10_000, beaconMaxGapMs: 3600_000, scanPorts: 20, scanWindowMs: 5 * 60_000 };
const mk = (id: string, name: string, severity: Severity, mitre: MitreRef[], description: string): RuleMeta => ({ id, name, severity, mitre, description });
export const R_UEBA_HOURS = mk("UEBA-001", "Logon outside the user's usual hours", "low", [T.valid], `Compares each successful logon in the last 24 h with the same user's earlier logons. Needs ${UEBA_CFG.baselineMinLogons}+ earlier logons; flags an hour (UTC, ±${UEBA_CFG.hourPad} h) the user has never logged on at before.`);
export const R_UEBA_SRC = mk("UEBA-002", "Logon from a source new to this user", "medium", [T.valid], "A remote logon (types 3 and 10) from an address this user has not used in the baseline; public addresses raise severity.");
export const R_NDR_BEACON = mk("NDR-001", "Regular outbound connections (possible beaconing)", "medium", [T.c2], `${NDR_CFG.beaconMin}+ Sysmon network connections from one process to one public address:port at near-constant intervals (coefficient of variation <= ${NDR_CFG.beaconCv}).`);
export const R_NDR_SCAN = mk("NDR-002", "Port or host scanning pattern", "medium", [T.scan], `One host reached ${NDR_CFG.scanPorts}+ distinct ports on one address (port scan) or ${NDR_CFG.scanPorts}+ distinct addresses on one port (sweep) within ${NDR_CFG.scanWindowMs / 60000} minutes.`);
export const EXTRA_META: RuleMeta[] = [R_UEBA_HOURS, R_UEBA_SRC, R_NDR_BEACON, R_NDR_SCAN];

const first = (e: SocEvent[]) => e.reduce((m, x) => (x.time < m ? x.time : m), e[0].time), last = (e: SocEvent[]) => e.reduce((m, x) => (x.time > m ? x.time : m), e[0].time);
function mkDraft(rule: RuleMeta, ev: SocEvent[], o: { title: string; severity?: Severity; confidence: number; keyPart: string; reasoning: string }): AlertDraft {
  return { ruleId: rule.id, key: `${rule.id}|${ev[0].assetId}|${o.keyPart}`, title: o.title, severity: o.severity ?? rule.severity, confidence: o.confidence, mitre: rule.mitre, assetId: ev[0].assetId, host: ev[0].host, eventIds: ev.map((x) => x.id).slice(0, 200), firstSeen: first(ev), lastSeen: last(ev), reasoning: o.reasoning, entities: { users: uniq(ev.map((x) => x.user).filter(Boolean) as string[]).slice(0, 20), ips: uniq(ev.map((x) => x.srcIp).filter(Boolean) as string[]).slice(0, 20) } };
}
const logons = (ev: SocEvent[]) => ev.filter((e) => e.eventId === 4624 && e.channel.toLowerCase() === "security" && e.user && !/^(system|anonymous logon|local service|network service|dwm-\d+|umfd-\d+)$/i.test(e.user) && !/\$$/.test(e.user));
const hourOf = (iso: string) => new Date(iso).getUTCHours();

export function uebaAlerts(events: SocEvent[]): AlertDraft[] {
  const L = logons(events); if (!L.length) return [];
  const newest = Math.max(...L.map((e) => ms(e.time))), cut = newest - UEBA_CFG.recentWindowMs, out: AlertDraft[] = [];
  const byUser = new Map<string, SocEvent[]>(); for (const e of L) (byUser.get(e.user!.toLowerCase()) ?? byUser.set(e.user!.toLowerCase(), []).get(e.user!.toLowerCase())!).push(e);
  for (const [user, list] of byUser) {
    const base = list.filter((e) => ms(e.time) < cut), recent = list.filter((e) => ms(e.time) >= cut);
    if (base.length < UEBA_CFG.baselineMinLogons || !recent.length) continue;
    const hours = new Set<number>(); for (const e of base) { const h = hourOf(e.time); for (let d = -UEBA_CFG.hourPad; d <= UEBA_CFG.hourPad; d++) hours.add((h + d + 24) % 24); }
    const odd = recent.filter((e) => !hours.has(hourOf(e.time)));
    if (odd.length) out.push(mkDraft(R_UEBA_HOURS, odd, { title: `${list[0].user} logged on at an unusual hour (${[...new Set(odd.map((e) => hourOf(e.time)))].map((h) => String(h).padStart(2, "0") + ":00 UTC").join(", ")})`, confidence: 0.4, keyPart: user, reasoning: `Based on ${base.length} earlier logons, ${list[0].user} had not logged on at these hours. Shift changes, travel or time zones are common benign causes; confirm with the user before escalating.` }));
    const seen = new Set(base.flatMap((e) => [e.srcIp, e.srcHost].filter(Boolean) as string[]).map((s) => s.toLowerCase()));
    const fresh = recent.filter((e) => (e.logonType === 3 || e.logonType === 10) && e.srcIp && !seen.has(e.srcIp.toLowerCase()) && e.srcIp !== "127.0.0.1" && e.srcIp !== "::1");
    for (const ip of uniq(fresh.map((e) => e.srcIp!))) {
      const ev = fresh.filter((e) => e.srcIp === ip), pub = !isPrivateIp(ip);
      out.push(mkDraft(R_UEBA_SRC, ev, { title: `${list[0].user} logged on from new ${pub ? "public " : ""}address ${ip}`, severity: pub ? "high" : "low", confidence: pub ? 0.6 : 0.3, keyPart: `${user}|${ip}`, reasoning: `${list[0].user} had ${base.length} earlier logons and none from ${ip}. ${pub ? "A first-time public address is a common sign of stolen credentials; verify with the user and check for MFA." : "A new internal address can be a new device or lateral movement; verify the device."}` }));
    }
  }
  return out;
}

export function ndrAlerts(events: SocEvent[]): AlertDraft[] {
  const net = events.filter((e) => e.eventId === 3 && /sysmon/i.test(e.channel) && e.srcIp && !isPrivateIp(e.srcIp)), out: AlertDraft[] = [];
  const g = new Map<string, SocEvent[]>(); for (const e of net) { const k = `${e.host}|${e.process ?? "?"}|${e.srcIp}|${e.data.DestinationPort ?? "?"}`; (g.get(k) ?? g.set(k, []).get(k)!).push(e); }
  for (const [k, list] of g) {
    if (list.length < NDR_CFG.beaconMin) continue; const s = [...list].sort((a, b) => ms(a.time) - ms(b.time)), gaps = s.slice(1).map((e, i) => ms(e.time) - ms(s[i].time));
    const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length; if (mean < NDR_CFG.beaconMinGapMs || mean > NDR_CFG.beaconMaxGapMs) continue;
    const cv = Math.sqrt(gaps.reduce((a, b) => a + (b - mean) ** 2, 0) / gaps.length) / mean; if (cv > NDR_CFG.beaconCv) continue;
    out.push(mkDraft(R_NDR_BEACON, s, { title: `${(s[0].process ?? "process").split("\\").pop()} connects to ${s[0].srcIp}:${s[0].data.DestinationPort ?? "?"} every ~${Math.round(mean / 1000)} s`, confidence: Math.min(0.8, 0.45 + (NDR_CFG.beaconCv - cv)), keyPart: k, reasoning: `${s.length} connections at a near-constant interval (mean ${Math.round(mean / 1000)} s, variation ${(cv * 100).toFixed(0)}%). Software update checks and monitoring agents also do this; confirm the destination and process are expected.` }));
  }
  const byHost = new Map<string, SocEvent[]>(); for (const e of events.filter((e) => e.eventId === 3 && /sysmon/i.test(e.channel) && e.srcIp)) (byHost.get(e.host) ?? byHost.set(e.host, []).get(e.host)!).push(e);
  for (const [host, list] of byHost) {
    const s = [...list].sort((a, b) => ms(a.time) - ms(b.time));
    for (const mode of ["port", "host"] as const) {
      const key = (e: SocEvent) => (mode === "port" ? e.srcIp! : e.data.DestinationPort ?? "?"), val = (e: SocEvent) => (mode === "port" ? e.data.DestinationPort ?? "?" : e.srcIp!);
      const groups = new Map<string, SocEvent[]>(); for (const e of s) (groups.get(key(e)) ?? groups.set(key(e), []).get(key(e))!).push(e);
      for (const [k, gl] of groups) { let lo = 0; const win: SocEvent[] = [];
        for (let hi = 0; hi < gl.length; hi++) { while (ms(gl[hi].time) - ms(gl[lo].time) > NDR_CFG.scanWindowMs) lo++; const w = gl.slice(lo, hi + 1); if (new Set(w.map(val)).size >= NDR_CFG.scanPorts) { win.splice(0, win.length, ...w); } }
        if (win.length) out.push(mkDraft(R_NDR_SCAN, win, { title: mode === "port" ? `${host} touched ${new Set(win.map(val)).size} ports on ${k}` : `${host} contacted ${new Set(win.map(val)).size} addresses on port ${k}`, confidence: 0.6, keyPart: `${mode}|${k}`, reasoning: `Reconnaissance-like fan-out within ${NDR_CFG.scanWindowMs / 60000} minutes. Authorised vulnerability scanners and discovery agents look the same; check scan schedules first.` })); }
    }
  }
  return out;
}
export const runExtra = (events: SocEvent[]): AlertDraft[] => [...uebaAlerts(events), ...ndrAlerts(events)];
export type { Alert };
