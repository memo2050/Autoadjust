import type { DataSource, Severity, SocEvent } from "./types";
import { clip, hid, nowIso, slug } from "./util";

/** What the Windows collector (or a Windows Event Forwarding export converted to JSON) sends. Field names are matched leniently. */
export interface RawWinEvent { [k: string]: unknown }

const pick = (o: Record<string, unknown>, ...names: string[]) => {
  for (const n of names) for (const k of Object.keys(o)) if (k.toLowerCase() === n.toLowerCase() && o[k] != null && o[k] !== "") return o[k];
  return undefined;
};
const str = (v: unknown) => (v == null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v));
const clean = (v: string | undefined) => (v && v !== "-" ? v : undefined);

const SUMMARY: Record<number, string> = {
  4624: "Successful logon", 4625: "Failed logon", 4648: "Logon with explicit credentials", 4672: "Special privileges assigned to new logon",
  4688: "Process created", 4698: "Scheduled task created", 4719: "Audit policy changed", 4720: "User account created", 4722: "User account enabled",
  4728: "Member added to security-enabled global group", 4732: "Member added to security-enabled local group", 4756: "Member added to security-enabled universal group",
  4740: "User account locked out", 1102: "Audit log cleared", 104: "Event log cleared", 7045: "Service installed", 1116: "Antimalware detected malware",
  1117: "Antimalware took action on malware", 5001: "Antimalware real-time protection disabled",
};

const SYSMON: Record<number, string> = { 1: "Sysmon: process created", 3: "Sysmon: network connection", 7: "Sysmon: image loaded", 8: "Sysmon: remote thread created", 10: "Sysmon: process accessed", 11: "Sysmon: file created", 13: "Sysmon: registry value set", 22: "Sysmon: DNS query" };
const APPLOG: Record<number, string> = { 1000: "Application error (crash)", 1001: "Windows Error Reporting", 1002: "Application hang", 1026: ".NET runtime error" };
const isSysmon = (channel: string, provider: string) => /sysmon/i.test(channel) || /sysmon/i.test(provider);
function eventSeverity(eventId: number, channel: string, provider: string, level: string | undefined): Severity {
  const lv = (level ?? "").toLowerCase();
  if ([1102, 104].includes(eventId)) return "high";
  if (isSysmon(channel, provider)) return [8, 10].includes(eventId) ? "medium" : "low";
  if (/critical/.test(lv)) return "critical"; if (/error/.test(lv)) return "high"; if (/warning/.test(lv)) return "medium";
  if ([4625, 4740, 4719, 5001, 1116, 1117].includes(eventId)) return "medium";
  return "low";
}
export function normalizeWindows(raw: RawWinEvent, opts: { host?: string; source: DataSource; collector: string; ingestedAt?: string }): SocEvent | { error: string } {
  const eventId = Number(pick(raw, "Id", "EventID", "EventId"));
  if (!Number.isInteger(eventId) || eventId <= 0) return { error: "missing or invalid event id" };
  const tRaw = pick(raw, "TimeCreated", "TimeGenerated", "Time", "Timestamp");
  const tVal = typeof tRaw === "object" && tRaw ? (tRaw as any).SystemTime ?? (tRaw as any).value : tRaw;
  const t = Date.parse(str(tVal));
  if (!Number.isFinite(t)) return { error: "missing or invalid time" };
  const host = str(pick(raw, "MachineName", "Computer", "Hostname", "Host") ?? opts.host).trim();
  if (!host) return { error: "missing host" };
  const hostShort = host.split(".")[0];
  const d0 = pick(raw, "Data", "EventData");
  const data: Record<string, string> = {};
  if (d0 && typeof d0 === "object" && !Array.isArray(d0)) for (const [k, v] of Object.entries(d0 as Record<string, unknown>)) data[k] = clip(str(v), 2000);
  const D = (...n: string[]) => clean(str(pick(data, ...n)) || undefined);
  const channel = str(pick(raw, "LogName", "Channel") ?? "Unknown");
  const provider = str(pick(raw, "ProviderName", "Provider") ?? "Unknown");
  const recordId = Number(pick(raw, "RecordId", "EventRecordID"));
  const logon = D("LogonType");

  const sysmon = isSysmon(channel, provider);
  const isLogon = !sysmon && (eventId === 4624 || eventId === 4625);
  const user = sysmon ? D("User") : isLogon || [4720, 4722, 4740].includes(eventId) ? D("TargetUserName") : D("SubjectUserName", "TargetUserName");
  const ev: SocEvent = {
    id: "", source: opts.source, collector: opts.collector, assetId: slug(hostShort), host: hostShort, time: new Date(t).toISOString(),
    channel, provider, eventId, recordId: Number.isFinite(recordId) ? recordId : undefined, level: clean(str(pick(raw, "LevelDisplayName", "Level"))),
    user, targetUser: [4728, 4732, 4756].includes(eventId) ? D("MemberName", "MemberSid") : [4648].includes(eventId) ? D("TargetUserName") : undefined,
    domain: D("TargetDomainName", "SubjectDomainName"), srcIp: sysmon && eventId === 3 ? D("DestinationIp") : D("IpAddress", "SourceAddress", "SourceNetworkAddress"), // for Sysmon network events this holds the REMOTE address
    severity: eventSeverity(eventId, channel, provider, clean(str(pick(raw, "LevelDisplayName", "Level")))),
    srcHost: D("WorkstationName"), logonType: logon ? Number(logon) : undefined,
    process: D("NewProcessName", "Image", "ProcessName", "Process Name"), parentProcess: D("ParentProcessName", "ParentImage"),
    commandLine: D("CommandLine", "ProcessCommandLine") ? clip(D("CommandLine", "ProcessCommandLine"), 1500) : undefined,
    summary: sysmon ? (SYSMON[eventId] ?? `Sysmon event ${eventId}`) + (eventId === 3 ? ` to ${D("DestinationIp") ?? "?"}:${D("DestinationPort") ?? "?"}` : "") : /^application$/i.test(channel) && APPLOG[eventId] ? APPLOG[eventId] : SUMMARY[eventId] ?? `Windows event ${eventId}`, data, fingerprint: "", ingestedAt: opts.ingestedAt ?? nowIso(),
  };
  ev.fingerprint = [ev.host, ev.channel, ev.recordId ?? "", ev.eventId, ev.time, ev.user ?? "", ev.srcIp ?? ""].join("|");
  ev.id = hid("evt", ev.fingerprint);
  return ev;
}
