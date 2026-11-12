import { findAll, kid, kids, parseXml, txt, type XNode } from "./xml";
import type { Severity } from "./types";

export interface Finding {
  host: string; ip: string; port: string; oid: string; name: string; cvss: number; cves: string[]; qod: number;
  summary: string; solution: string; solutionType: string;
}
export interface ParsedReport { format: "xml" | "csv"; scanTime?: string; findings: Finding[]; logResultsSkipped: number }

export const sevFromCvss = (c: number): Severity => (c >= 9 ? "critical" : c >= 7 ? "high" : c >= 4 ? "medium" : c > 0 ? "low" : "info");
const num = (s: string | undefined) => { const n = parseFloat(String(s ?? "").replace(",", ".")); return Number.isFinite(n) ? n : 0; };
const CVE = /CVE-\d{4}-\d{4,}/gi;

export function parseGreenboneXml(src: string): ParsedReport {
  const root = parseXml(src);
  const results = findAll(root, "result").filter((r) => kid(r, "nvt") || kid(r, "host"));
  if (!results.length) throw new Error("No <result> entries found. Export the report from Greenbone/OpenVAS as XML (get_reports) and try again.");
  const findings: Finding[] = []; let skipped = 0;
  for (const r of results) {
    const nvt = kid(r, "nvt");
    const hostNode = kid(r, "host") as XNode | undefined;
    const ip = txt(hostNode).split(/\s+/)[0] ?? "";
    const hostname = txt(kid(hostNode, "hostname"));
    const cvss = num(txt(kid(r, "severity")) || kid(nvt, "severities")?.attrs.score || txt(kid(nvt, "cvss_base")));
    if (cvss <= 0 || txt(kid(r, "threat")).toLowerCase() === "log") { skipped++; continue; }
    const cves = new Set<string>();
    for (const ref of kids(kid(nvt, "refs"), "ref")) if ((ref.attrs.type ?? "").toLowerCase() === "cve" && ref.attrs.id) cves.add(ref.attrs.id.toUpperCase());
    for (const m of txt(kid(nvt, "cve")).matchAll(CVE)) cves.add(m[0].toUpperCase());
    const tags = txt(kid(nvt, "tags")), tag = (k: string) => tags.match(new RegExp(`(?:^|\\|)${k}=([^|]*)`))?.[1] ?? "";
    const sol = kid(nvt, "solution");
    findings.push({
      host: hostname || ip, ip, port: txt(kid(r, "port")) || "general/tcp", oid: nvt?.attrs.oid ?? txt(kid(nvt, "oid")) ?? "", name: txt(kid(nvt, "name")) || txt(kid(r, "name")) || "Unnamed finding",
      cvss, cves: [...cves], qod: num(txt(kid(kid(r, "qod"), "value"))) || 0, summary: (tag("summary") || txt(kid(r, "description"))).slice(0, 1500),
      solution: (txt(sol) || tag("solution")).slice(0, 1500), solutionType: sol?.attrs.type ?? tag("solution_type"),
    });
  }
  const end = findAll(root, "scan_end").map(txt).find(Boolean) || findAll(root, "creation_time").map(txt).find(Boolean) || findAll(root, "timestamp").map(txt).find(Boolean);
  const t = end ? Date.parse(end) : NaN;
  return { format: "xml", scanTime: Number.isFinite(t) ? new Date(t).toISOString() : undefined, findings, logResultsSkipped: skipped };
}

export function parseCsv(src: string): string[][] {
  const rows: string[][] = []; let row: string[] = [], f = "", q = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (q) { if (c === '"') { if (src[i + 1] === '"') { f += '"'; i++; } else q = false; } else f += c; }
    else if (c === '"') q = true;
    else if (c === ",") { row.push(f); f = ""; }
    else if (c === "\n" || c === "\r") { if (c === "\r" && src[i + 1] === "\n") i++; row.push(f); f = ""; if (row.some((x) => x !== "")) rows.push(row); row = []; }
    else f += c;
  }
  row.push(f); if (row.some((x) => x !== "")) rows.push(row);
  return rows;
}

export function parseGreenboneCsv(src: string): ParsedReport {
  const rows = parseCsv(src.replace(/^﻿/, ""));
  if (rows.length < 2) throw new Error("CSV has no data rows.");
  const head = rows[0].map((h) => h.trim().toLowerCase());
  const col = (...n: string[]) => head.findIndex((h) => n.includes(h));
  const iIp = col("ip"), iHost = col("hostname"), iPort = col("port"), iProto = col("port protocol"), iCvss = col("cvss"), iQod = col("qod"), iName = col("nvt name"), iOid = col("nvt oid"),
    iSum = col("summary"), iSol = col("solution"), iSolT = col("solution type"), iCve = col("cves"), iTime = col("timestamp");
  if (iIp < 0 || iCvss < 0 || iName < 0) throw new Error("CSV is missing required Greenbone columns (IP, CVSS, NVT Name). Export the results as CSV from Greenbone.");
  const findings: Finding[] = []; let skipped = 0, latest = 0;
  for (const r of rows.slice(1)) {
    const cvss = num(r[iCvss]);
    if (cvss <= 0) { skipped++; continue; }
    const t = iTime >= 0 ? Date.parse(r[iTime]) : NaN; if (Number.isFinite(t)) latest = Math.max(latest, t);
    const port = iPort >= 0 && r[iPort] ? `${r[iPort]}/${(iProto >= 0 && r[iProto]) || "tcp"}` : "general/tcp";
    findings.push({ host: (iHost >= 0 && r[iHost]) || r[iIp], ip: r[iIp], port, oid: (iOid >= 0 && r[iOid]) || "", name: r[iName] || "Unnamed finding", cvss, cves: [...(iCve >= 0 ? r[iCve] : "").matchAll(CVE)].map((m) => m[0].toUpperCase()),
      qod: iQod >= 0 ? num(r[iQod]) : 0, summary: iSum >= 0 ? r[iSum].slice(0, 1500) : "", solution: iSol >= 0 ? r[iSol].slice(0, 1500) : "", solutionType: iSolT >= 0 ? r[iSolT] : "" });
  }
  return { format: "csv", scanTime: latest ? new Date(latest).toISOString() : undefined, findings, logResultsSkipped: skipped };
}

export function parseReport(content: string, format?: "xml" | "csv"): ParsedReport {
  const f = format ?? (content.trimStart().startsWith("<") ? "xml" : "csv");
  return f === "xml" ? parseGreenboneXml(content) : parseGreenboneCsv(content);
}
