import type { Asset, Incident, Severity, Vuln } from "./types";

const W: Record<Severity, number> = { critical: 25, high: 12, medium: 4, low: 1, info: 0 };

export function vulnPriority(v: { cvss: number; qod: number; kev: boolean; status?: string }, asset?: Pick<Asset, "criticality">): { score: number; reasons: string[] } {
  const reasons: string[] = [`CVSS ${v.cvss.toFixed(1)}`];
  let s = v.cvss * 10;
  const crit = asset?.criticality ?? 3;
  s *= 0.8 + crit * 0.1;
  if (crit !== 3) reasons.push(`asset criticality ${crit}/5`);
  if (v.kev) { s += 15; reasons.push("listed in the CISA KEV file you imported (known exploited)"); }
  if (v.qod && v.qod < 70) { s -= 10; reasons.push(`scanner detection quality only ${v.qod}%`); }
  return { score: Math.max(0, Math.min(100, Math.round(s))), reasons };
}

export function assetRisk(vulns: Pick<Vuln, "severity" | "status">[], incidents: Pick<Incident, "severity" | "status">[]): number {
  let sum = 0;
  for (const v of vulns) if (v.status === "open" || v.status === "reappeared" || v.status === "in_remediation") sum += W[v.severity];
  for (const i of incidents) if (i.status !== "closed" && i.status !== "remediated") sum += i.severity === "critical" ? 30 : i.severity === "high" ? 20 : i.severity === "medium" ? 10 : 3;
  return Math.round(100 * (1 - Math.exp(-sum / 60)));
}
