// MITRE ATT&CK coverage view derived from the live rule catalogue. Shows which tactics/techniques have at least one detection rule, and which do not (honest gaps).
import { RULES_META } from "./rules";
export const TACTICS = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"] as const;
export interface TechniqueCover { id: string; name: string; rules: string[] }
export interface TacticCover { tactic: string; covered: boolean; techniques: TechniqueCover[] }
export function mitreCoverage(meta = RULES_META): { tactics: TacticCover[]; coveredTactics: number; totalTactics: number; techniques: number; gaps: string[]; note: string } {
  const by = new Map<string, Map<string, TechniqueCover>>();
  for (const r of meta) for (const m of r.mitre) { if (m.id === "N/A") continue; const t = by.get(m.tactic) ?? by.set(m.tactic, new Map()).get(m.tactic)!; const c = t.get(m.id) ?? { id: m.id, name: m.name, rules: [] }; if (!c.rules.includes(r.id)) c.rules.push(r.id); t.set(m.id, c); }
  const tactics = TACTICS.map((t) => ({ tactic: t as string, covered: by.has(t), techniques: [...(by.get(t)?.values() ?? [])].sort((a, b) => a.id.localeCompare(b.id)) }));
  const known = new Set<string>(TACTICS); for (const t of by.keys()) if (!known.has(t)) tactics.push({ tactic: t, covered: true, techniques: [...by.get(t)!.values()] });
  return { tactics, coveredTactics: tactics.filter((t) => t.covered).length, totalTactics: tactics.length, techniques: tactics.reduce((n, t) => n + t.techniques.length, 0), gaps: tactics.filter((t) => !t.covered).map((t) => t.tactic), note: "Coverage means a rule exists for at least one technique in the tactic, not that every technique is detected. Rules are tested on synthetic fixtures only." };
}
